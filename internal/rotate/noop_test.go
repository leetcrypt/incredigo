package rotate

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/awnumar/memguard"

	"incredigo/internal/discover"
	"incredigo/internal/sink"
	"incredigo/internal/vault"
)

// TestNoopFullFlow walks the entire safety spine end-to-end with the dry-run
// driver: mandatory backup → Detect → Rotate(mint new) → Verify → store →
// RevokeOld. It asserts the spine's invariants without touching any service:
// the old secret is never disturbed, a distinct new secret is minted, and
// revoke runs only after verify succeeds.
func TestNoopFullFlow(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	old := []byte("AKIA-OLD-SECRET-1")
	oldHandle := v.Store(append([]byte(nil), old...))
	creds := []discover.Credential{
		{Source: "aws", Kind: discover.KindAWSKey, Identity: "default / AKIA…REDACTED", Secret: oldHandle},
		{Source: "env", Kind: discover.KindToken, Identity: "API_TOKEN"},
	}

	// 1. MANDATORY backup gate must pass before anything rotates.
	gp := fakeGopass(t)
	pass := memguard.NewBufferFromBytes([]byte("flow-pass"))
	defer pass.Destroy()
	out := filepath.Join(t.TempDir(), "flow.age")
	if _, err := Snapshot(context.Background(), gp, "imported/", &sink.Age{}, pass, out); err != nil {
		t.Fatalf("backup gate must succeed before rotation: %v", err)
	}

	ctx := context.Background()
	d := &NoopRotator{}

	for _, c := range creds {
		if !d.Detect(c) {
			t.Fatalf("noop must Detect %s", c.Identity)
		}

		// 2. Rotate mints a NEW secret and must not revoke anything yet.
		revokedBefore := len(d.Revoked())
		newHandle, err := d.Rotate(ctx, c, v)
		if err != nil {
			t.Fatalf("Rotate %s: %v", c.Identity, err)
		}
		if len(d.Revoked()) != revokedBefore {
			t.Fatalf("Rotate must not revoke; revoked=%v", d.Revoked())
		}

		// New secret is real and distinct from the old value.
		nb, err := v.Open(newHandle)
		if err != nil {
			t.Fatalf("open new secret: %v", err)
		}
		if nb.Size() == 0 {
			t.Fatalf("new secret for %s is empty", c.Identity)
		}
		if bytes.Equal(nb.Bytes(), old) {
			t.Fatalf("new secret equals old for %s — rotation minted nothing", c.Identity)
		}

		// 3. Verify before revoke.
		if err := d.Verify(ctx, newHandle, v); err != nil {
			t.Fatalf("Verify %s: %v", c.Identity, err)
		}

		// 4. Only now retire the old credential.
		if err := d.RevokeOld(ctx, c, v); err != nil {
			t.Fatalf("RevokeOld %s: %v", c.Identity, err)
		}
	}

	// The old secret must remain readable — the noop never touches a real value.
	ob, err := v.Open(oldHandle)
	if err != nil {
		t.Fatalf("old secret was disturbed: %v", err)
	}
	if !bytes.Equal(ob.Bytes(), old) {
		t.Fatal("old secret value changed — dry run must leave originals intact")
	}

	if got, want := d.Revoked(), []string{"default / AKIA…REDACTED", "API_TOKEN"}; !equal(got, want) {
		t.Fatalf("revoked = %v, want %v", got, want)
	}
}

// TestNoopNotRegistered guards the hard rule: the dry-run driver must not leak
// into the global registry, so the production `rotate` command still sees zero
// drivers and PlanAll reports "(none)".
func TestNoopNotRegistered(t *testing.T) {
	for _, d := range Drivers() {
		if d.Name() == "noop" {
			t.Fatal("NoopRotator must NOT auto-register — production rotate must report zero drivers")
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
