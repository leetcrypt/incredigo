package rotate

import (
	"context"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// TestDryRunSpine confirms DryRun walks rotate→verify→revoke for every detected
// credential and persists nothing: the minted secret is Forgotten, and the
// original credential is left intact.
func TestDryRunSpine(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	old := []byte("OLD-VALUE")
	oldH := v.Store(append([]byte(nil), old...))
	creds := []discover.Credential{
		{Source: "aws", Identity: "default / AKIA…REDACTED", Secret: oldH},
		{Source: "env", Identity: ".env / API_TOKEN"},
	}

	d := &NoopRotator{}
	results := DryRun(context.Background(), d, creds, v)

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("%s: unexpected error: %v", r.Credential.Identity, r.Err)
		}
		if !r.Rotated || !r.Verified || !r.Revoked {
			t.Fatalf("%s: spine incomplete: rotated=%t verified=%t revoked=%t",
				r.Credential.Identity, r.Rotated, r.Verified, r.Revoked)
		}
	}

	// Every credential was revoked exactly once, after verify.
	if got := len(d.Revoked()); got != 2 {
		t.Fatalf("revoked %d, want 2", got)
	}

	// The original secret must remain readable — a dry run persists nothing and
	// disturbs nothing.
	ob, err := v.Open(oldH)
	if err != nil {
		t.Fatalf("old secret disturbed: %v", err)
	}
	if string(ob.Bytes()) != string(old) {
		t.Fatal("old secret value changed during dry run")
	}
}

// TestDryRunDetectFilter confirms DryRun skips credentials a driver does not
// claim, so a real (selective) driver only touches its own kind.
func TestDryRunDetectFilter(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	creds := []discover.Credential{{Source: "aws", Identity: "a"}, {Source: "env", Identity: "b"}}
	results := DryRun(context.Background(), onlyAWS{&NoopRotator{}}, creds, v)
	if len(results) != 1 || results[0].Credential.Source != "aws" {
		t.Fatalf("expected only the aws credential, got %+v", results)
	}
}

// onlyAWS is a minimal test driver that claims only aws credentials, reusing the
// noop's rotate/verify/revoke. It embeds a pointer so it carries no copied lock.
type onlyAWS struct{ *NoopRotator }

func (onlyAWS) Detect(c discover.Credential) bool { return c.Source == "aws" }
