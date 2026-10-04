package rotate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/sink"
	"incredigo/internal/vault"
)

// faultGopass is a fake gopass over a plain dir ($FAKE_GOPASS_STORE) whose insert/show/rm
// fail for one exact path named by $FAKE_GOPASS_FAIL_INSERT / _SHOW / _RM. Fake creds only.
func faultGopass(t *testing.T, entries map[string]string) (*sink.Gopass, string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gopass")
	script := `#!/usr/bin/env bash
store="$FAKE_GOPASS_STORE"
cmd="$1"; shift; path=""
for a in "$@"; do case "$a" in --multiline=false|-f|-o|--flat) ;; *) path="$a";; esac; done
case "$cmd" in
  ls) (cd "$store" 2>/dev/null && find . -type f | sed 's#^\./##' | sort) ;;
  show) [[ "$path" == "$FAKE_GOPASS_FAIL_SHOW" ]] && { echo "show failed" >&2; exit 1; }
    cat "$store/$path" ;;
  insert) [[ "$path" == "$FAKE_GOPASS_FAIL_INSERT" ]] && { cat >/dev/null; echo "insert failed" >&2; exit 1; }
    mkdir -p "$store/$(dirname "$path")"; cat > "$store/$path" ;;
  rm) [[ "$path" == "$FAKE_GOPASS_FAIL_RM" ]] && { echo "rm failed" >&2; exit 1; }
    [[ -f "$store/$path" ]] || { echo "not found" >&2; exit 1; }
    rm -f "$store/$path" ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", store)
	t.Setenv("FAKE_GOPASS_FAIL_INSERT", "")
	t.Setenv("FAKE_GOPASS_FAIL_SHOW", "")
	t.Setenv("FAKE_GOPASS_FAIL_RM", "")
	for p, s := range entries {
		full := filepath.Join(store, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &sink.Gopass{Bin: bin}, store
}

// fakeService is a credential-holding service plus its Rotator. In IN-PLACE mode Rotate
// changes the one password (the old dies immediately, like postgres ALTER USER); otherwise it
// creates a second credential and RevokeOld kills the old one (like an API token).
type fakeService struct {
	name, source string
	inPlace      bool
	fault        string // see TestExecute_faultMatrix
	cancel       context.CancelFunc

	valid   map[string]bool // secrets the service accepts right now
	old     string
	verifyN atomic.Int32
}

var fakeSvcSeq atomic.Int32

func (s *fakeService) Name() string                      { return s.name }
func (s *fakeService) Detect(c discover.Credential) bool { return c.Source == s.source }

func (s *fakeService) Rotate(_ context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	if s.fault == "rotate-fails" {
		return nil, errors.New("provider rejected the change")
	}
	newPW := fmt.Sprintf("fake-new-%d", fakeSvcSeq.Add(1))
	if s.inPlace {
		s.valid = map[string]bool{newPW: true}
	} else {
		s.valid[newPW] = true
	}
	h := v.Store([]byte(newPW))
	switch s.fault {
	case "cancel-in-rotate":
		s.cancel() // operator hits Ctrl-C right after the service changed
	case "rotate-unknown":
		return h, errors.New("outcome unknown")
	}
	return h, nil
}

func (s *fakeService) Verify(_ context.Context, h *vault.Handle, v *vault.Vault) error {
	n := s.verifyN.Add(1)
	if (s.fault == "verify-new" && n == 1) || (s.fault == "verify-stored" && n == 2) {
		return errors.New("verify: connection reset")
	}
	buf, err := v.Open(h)
	if err != nil {
		return err
	}
	if !s.valid[string(buf.Bytes())] {
		return errors.New("verify: rejected")
	}
	return nil
}

func (s *fakeService) RevokeOld(context.Context, discover.Credential, *vault.Vault) error {
	if s.fault == "revoke" {
		return errors.New("revoke: provider error")
	}
	if !s.inPlace {
		delete(s.valid, s.old)
	}
	return nil
}

// storedSecrets returns every value held in the fake store, keyed by path.
func storedSecrets(t *testing.T, store string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(store, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(store, p)
		out[rel] = strings.TrimRight(string(b), "\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestExecute_faultMatrix injects a fault at every step of the spine, for both kinds of
// service, and asserts the one invariant that matters: SOME secret held in gopass (the
// primary entry or its .pending copy) still authenticates at the service. No lockout.
func TestExecute_faultMatrix(t *testing.T) {
	const entry = "imported/svc/app"
	const pending = entry + PendingSuffix
	type want struct {
		ok           bool // Execute reports success for the credential
		pendingLeft  bool // a .pending copy remains for the human
		primaryIsNew bool // the primary entry holds the new secret
	}
	faults := []struct {
		fault   string
		env     [2]string // fake-gopass fault env var + path
		inPlace want
		create  want
	}{
		{"none", [2]string{}, want{true, false, true}, want{true, false, true}},
		{"rotate-fails", [2]string{}, want{false, false, false}, want{false, false, false}},
		{"verify-new", [2]string{}, want{false, true, false}, want{false, true, false}},
		{"store", [2]string{"FAKE_GOPASS_FAIL_INSERT", entry}, want{false, true, false}, want{false, true, false}},
		{"reread", [2]string{"FAKE_GOPASS_FAIL_SHOW", entry}, want{false, true, true}, want{false, true, true}},
		{"verify-stored", [2]string{}, want{false, true, true}, want{false, true, true}},
		{"pending-store", [2]string{"FAKE_GOPASS_FAIL_INSERT", pending}, want{true, false, true}, want{true, false, true}},
		{"pending-cleanup", [2]string{"FAKE_GOPASS_FAIL_RM", pending}, want{true, true, true}, want{true, true, true}},
		{"revoke", [2]string{}, want{false, false, true}, want{false, false, true}},
		{"cancel-in-rotate", [2]string{}, want{false, true, false}, want{false, true, false}},
		{"rotate-unknown", [2]string{}, want{false, true, false}, want{false, true, false}},
	}
	for _, f := range faults {
		for _, inPlace := range []bool{true, false} {
			mode, w := "create-then-revoke", f.create
			if inPlace {
				mode, w = "in-place", f.inPlace
			}
			t.Run(f.fault+"/"+mode, func(t *testing.T) {
				const oldPW = "fake-old-pw"
				gp, store := faultGopass(t, map[string]string{entry: oldPW})
				if f.env[0] != "" {
					t.Setenv(f.env[0], f.env[1])
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				seq := fakeSvcSeq.Add(1)
				svc := &fakeService{
					name:    fmt.Sprintf("fakesvc-%d", seq),
					source:  fmt.Sprintf("fakesvc-src-%d", seq),
					inPlace: inPlace, fault: f.fault, cancel: cancel,
					valid: map[string]bool{oldPW: true}, old: oldPW,
				}
				Register(svc)

				v := vault.New()
				defer v.Purge()
				creds := []discover.Credential{{
					Source: svc.source, Identity: entry, Location: entry,
					Secret: v.Store([]byte(oldPW)),
				}}
				res := Execute(ctx, gp, creds, v, true)
				if len(res) != 1 {
					t.Fatalf("got %d results, want 1", len(res))
				}
				r := res[0]
				held := storedSecrets(t, store)

				// THE invariant: no lockout.
				working := false
				for _, s := range held {
					if svc.valid[s] {
						working = true
					}
				}
				if !working {
					t.Fatalf("LOCKOUT: nothing in gopass authenticates. held=%v err=%v", held, r.Err)
				}

				if got := r.Err == nil; got != w.ok {
					t.Errorf("success = %v (err %v), want %v", got, r.Err, w.ok)
				}
				_, hasPending := held[pending]
				if hasPending != w.pendingLeft {
					t.Errorf(".pending left = %v, want %v", hasPending, w.pendingLeft)
				}
				if w.pendingLeft && r.PendingPath != pending {
					t.Errorf("result PendingPath = %q, want %q", r.PendingPath, pending)
				}
				if w.pendingLeft && r.Err != nil && !strings.Contains(r.Err.Error(), pending) {
					t.Errorf("error must name the pending entry: %v", r.Err)
				}
				if got := held[entry] != oldPW; got != w.primaryIsNew {
					t.Errorf("primary holds new = %v, want %v", got, w.primaryIsNew)
				}
				if w.ok && !inPlace && f.fault != "revoke" && svc.valid[oldPW] {
					t.Error("old credential not revoked after a successful rotation")
				}
			})
		}
	}
}
