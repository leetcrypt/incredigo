package rotate

import (
	"context"
	"errors"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// spyGateDriver is a minimal registered driver used to observe whether Execute's
// proof gate actually reached (or skipped) a driver's Rotate. It contacts no
// service: Rotate records that it ran and returns rotateErr, short-circuiting the
// spine before any gopass write, so allowMock=true can be proven without a store.
type spyGateDriver struct {
	name      string
	source    string
	rotateErr error
	rotated   bool
}

func (s *spyGateDriver) Name() string                      { return s.name }
func (s *spyGateDriver) Detect(c discover.Credential) bool { return c.Source == s.source }
func (s *spyGateDriver) Verify(context.Context, *vault.Handle, *vault.Vault) error {
	return nil
}
func (s *spyGateDriver) RevokeOld(context.Context, discover.Credential, *vault.Vault) error {
	return nil
}
func (s *spyGateDriver) Rotate(context.Context, discover.Credential, *vault.Vault) (*vault.Handle, error) {
	s.rotated = true
	return nil, s.rotateErr
}

// TestExecuteProofGateSkipsMockOnly proves that by default (allowMock=false) a
// driver whose proof is below MinExecuteProof is SKIPPED: its Rotate is never
// called and the credential is reported as skipped, not rotated.
func TestExecuteProofGateSkipsMockOnly(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	// Unknown name => ProofUnproven (< MinExecuteProof); unique source so no real
	// driver claims it.
	spy := &spyGateDriver{name: "spy-unproven", source: "faketest-gate-skip"}
	Register(spy)

	creds := []discover.Credential{{Source: "faketest-gate-skip", Identity: "x", Location: "imported/x"}}
	res := Execute(context.Background(), nil, creds, v, false)

	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	r := res[0]
	if !r.Skipped {
		t.Errorf("mock-only driver was not skipped: %+v", r)
	}
	if r.SkipReason == "" {
		t.Error("skipped result has no SkipReason")
	}
	if r.Rotated || r.Err != nil {
		t.Errorf("skipped credential should not be rotated or errored: %+v", r)
	}
	if spy.rotated {
		t.Error("gate leaked: Rotate was called on a gated driver")
	}
}

// TestExecuteProofGateAllowMockOverride proves --allow-mock-proven (allowMock=true)
// lets a below-threshold driver through: Rotate IS called (we make it fail fast so
// no gopass write is needed) and the result is not marked Skipped.
func TestExecuteProofGateAllowMockOverride(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	spy := &spyGateDriver{name: "spy-unproven-override", source: "faketest-gate-allow", rotateErr: errors.New("boom")}
	Register(spy)

	creds := []discover.Credential{{Source: "faketest-gate-allow", Identity: "x", Location: "imported/x"}}
	res := Execute(context.Background(), nil, creds, v, true)

	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	r := res[0]
	if r.Skipped {
		t.Errorf("allowMock should not skip the driver: %+v", r)
	}
	if !spy.rotated {
		t.Error("allowMock did not let the driver run: Rotate never called")
	}
	if r.Err == nil {
		t.Error("expected the driver's Rotate error to surface")
	}
}

// TestExecuteProofGateLiveVMRuns proves a driver at or above MinExecuteProof runs
// WITHOUT the override. The spy takes the name "postgres" (LIVE-VM in proofs.go)
// but a unique source so only it claims the credential; Rotate fails fast to avoid
// any real service call.
func TestExecuteProofGateLiveVMRuns(t *testing.T) {
	if ProofLevelOf("postgres") < MinExecuteProof {
		t.Skip("postgres proof level changed; test assumption invalid")
	}
	v := vault.New()
	defer v.Purge()

	spy := &spyGateDriver{name: "postgres", source: "faketest-gate-livevm", rotateErr: errors.New("boom")}
	Register(spy)

	creds := []discover.Credential{{Source: "faketest-gate-livevm", Identity: "x", Location: "imported/x"}}
	res := Execute(context.Background(), nil, creds, v, false)

	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if res[0].Skipped {
		t.Errorf("LIVE-VM driver was gated by default: %+v", res[0])
	}
	if !spy.rotated {
		t.Error("LIVE-VM driver did not run under the default gate")
	}
}

// TestProofLevelOrderAndString locks the level ordering (Unproven < MockOnly <
// LiveVM < LiveReal) and the LIVE-REAL token the CLI/manifest render.
func TestProofLevelOrderAndString(t *testing.T) {
	if !(ProofUnproven < ProofMockOnly && ProofMockOnly < ProofLiveVM && ProofLiveVM < ProofLiveReal) {
		t.Fatal("proof levels are not ordered lowest→highest")
	}
	if MinExecuteProof != ProofLiveVM {
		t.Errorf("MinExecuteProof = %v, want ProofLiveVM", MinExecuteProof)
	}
	want := map[ProofLevel]string{
		ProofUnproven: "UNPROVEN",
		ProofMockOnly: "MOCK-ONLY",
		ProofLiveVM:   "LIVE-VM",
		ProofLiveReal: "LIVE-REAL",
	}
	for lvl, s := range want {
		if got := lvl.String(); got != s {
			t.Errorf("%d.String() = %q, want %q", lvl, got, s)
		}
	}
}
