package rotate

import (
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/policy"
)

// SelectStale returns only the credentials the expiry policy marks Warn or Stale
// as of now — the subset that `rotate --stale` plans/rotates. Credentials the
// policy still considers OK are dropped, so an unattended headless run touches
// only aging credentials instead of every discovered one.
//
// It is a pure, read-only filter over the policy engine (policy.Policy.Evaluate);
// it mints, stores, and revokes nothing. Order is preserved.
func SelectStale(pol policy.Policy, creds []discover.Credential, now time.Time) []discover.Credential {
	out := make([]discover.Credential, 0, len(creds))
	for _, c := range creds {
		switch st, _ := pol.Evaluate(c, now); st {
		case policy.Warn, policy.Stale:
			out = append(out, c)
		}
	}
	return out
}
