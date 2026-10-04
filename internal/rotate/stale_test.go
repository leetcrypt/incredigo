package rotate

import (
	"testing"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/policy"
)

// TestStaleSelection proves SelectStale keeps only the credentials the policy
// engine marks Warn or Stale (expiry-driven) and drops the OK ones, using the
// default thresholds (warn_after 60d, stale_after 90d; aws override warn 30d).
func TestStaleSelection(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	daysAgo := func(d int) time.Time { return now.Add(-time.Duration(d) * 24 * time.Hour) }

	cred := func(id string, kind discover.Kind, ageDays int) discover.Credential {
		return discover.Credential{Source: "file", Kind: kind, Identity: id, Modified: daysAgo(ageDays)}
	}

	all := []discover.Credential{
		cred("fresh", discover.KindToken, 10),     // OK  (<60d)
		cred("warn", discover.KindToken, 75),      // WARN (>=60d, <90d)
		cred("stale", discover.KindToken, 120),    // STALE (>=90d)
		cred("aws-warn", discover.KindAWSKey, 45), // WARN via aws override (>=30d, <90d)
		cred("edge-ok", discover.KindToken, 59),   // OK  (just under warn)
	}

	cases := []struct {
		name string
		want []string // identities expected to survive the filter, in order
	}{
		{name: "default-thresholds", want: []string{"warn", "stale", "aws-warn"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectStale(policy.Default(), all, now)
			var gotIDs []string
			for _, c := range got {
				gotIDs = append(gotIDs, c.Identity)
			}
			if len(gotIDs) != len(tc.want) {
				t.Fatalf("selected %v, want %v", gotIDs, tc.want)
			}
			for i := range tc.want {
				if gotIDs[i] != tc.want[i] {
					t.Fatalf("selected %v, want %v", gotIDs, tc.want)
				}
			}
			// Nothing OK must ever survive the filter.
			for _, c := range got {
				if st, _ := policy.Default().Evaluate(c, now); st == policy.OK {
					t.Errorf("SelectStale kept an OK credential %q", c.Identity)
				}
			}
		})
	}
}
