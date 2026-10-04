// Package policy is the local-only expiry engine. It reads credential mtimes and
// reports age against thresholds. No network calls in v1.
package policy

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"incredigo/internal/discover"
)

type State string

const (
	OK    State = "ok"
	Warn  State = "warn"
	Stale State = "stale"
)

// Thresholds in days. Zero means "unset / no opinion".
type Threshold struct {
	WarnAfter  Days `yaml:"warn_after"`
	StaleAfter Days `yaml:"stale_after"`
}

type Policy struct {
	Defaults  Threshold                    `yaml:"defaults"`
	Overrides map[discover.Kind]Threshold `yaml:"overrides"`
}

// Default policy used when no config file is present.
func Default() Policy {
	return Policy{
		Defaults: Threshold{WarnAfter: 60, StaleAfter: 90},
		Overrides: map[discover.Kind]Threshold{
			discover.KindAWSKey:     {WarnAfter: 30, StaleAfter: 90},
			discover.KindPrivateKey: {WarnAfter: 180},
		},
	}
}

// Load reads a YAML policy file, falling back to Default if path is empty or
// missing.
func Load(path string) (Policy, error) {
	if path == "" {
		return Default(), nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Policy{}, err
	}
	p := Default()
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Evaluate returns the state and age for one credential.
func (p Policy) Evaluate(c discover.Credential, now time.Time) (State, time.Duration) {
	age := now.Sub(c.Modified)
	t := p.Defaults
	if ov, ok := p.Overrides[c.Kind]; ok {
		if ov.WarnAfter != 0 {
			t.WarnAfter = ov.WarnAfter
		}
		if ov.StaleAfter != 0 {
			t.StaleAfter = ov.StaleAfter
		}
	}
	switch {
	case t.StaleAfter != 0 && age >= t.StaleAfter.Duration():
		return Stale, age
	case t.WarnAfter != 0 && age >= t.WarnAfter.Duration():
		return Warn, age
	default:
		return OK, age
	}
}

// Days is a day-count threshold. In policy.yaml it may be written either as a
// bare integer (`60`) or with a unit suffix: `60d` (days) or `8w` (weeks). Zero
// means "unset / no opinion".
type Days int

func (d Days) Duration() time.Duration { return time.Duration(d) * 24 * time.Hour }

// UnmarshalYAML accepts a scalar that is either an integer count of days or a
// string with a `d`/`w` unit suffix, so the DESIGN's `warn_after: 60d` form and a
// plain `warn_after: 60` both work.
func (d *Days) UnmarshalYAML(node *yaml.Node) error {
	s := strings.TrimSpace(node.Value)
	if s == "" {
		*d = 0
		return nil
	}
	mult := 1
	switch s[len(s)-1] {
	case 'd', 'D':
		s = strings.TrimSpace(s[:len(s)-1])
	case 'w', 'W':
		mult = 7
		s = strings.TrimSpace(s[:len(s)-1])
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("policy: invalid day threshold %q (want e.g. 60, 60d, or 8w)", node.Value)
	}
	*d = Days(n * mult)
	return nil
}
