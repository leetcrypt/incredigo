package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"incredigo/internal/discover"
)

func TestLoad(t *testing.T) {
	// Empty path → built-in default.
	if p, err := Load(""); err != nil || p.Defaults.WarnAfter != 60 {
		t.Fatalf("Load(\"\") = %+v, %v; want default", p, err)
	}

	// Missing file → default (not an error).
	miss := filepath.Join(t.TempDir(), "nope.yaml")
	if p, err := Load(miss); err != nil || p.Defaults.StaleAfter != 90 {
		t.Fatalf("Load(missing) = %+v, %v; want default", p, err)
	}

	// Valid file → parsed onto the Default() base: a struct field absent from the
	// file keeps its default (stale_after stays 90), while an override is applied.
	f := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(f, []byte("defaults:\n  warn_after: 10d\noverrides:\n  aws_key:\n    warn_after: 5d\n    stale_after: 45d\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(f)
	if err != nil {
		t.Fatalf("Load(valid): %v", err)
	}
	if p.Defaults.WarnAfter != 10 || p.Defaults.StaleAfter != 90 {
		t.Errorf("defaults = %+v, want {10 90} (stale kept from Default)", p.Defaults)
	}
	if got := p.Overrides[discover.KindAWSKey]; got.WarnAfter != 5 || got.StaleAfter != 45 {
		t.Errorf("aws_key override = %+v, want {5 45}", got)
	}

	// Malformed YAML → error.
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("defaults: [this is not a mapping"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("Load(malformed) returned no error")
	}

	// Unreadable (a directory, not a regular file) → a non-IsNotExist error.
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("Load(directory) returned no error")
	}
}

func TestDaysUnmarshal(t *testing.T) {
	ok := map[string]Days{
		"60":     60,
		"60d":    60,
		"8w":     56,
		"  90d ": 90,
		"0":      0,
	}
	for in, want := range ok {
		var d Days
		if err := yaml.Unmarshal([]byte(in), &d); err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
			continue
		}
		if d != want {
			t.Errorf("%q: got %d want %d", in, d, want)
		}
	}
	for _, bad := range []string{"60x", "abc", "d"} {
		var d Days
		if err := yaml.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("%q: expected error, got %d", bad, d)
		}
	}
}

func TestPolicyYAMLWithSuffixes(t *testing.T) {
	src := `
defaults:
  warn_after: 60d
  stale_after: 90d
overrides:
  private_key:
    warn_after: 26w
`
	p := Default()
	if err := yaml.Unmarshal([]byte(src), &p); err != nil {
		t.Fatal(err)
	}
	if p.Defaults.WarnAfter != 60 || p.Defaults.StaleAfter != 90 {
		t.Errorf("defaults = %+v", p.Defaults)
	}
	if p.Overrides[discover.KindPrivateKey].WarnAfter != 182 { // 26*7
		t.Errorf("private_key warn_after = %d, want 182", p.Overrides[discover.KindPrivateKey].WarnAfter)
	}
}

func TestEvaluate(t *testing.T) {
	p := Default() // defaults 60/90; aws_key 30/90
	now := time.Now()
	aged := func(days int, kind discover.Kind) discover.Credential {
		return discover.Credential{Kind: kind, Modified: now.Add(-time.Duration(days) * 24 * time.Hour)}
	}

	cases := []struct {
		name string
		cred discover.Credential
		want State
	}{
		{"fresh token", aged(10, discover.KindToken), OK},
		{"warn token", aged(70, discover.KindToken), Warn},
		{"stale token", aged(100, discover.KindToken), Stale},
		{"aws warns earlier", aged(40, discover.KindAWSKey), Warn},
		{"aws fresh", aged(20, discover.KindAWSKey), OK},
	}
	for _, c := range cases {
		if st, _ := p.Evaluate(c.cred, now); st != c.want {
			t.Errorf("%s: got %s want %s", c.name, st, c.want)
		}
	}
}
