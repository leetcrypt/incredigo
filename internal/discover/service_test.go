package discover

import "testing"

func TestServiceForSecret(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want string
	}{
		{"github classic pat", "ghp_0123456789abcdefABCDEF", "github"},
		{"github fine-grained pat", "github_pat_11ABCDE0000xyz", "github"},
		{"github oauth", "gho_abcdef0123456789", "github"},
		{"github server", "ghs_abcdef0123456789", "github"},
		{"stripe secret live", "sk_live_51HxYzAbCdEf", "stripe"},
		{"stripe secret test", "sk_test_51HxYzAbCdEf", "stripe"},
		{"stripe restricted", "rk_live_51HxYzAbCdEf", "stripe"},
		{"leading whitespace", "\n  ghp_abc123", "github"},
		{"unknown opaque token", "xoxb-not-a-known-prefix", ""},
		{"random high entropy", "Zk9fQ2pVw7eR1tY3", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ServiceForSecret([]byte(c.val)); got != c.want {
				t.Errorf("ServiceForSecret(%q) = %q, want %q", c.val, got, c.want)
			}
		})
	}
}
