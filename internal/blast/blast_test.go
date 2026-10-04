package blast

import (
	"os"
	"path/filepath"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

func TestMarkers(t *testing.T) {
	cases := []struct {
		name string
		cred discover.Credential
		want []string
	}{
		{"env var name", discover.Credential{Identity: ".env / API_TOKEN"}, []string{"API_TOKEN"}},
		{"hostname", discover.Credential{Identity: "github.com / alice"}, []string{"github.com"}},
		{"redacted aws key yields nothing", discover.Credential{
			Identity: "default / AKIA****Xy",
			Meta:     map[string]string{"access_key_id": "AKIA****Xy"},
		}, nil},
		{"all-caps service", discover.Credential{Identity: "SENDGRID / mail"}, []string{"SENDGRID"}},
		{"generic profile dropped", discover.Credential{Identity: "default / prod"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Markers(c.cred)
			if !eq(got, c.want) {
				t.Fatalf("Markers(%q) = %v, want %v", c.cred.Identity, got, c.want)
			}
		})
	}
}

func TestMapFindsConsumersNotSecret(t *testing.T) {
	dir := t.TempDir()
	// The credential's own source file (should NOT be reported as a consumer).
	src := filepath.Join(dir, ".env")
	secret := "s3cr3t-VALUE-do-not-find-me"
	write(t, src, "API_TOKEN="+secret+"\n")
	// A genuine consumer referencing the var name.
	consumer := filepath.Join(dir, "docker-compose.yml")
	write(t, consumer, "services:\n  app:\n    environment:\n      - API_TOKEN=${API_TOKEN}\n")
	// A file that contains ONLY the secret value, never the marker — must be ignored.
	leak := filepath.Join(dir, "random.txt")
	write(t, leak, secret+"\n")
	// Noise dir that must be skipped.
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "node_modules", "x.js"), "API_TOKEN here\n")

	v := vault.New()
	defer v.Purge()
	creds := []discover.Credential{{
		Source:   "env",
		Identity: ".env / API_TOKEN",
		Location: src,
		Secret:   v.Store([]byte(secret)),
	}}

	res, err := Map(creds, Options{Roots: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}

	files := res[0].Files()
	if len(files) != 1 || filepath.Base(files[0]) != "docker-compose.yml" {
		t.Fatalf("consumers = %v, want only docker-compose.yml", files)
	}

	// Leak-check: the secret value must never appear as a marker or a hit.
	for _, m := range res[0].Markers {
		if m == secret {
			t.Fatal("secret value leaked into markers")
		}
	}
	for _, h := range res[0].Hits {
		if filepath.Base(h.File) == "random.txt" {
			t.Fatal("matched a file by secret value — must only match non-secret markers")
		}
		if h.Marker == secret {
			t.Fatal("secret value used as a marker")
		}
	}
}

func TestContainsToken(t *testing.T) {
	cases := []struct {
		line, marker string
		want         bool
	}{
		{"- API_TOKEN=${API_TOKEN}", "API_TOKEN", true},
		{"MY_API_TOKEN_EXTRA=1", "API_TOKEN", false}, // bounded, not a substring hit
		{"host: github.com", "github.com", true},
		{"github.community", "github.com", false},
	}
	for _, c := range cases {
		if got := containsToken(c.line, c.marker); got != c.want {
			t.Errorf("containsToken(%q,%q)=%t want %t", c.line, c.marker, got, c.want)
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func eq(a, b []string) bool {
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
