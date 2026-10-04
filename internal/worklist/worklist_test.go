package worklist

import (
	"strings"
	"testing"

	"incredigo/internal/discover"
)

func TestBuildAndMarkdown(t *testing.T) {
	creds := []discover.Credential{
		{Source: "git", Identity: "alice @ github.com", Kind: discover.KindToken},
		{Source: "ssh", Identity: "id_ed25519", Kind: discover.KindPrivateKey},
		{Source: "docker", Identity: "ghcr.io", Kind: discover.KindPassword},
	}
	items := Build(creds)
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3", len(items))
	}
	// git and docker have no driver (manual); ssh now has a registered driver.
	if !items[0].Manual() {
		t.Errorf("git item should be manual, got driver %q", items[0].Driver)
	}
	if items[1].Manual() || items[1].Driver != "ssh" {
		t.Errorf("ssh item should be auto via driver %q, got %q", "ssh", items[1].Driver)
	}
	if !items[2].Manual() {
		t.Errorf("docker item should be manual, got driver %q", items[2].Driver)
	}
	// github link is curated; ssh has no web page.
	if items[0].Link.URL != "https://github.com/settings/tokens" {
		t.Errorf("git link = %q", items[0].Link.URL)
	}
	if items[1].Link.URL != "" {
		t.Errorf("ssh should have no link, got %q", items[1].Link.URL)
	}

	md := Markdown(items)
	for _, want := range []string{
		"# incredigo rotation worklist",
		"3 credential(s)",
		"https://github.com/settings/tokens",
		"alice @ github.com",
		"auto: ssh",        // ssh now driver-handled
		"— (no web page)",  // ssh row has no link
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, md)
		}
	}
}

func TestMarkdownHasNoSecrets(t *testing.T) {
	// Identities are pre-redacted; assert the renderer never invents a secret column.
	items := Build([]discover.Credential{{Source: "aws", Identity: "default / AKIA***"}})
	md := Markdown(items)
	if strings.Contains(strings.ToLower(md), "password |") && strings.Contains(md, "secret value") {
		t.Error("worklist must not contain a secret-value column")
	}
}
