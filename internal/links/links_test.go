package links

import (
	"testing"

	"incredigo/internal/discover"
)

func TestFor(t *testing.T) {
	cases := []struct {
		host    string
		wantURL string
		wantSrc Source
	}{
		{"github.com", "https://github.com/settings/tokens", SourceKnown},
		{"GitHub.com:443", "https://github.com/settings/tokens", SourceKnown},
		{"api.github.com", "https://github.com/settings/tokens", SourceKnown}, // parent-domain fallback
		{"s3.amazonaws.com", "https://console.aws.amazon.com/iam/home#/security_credentials", SourceKnown},
		{"example.com", "https://example.com/.well-known/change-password", SourceWellKnown},
		{"registry.internal.corp", "https://registry.internal.corp/.well-known/change-password", SourceWellKnown},
		{"", "", SourceNone},
	}
	for _, c := range cases {
		got := For(c.host)
		if got.URL != c.wantURL || got.Source != c.wantSrc {
			t.Errorf("For(%q) = {%q,%s}, want {%q,%s}", c.host, got.URL, got.Source, c.wantURL, c.wantSrc)
		}
	}
}

func TestHostFor(t *testing.T) {
	cases := []struct {
		cred discover.Credential
		want string
	}{
		{discover.Credential{Source: "git", Identity: "alice @ github.com"}, "github.com"},
		{discover.Credential{Source: "netrc", Identity: "bob @ api.example.com"}, "api.example.com"},
		{discover.Credential{Source: "netrc", Identity: "bob @ default"}, ""}, // netrc "default" is not a host
		{discover.Credential{Source: "docker", Identity: "ghcr.io"}, "ghcr.io"},
		{discover.Credential{Source: "aws", Identity: "default / AKIA***"}, "console.aws.amazon.com"},
		{discover.Credential{Source: "ssh", Identity: "id_ed25519"}, ""},
		{discover.Credential{Source: "file", Identity: "keys/deploy"}, ""},
	}
	for _, c := range cases {
		if got := HostFor(c.cred); got != c.want {
			t.Errorf("HostFor(%s/%q) = %q, want %q", c.cred.Source, c.cred.Identity, got, c.want)
		}
	}
}

func TestLinkForGit(t *testing.T) {
	l := LinkFor(discover.Credential{Source: "git", Identity: "alice @ github.com"})
	if l.Source != SourceKnown || l.URL != "https://github.com/settings/tokens" {
		t.Errorf("LinkFor git github = {%q,%s}", l.URL, l.Source)
	}
}

// A GitHub PAT / Stripe key arrives from the env or file scanner with no host of
// its own, only a non-secret service hint. HostFor must turn that hint into the
// curated change-password host so the guided worklist gets a real link.
func TestHostForServiceHint(t *testing.T) {
	cases := []struct {
		service string
		want    string
	}{
		{"github", "github.com"},
		{"stripe", "stripe.com"},
		{"unknown", ""},
	}
	for _, c := range cases {
		cred := discover.Credential{
			Source:   "env",
			Identity: ".env / API_KEY",
			Meta:     map[string]string{discover.MetaService: c.service},
		}
		if got := HostFor(cred); got != c.want {
			t.Errorf("HostFor(service=%q) = %q, want %q", c.service, got, c.want)
		}
	}
}

func TestLinkForServiceHint(t *testing.T) {
	cases := []struct {
		service string
		wantURL string
	}{
		{"github", "https://github.com/settings/tokens"},
		{"stripe", "https://dashboard.stripe.com/apikeys"},
	}
	for _, c := range cases {
		cred := discover.Credential{
			Source:   "env",
			Identity: ".env / TOKEN",
			Meta:     map[string]string{discover.MetaService: c.service},
		}
		l := LinkFor(cred)
		if l.Source != SourceKnown || l.URL != c.wantURL {
			t.Errorf("LinkFor(service=%q) = {%q,%s}, want {%q,known}", c.service, l.URL, l.Source, c.wantURL)
		}
	}
}
