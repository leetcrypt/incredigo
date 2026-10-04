// Package links derives the web page a user must visit to rotate a credential by
// hand. It is OFFLINE and pure — it never makes a network call. A URL comes from
// one of three sources, in order of quality: a curated per-service table, the
// RFC 8615 `/.well-known/change-password` convention (which sites redirect to
// their real change-password page), or nothing when no web host can be derived.
package links

import (
	"strings"

	"incredigo/internal/discover"
)

type Source string

const (
	SourceKnown     Source = "known"      // curated credential/change-password page
	SourceWellKnown Source = "well-known" // RFC 8615 /.well-known/change-password
	SourceNone      Source = "none"       // no web host could be derived
)

// Link is a generated rotation URL plus how it was derived.
type Link struct {
	URL    string
	Source Source
}

// curated maps a host to the exact page where its credential is rotated.
var curated = map[string]string{
	"github.com":             "https://github.com/settings/tokens",
	"ghcr.io":                "https://github.com/settings/tokens",
	"gitlab.com":             "https://gitlab.com/-/user_settings/personal_access_tokens",
	"gitea.com":              "https://gitea.com/user/settings/applications",
	"pypi.org":               "https://pypi.org/manage/account/token/",
	"npmjs.com":              "https://www.npmjs.com/settings/~/tokens",
	"registry.npmjs.org":     "https://www.npmjs.com/settings/~/tokens",
	"hub.docker.com":         "https://hub.docker.com/settings/security",
	"docker.io":              "https://hub.docker.com/settings/security",
	"index.docker.io":        "https://hub.docker.com/settings/security",
	"digitalocean.com":       "https://cloud.digitalocean.com/account/api/tokens",
	"cloudflare.com":         "https://dash.cloudflare.com/profile/api-tokens",
	"stripe.com":             "https://dashboard.stripe.com/apikeys",
	"openai.com":             "https://platform.openai.com/api-keys",
	"anthropic.com":          "https://console.anthropic.com/settings/keys",
	"sendgrid.com":           "https://app.sendgrid.com/settings/api_keys",
	"amazonaws.com":          "https://console.aws.amazon.com/iam/home#/security_credentials",
	"console.aws.amazon.com": "https://console.aws.amazon.com/iam/home#/security_credentials",
	"heroku.com":             "https://dashboard.heroku.com/account/applications",
}

// serviceByScanner supplies a host/service when the credential carries no usable
// host of its own (e.g. an AWS key from ~/.aws/credentials).
var serviceByScanner = map[string]string{
	"aws": "console.aws.amazon.com",
}

// serviceHost maps a scanner's non-secret service hint (discover.MetaService) to
// the web host whose curated page rotates that credential. This is how guided-only
// credentials — GitHub PATs and Stripe keys, which have no scriptable rotation API
// — get a change-password link even though they arrive from the env/file scanner
// with no host of their own.
var serviceHost = map[string]string{
	"github": "github.com",
	"stripe": "stripe.com",
}

// For returns the best rotation URL for a host.
func For(host string) Link {
	h := normalize(host)
	if h == "" {
		return Link{Source: SourceNone}
	}
	if u, ok := curated[h]; ok {
		return Link{URL: u, Source: SourceKnown}
	}
	if u, ok := curated[parentDomain(h)]; ok {
		return Link{URL: u, Source: SourceKnown}
	}
	return Link{URL: "https://" + h + "/.well-known/change-password", Source: SourceWellKnown}
}

// HostFor derives a web host from a discovered credential, or "" if none applies
// (e.g. ssh keys and opaque file/env secrets have no rotation page).
func HostFor(c discover.Credential) string {
	// A scanner-recognised provider (GitHub PAT, Stripe key) carries a non-secret
	// service hint — the strongest signal, since the value prefix is unambiguous.
	if svc := c.Meta[discover.MetaService]; svc != "" {
		if h, ok := serviceHost[svc]; ok {
			return h
		}
	}
	// "user @ host" identities (git, netrc).
	if i := strings.LastIndex(c.Identity, " @ "); i >= 0 {
		if host := strings.TrimSpace(c.Identity[i+3:]); host != "" && host != "default" {
			return host
		}
	}
	// docker identity is the registry host.
	if c.Source == "docker" && c.Identity != "" {
		return c.Identity
	}
	if s, ok := serviceByScanner[c.Source]; ok {
		return s
	}
	return ""
}

// LinkFor is HostFor composed with For.
func LinkFor(c discover.Credential) Link { return For(HostFor(c)) }

func normalize(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i] // strip port
	}
	return h
}

// parentDomain returns the registrable-ish parent ("api.github.com" -> "github.com")
// for a one-level curated fallback. Good enough for the common multi-part TLD-free
// cases we curate; the well-known fallback covers everything else.
func parentDomain(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return h
}
