package discover

import "bytes"

// MetaService is the Meta key under which a scanner records the issuing service of
// a credential it recognised by value-prefix (e.g. "github", "stripe"). It is a
// NON-SECRET hint: the value is a fixed service name, never the secret material.
// The links/worklist layer turns it into a guided change-password URL for
// credentials that have no scriptable rotation API (GitHub PATs, Stripe keys).
const MetaService = "service"

// servicePrefixes maps a credential's well-known, PUBLIC value prefix to the
// service that issued it. Each prefix is a documented format marker — not the
// secret itself — so matching one and recording the service name leaks nothing.
var servicePrefixes = []struct {
	prefix  []byte
	service string
}{
	{[]byte("github_pat_"), "github"}, // fine-grained PAT
	{[]byte("ghp_"), "github"},        // classic personal access token
	{[]byte("gho_"), "github"},        // OAuth access token
	{[]byte("ghu_"), "github"},        // user-to-server token
	{[]byte("ghs_"), "github"},        // server-to-server token
	{[]byte("ghr_"), "github"},        // refresh token
	{[]byte("sk_live_"), "stripe"},    // secret key (live)
	{[]byte("sk_test_"), "stripe"},    // secret key (test)
	{[]byte("rk_live_"), "stripe"},    // restricted key (live)
	{[]byte("rk_test_"), "stripe"},    // restricted key (test)
}

// ServiceForSecret recognises a credential by its well-known value prefix and
// returns the issuing service ("github", "stripe", …) or "" if unrecognised. It
// inspects only the leading bytes and returns a fixed service NAME, so no secret
// material escapes. Callers attach the result as Meta[MetaService] so the
// links/worklist layer can offer a guided rotation page for credentials that
// cannot be rotated through a provider API.
func ServiceForSecret(b []byte) string {
	head := bytes.TrimLeft(b, " \t\r\n")
	for _, sp := range servicePrefixes {
		if bytes.HasPrefix(head, sp.prefix) {
			return sp.service
		}
	}
	return ""
}
