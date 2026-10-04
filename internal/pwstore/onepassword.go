package pwstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"incredigo/internal/vault"
)

// OnePassword adapts the official `op` CLI. It reads logins with `op item list` +
// `op item get` and updates ONE item's password in place with `op item edit`.
//
// Argv caveat (documented, not hidden): unlike Bitwarden, `op item edit` has NO
// stdin-per-field path — only `op item create` reads from stdin. The two safe-on-
// paper alternatives both have costs: a JSON template would write the plaintext to
// disk (forbidden, hard rule 3), so the remaining real path is an argv field
// assignment `op item edit <id> password=<new>`. That value is therefore visible to
// same-uid processes via /proc/<pid>/cmdline for the ~tens-of-ms the op exec lives.
// This is strictly weaker than the Bitwarden stdin path; it is recorded as such in
// docs/ROTATION-PROOFS.md and the op proof level is gated accordingly. We choose
// argv (transient, same-uid, in-RAM) over a disk template (rule-3 violation).
//
// The caller is responsible for an authenticated `op` session; this adapter inherits
// the process environment and shells out.
type OnePassword struct {
	Bin string // default "op"; injectable for tests
}

func init() { Register(&OnePassword{}) }

func (o *OnePassword) Name() string { return "1password" }

func (o *OnePassword) bin() string {
	if o.Bin != "" {
		return o.Bin
	}
	return "op"
}

// Available reports whether the op binary is resolvable.
func (o *OnePassword) Available() bool {
	if o.Bin != "" {
		return true // explicitly injected (tests)
	}
	_, err := exec.LookPath("op")
	return err == nil
}

// opItem is the subset of an `op item get --format=json` we read. op nests the
// password and URLs inside a flat fields array rather than a login object.
type opItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"` // "LOGIN" for logins
	URLs     []struct {
		Href string `json:"href"`
	} `json:"urls"`
	Fields []struct {
		ID    string `json:"id"`    // "username", "password", …
		Type  string `json:"type"`  // "STRING", "CONCEALED", …
		Value string `json:"value"` // present only with --reveal
	} `json:"fields"`
}

func (it opItem) field(id string) string {
	for _, f := range it.Fields {
		if f.ID == id {
			return f.Value
		}
	}
	return ""
}

// opSummary is the lighter shape returned by `op item list`.
type opSummary struct {
	ID       string `json:"id"`
	Category string `json:"category"`
}

// Export lists login items, then fetches each (with --reveal) to read the password.
func (o *OnePassword) Export(ctx context.Context, v *vault.Vault) ([]Account, error) {
	out, err := exec.CommandContext(ctx, o.bin(), "item", "list", "--categories", "Login", "--format=json").Output()
	if err != nil {
		return nil, fmt.Errorf("1password: item list: %w", err)
	}
	var summaries []opSummary
	if err := json.Unmarshal(out, &summaries); err != nil {
		return nil, fmt.Errorf("1password: decode item list: %w", err)
	}
	var accts []Account
	for _, s := range summaries {
		raw, err := exec.CommandContext(ctx, o.bin(), "item", "get", s.ID, "--reveal", "--format=json").Output()
		if err != nil {
			return nil, fmt.Errorf("1password: item get %s: %w", s.ID, err)
		}
		var it opItem
		if err := json.Unmarshal(raw, &it); err != nil {
			return nil, fmt.Errorf("1password: decode item %s: %w", s.ID, err)
		}
		a := Account{
			ID:       it.ID,
			Username: it.field("username"),
			Meta:     map[string]string{"name": it.Title},
		}
		if len(it.URLs) > 0 {
			a.URL = it.URLs[0].Href
			a.Site = hostFromURL(a.URL)
		}
		a.Secret = v.Store([]byte(it.field("password")))
		accts = append(accts, a)
	}
	return accts, nil
}

// UpdatePassword rewrites acct's password in place via `op item edit <id> password=<new>`.
// See the argv caveat on the type doc: op has no stdin-per-field edit, so the new
// value transits this process's argv for the brief op exec. The plaintext is read
// from the vault into a single argv string and not retained anywhere else.
func (o *OnePassword) UpdatePassword(ctx context.Context, v *vault.Vault, acct Account, newPassword *vault.Handle) error {
	if acct.ID == "" {
		return fmt.Errorf("1password: account has no item id — cannot update in place")
	}
	pwBuf, err := v.Open(newPassword)
	if err != nil {
		return err
	}
	assignment := "password=" + string(pwBuf.Bytes())
	cmd := exec.CommandContext(ctx, o.bin(), "item", "edit", acct.ID, assignment, "--format=json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("1password: item edit: %w: %s", err, out)
	}
	return nil
}
