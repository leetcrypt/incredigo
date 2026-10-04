package pwstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"

	"incredigo/internal/vault"
)

// Bitwarden adapts the official `bw` CLI. It reads logins with `bw list items`
// and updates ONE item's password in place with `bw edit item <id>` — the
// encoded item is piped via STDIN so the new password never appears on argv and
// no plaintext file is ever written (the safe ItemUpdater path).
//
// The caller is responsible for an authenticated, unlocked session (BW_SESSION in
// the environment); this adapter inherits the process environment and shells out.
type Bitwarden struct {
	Bin string // default "bw"; injectable for tests
}

func init() { Register(&Bitwarden{}) }

func (b *Bitwarden) Name() string { return "bitwarden" }

func (b *Bitwarden) bin() string {
	if b.Bin != "" {
		return b.Bin
	}
	return "bw"
}

// Available reports whether the bw binary is resolvable.
func (b *Bitwarden) Available() bool {
	if b.Bin != "" {
		return true // explicitly injected (tests)
	}
	_, err := exec.LookPath("bw")
	return err == nil
}

// bwItem is the subset of a `bw` item we read/write. Unknown fields are preserved
// across an edit by round-tripping through a json.RawMessage map (see updateRaw).
type bwItem struct {
	ID    string `json:"id"`
	Type  int    `json:"type"` // 1 = login
	Name  string `json:"name"`
	Login *struct {
		Username string `json:"username"`
		Password string `json:"password"`
		URIs     []struct {
			URI string `json:"uri"`
		} `json:"uris"`
	} `json:"login"`
}

// Export runs `bw list items` and maps every login item into an Account.
func (b *Bitwarden) Export(ctx context.Context, v *vault.Vault) ([]Account, error) {
	out, err := exec.CommandContext(ctx, b.bin(), "list", "items").Output()
	if err != nil {
		return nil, fmt.Errorf("bitwarden: list items: %w", err)
	}
	var items []bwItem
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("bitwarden: decode items: %w", err)
	}
	var accts []Account
	for _, it := range items {
		if it.Login == nil {
			continue
		}
		a := Account{
			ID:       it.ID,
			Username: it.Login.Username,
			Meta:     map[string]string{"name": it.Name},
		}
		if len(it.Login.URIs) > 0 {
			a.URL = it.Login.URIs[0].URI
			a.Site = hostFromURL(a.URL)
		}
		a.Secret = v.Store([]byte(it.Login.Password))
		accts = append(accts, a)
	}
	return accts, nil
}

// UpdatePassword rewrites acct's password in place. It re-fetches the item as a
// raw map (so every field — folder, notes, custom fields — survives), swaps in the
// new password, re-encodes, and pipes the base64 to `bw edit item <id>` on stdin.
func (b *Bitwarden) UpdatePassword(ctx context.Context, v *vault.Vault, acct Account, newPassword *vault.Handle) error {
	if acct.ID == "" {
		return fmt.Errorf("bitwarden: account has no item id — cannot update in place")
	}
	raw, err := exec.CommandContext(ctx, b.bin(), "get", "item", acct.ID).Output()
	if err != nil {
		return fmt.Errorf("bitwarden: get item: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("bitwarden: decode item: %w", err)
	}
	login, ok := obj["login"].(map[string]any)
	if !ok {
		return fmt.Errorf("bitwarden: item %s is not a login", acct.ID)
	}

	pwBuf, err := v.Open(newPassword)
	if err != nil {
		return err
	}
	login["password"] = string(pwBuf.Bytes())
	obj["login"] = login

	encoded, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("bitwarden: encode item: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString(encoded)
	// Wipe the transient plaintext JSON buffer now that it is base64-wrapped.
	for i := range encoded {
		encoded[i] = 0
	}

	cmd := exec.CommandContext(ctx, b.bin(), "edit", "item", acct.ID)
	cmd.Stdin = bytes.NewReader([]byte(b64))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bitwarden: edit item: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
