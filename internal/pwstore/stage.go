package pwstore

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"incredigo/internal/vault"
)

// StagedImporter is implemented by the browser-CSV adapters (Chrome/Firefox). Unlike
// ItemUpdater (which mutates one item by id with no file), a browser store can only be
// updated by re-importing a whole CSV, so the commit path stages that CSV on tmpfs and
// shreds it. The path is returned so the caller can tell the human exactly which file to
// re-import; cleanup MUST be deferred until after the human confirms.
type StagedImporter interface {
	ImportStaged(v *vault.Vault, accts []Account, newPw map[int]*vault.Handle) (path string, cleanup func(), err error)
}

// Reimporter is optionally implemented by StagedImporters to provide a manager-specific
// instruction telling the human exactly where to re-import the staged CSV (e.g. a browser
// settings URL or a manager's import menu path). The commit path uses it when present.
type Reimporter interface {
	ReimportHint() string
}

// stagedRecord is one line of a sealed staged list. It carries the manager-native id
// (so a headless commit can target the right item) plus the non-secret labels and the
// password. The password is plaintext ONLY inside this struct in RAM; on disk this
// record exists exclusively inside a Sealer-encrypted stream (age), never as cleartext —
// identical to the backup-bundle rule. Hence it is safe to persist a staged list of NEW
// passwords across the plan→commit gap a headless run needs.
type stagedRecord struct {
	ID       string `json:"id,omitempty"`
	Site     string `json:"site,omitempty"`
	URL      string `json:"url,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
}

// WriteStaged streams accts as JSON-lines into w, substituting the NEW password from
// newPw (keyed by account index) where present and otherwise keeping the account's
// existing Secret. The caller pipes w into a Sealer so the bytes are encrypted before
// they ever reach disk. Passing newPw=nil writes the accounts' current passwords — used
// for the mandatory pre-commit backup of the existing store.
func WriteStaged(w io.Writer, v *vault.Vault, accts []Account, newPw map[int]*vault.Handle) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	for i, a := range accts {
		h := a.Secret
		if newPw != nil {
			if nh, ok := newPw[i]; ok && nh != nil {
				h = nh
			}
		}
		pw, err := readHandle(v, h)
		if err != nil {
			return err
		}
		rec := stagedRecord{ID: a.ID, Site: a.Site, URL: a.URL, Username: a.Username, Password: pw}
		err = enc.Encode(&rec)
		wipeStr(&pw)
		rec.Password = ""
		if err != nil {
			return err
		}
	}
	return bw.Flush()
}

// ReadStaged parses a JSON-lines staged stream (already decrypted by the Sealer) back
// into Accounts, storing each password in v as a handle. It is the inverse of
// WriteStaged: used to verify a backup bundle and to load a staged new-password list
// for a headless commit.
func ReadStaged(v *vault.Vault, r io.Reader) ([]Account, error) {
	var out []Account
	dec := json.NewDecoder(bufio.NewReader(r))
	for {
		var rec stagedRecord
		err := dec.Decode(&rec)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("pwstore: decode staged record: %w", err)
		}
		a := Account{
			ID:       rec.ID,
			Site:     rec.Site,
			URL:      rec.URL,
			Username: rec.Username,
			Meta:     map[string]string{},
		}
		if a.Site == "" {
			a.Site = hostFromURL(a.URL)
		}
		a.Secret = v.Store([]byte(rec.Password))
		rec.Password = ""
		out = append(out, a)
	}
	return out, nil
}
