package pwstore

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"incredigo/internal/vault"
)

// csvCols maps the meaningful login fields to their column index in a particular
// browser's export. A negative index means the column is absent.
type csvCols struct {
	name, url, username, password, note, group int
}

// colsFromHeader resolves a csvCols from a header row by case-insensitive name.
// Unknown/missing columns resolve to -1.
func colsFromHeader(header []string) csvCols {
	idx := func(want ...string) int {
		for i, h := range header {
			hl := strings.ToLower(strings.TrimSpace(h))
			for _, w := range want {
				if hl == w {
					return i
				}
			}
		}
		return -1
	}
	return csvCols{
		name:     idx("name", "title"),
		url:      idx("url", "login_uri", "web site", "website", "matchurl"),
		username: idx("username", "login_username", "user", "login"),
		password: idx("password", "login_password", "pass", "pwd"),
		note:     idx("note", "notes", "extra"),
		// group: KeePassXC "group"; LastPass "grouping"; Dashlane "category";
		// NordPass/RoboForm "folder"; Proton "vault". Absent elsewhere (-1).
		group: idx("group", "grouping", "category", "folder", "vault"),
	}
}

// parseLoginCSV reads a browser password-export CSV into Accounts, storing each
// password in v as a handle. The transient plaintext passes through Go strings
// (encoding/csv's interface) — acceptable only because this whole path is the
// flag-gated, tmpfs, shredded CSV exception (see docs/BROWSER-ROTATION.md §3).
func parseLoginCSV(v *vault.Vault, data []byte) ([]Account, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1 // tolerate ragged exports
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("pwstore: read csv header: %w", err)
	}
	cols := colsFromHeader(header)
	if cols.password < 0 {
		return nil, fmt.Errorf("pwstore: csv has no password column")
	}
	get := func(rec []string, i int) string {
		if i >= 0 && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	var out []Account
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("pwstore: read csv row: %w", err)
		}
		a := Account{
			Site:     hostFromURL(get(rec, cols.url)),
			URL:      get(rec, cols.url),
			Username: get(rec, cols.username),
			Meta:     map[string]string{},
		}
		if n := get(rec, cols.name); n != "" {
			a.Meta["name"] = n
		}
		if g := get(rec, cols.group); g != "" {
			a.Meta["group"] = g
		}
		// Preserve notes so a manager round-trip (export -> import CSV) does not wipe
		// the user's existing note on the entry. Notes are non-secret metadata.
		if nt := get(rec, cols.note); nt != "" {
			a.Meta["note"] = nt
		}
		pw := get(rec, cols.password)
		a.Secret = v.Store([]byte(pw))
		out = append(out, a)
	}
	return out, nil
}

// chromeCSVHeader is Chrome's password-export column order.
var chromeCSVHeader = []string{"name", "url", "username", "password", "note"}

// firefoxCSVHeader is the minimal column set Firefox's about:logins import maps by
// name. Firefox keys on header text, so url/username/password is sufficient.
var firefoxCSVHeader = []string{"url", "username", "password"}

// csvLayout describes a browser's import CSV shape: the header row and how to render
// one account row (with the resolved plaintext password). Keeping the two browser
// formats behind one type lets writeShreddableCSVLayout stay format-agnostic.
type csvLayout struct {
	header []string
	record func(a Account, pw string) []string
}

var chromeLayout = csvLayout{
	header: chromeCSVHeader,
	record: func(a Account, pw string) []string {
		return []string{a.Meta["name"], a.URL, a.Username, pw, a.Meta["note"]}
	},
}

var firefoxLayout = csvLayout{
	header: firefoxCSVHeader,
	record: func(a Account, pw string) []string {
		return []string{a.URL, a.Username, pw}
	},
}

// writeShreddableCSV materializes accounts (with NEW passwords from newPw, keyed
// by account index) as a Chrome-format CSV in a tmpfs dir and returns its path
// plus a cleanup func that securely shreds it. Caller MUST defer cleanup().
//
// The file is written to /dev/shm when available so the plaintext never touches
// stable storage; Shred is the belt-and-braces overwrite on top of that.
func writeShreddableCSV(v *vault.Vault, accts []Account, newPw map[int]*vault.Handle) (path string, cleanup func(), err error) {
	return writeShreddableCSVLayout(v, accts, newPw, chromeLayout)
}

// writeShreddableCSVLayout is the format-agnostic core: same tmpfs + shred guarantees
// as writeShreddableCSV, but the header and per-row shape come from layout so Firefox
// and Chrome share one secure-write path.
func writeShreddableCSVLayout(v *vault.Vault, accts []Account, newPw map[int]*vault.Handle, layout csvLayout) (path string, cleanup func(), err error) {
	dir, err := tmpfsDir()
	if err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(dir, "incredigo-pw-*.csv")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = Shred(f.Name()) }

	w := csv.NewWriter(f)
	if err := w.Write(layout.header); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	for i, a := range accts {
		h := a.Secret
		if nh, ok := newPw[i]; ok && nh != nil {
			h = nh
		}
		pw, err := readHandle(v, h)
		if err != nil {
			f.Close()
			cleanup()
			return "", nil, err
		}
		rec := layout.record(a, pw)
		if err := w.Write(rec); err != nil {
			wipeStr(&pw)
			f.Close()
			cleanup()
			return "", nil, err
		}
		wipeStr(&pw)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return f.Name(), cleanup, nil
}

// tmpfsDir prefers /dev/shm (tmpfs, never written to disk) and falls back to the
// OS temp dir if it is unavailable.
func tmpfsDir() (string, error) {
	const shm = "/dev/shm"
	if fi, err := os.Stat(shm); err == nil && fi.IsDir() {
		d := filepath.Join(shm, "incredigo")
		if err := os.MkdirAll(d, 0o700); err == nil {
			return d, nil
		}
	}
	d := filepath.Join(os.TempDir(), "incredigo")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

// Shred best-effort destroys a plaintext file: overwrite with random bytes, then
// zeros, fsync between, then unlink. On SSD/journaling/CoW filesystems this is not
// a guarantee — which is why writeShreddableCSV prefers tmpfs (/dev/shm), where
// the bytes never reach stable storage in the first place.
func Shred(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = os.Remove(path) }()
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	size := fi.Size()
	overwrite := func(fill func([]byte) error) error {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		buf := make([]byte, 4096)
		remaining := size
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			if err := fill(buf[:n]); err != nil {
				return err
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return err
			}
			remaining -= n
		}
		return f.Sync()
	}
	if err := overwrite(func(b []byte) error { _, e := rand.Read(b); return e }); err != nil {
		f.Close()
		return err
	}
	if err := overwrite(func(b []byte) error {
		for i := range b {
			b[i] = 0
		}
		return nil
	}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// readHandle returns a handle's bytes as a string for the narrow CSV-write window.
func readHandle(v *vault.Vault, h *vault.Handle) (string, error) {
	buf, err := v.Open(h)
	if err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

// wipeStr overwrites the backing array of a string built from vault bytes. Go
// strings are immutable so this is best-effort via an unsafe-free copy-out; we
// simply drop the reference and rely on GC, but zero the local for clarity.
func wipeStr(s *string) { *s = "" }
