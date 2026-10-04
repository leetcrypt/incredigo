package pwstore

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"incredigo/internal/vault"
)

// Keychain adapts the macOS `security` CLI as a login source for the passwords engine.
// It targets INTERNET passwords (class "inet" — website/app logins), the slice that
// maps onto a change-password rotation; generic ("genp") items (Wi-Fi, app secrets)
// are deliberately skipped.
//
// The `security` binary is pure exec with no platform syscalls, so this file compiles
// and unit-tests everywhere (via an injected fake `Bin`); Available() returns false off
// macOS so the registry singleton is inert on Linux. Read paths keep secrets off argv
// (`find-internet-password -w` prints to stdout). The WRITE path, however, has no stdin
// option: `security add-internet-password -w <pw>` takes the password on ARGV — a CLI
// limitation, identical in shape to 1Password's argv caveat (documented, MOCK-ONLY).
type Keychain struct {
	Bin      string // default "security"; injectable for tests
	Keychain string // optional keychain path; default == the login keychain
}

func init() { Register(&Keychain{}) }

func (k *Keychain) Name() string { return "keychain" }

func (k *Keychain) bin() string {
	if k.Bin != "" {
		return k.Bin
	}
	return "security"
}

// Available is true only on macOS (or when a fake Bin is injected for tests) — this
// guards against an unrelated `security` binary on a non-macOS PATH.
func (k *Keychain) Available() bool {
	if k.Bin != "" {
		return true // injected (tests)
	}
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath("security")
	return err == nil
}

// kcItem is one internet-password item's non-secret identity from dump-keychain.
type kcItem struct {
	server  string // "srvr" attribute (hostname)
	account string // "acct" attribute (login)
}

// Export dumps the keychain, parses the internet-password items, and fetches each
// secret with find-internet-password. Items whose secret cannot be read (locked, no
// ACL) are skipped rather than aborting the whole export.
func (k *Keychain) Export(ctx context.Context, v *vault.Vault) ([]Account, error) {
	args := []string{"dump-keychain"}
	if k.Keychain != "" {
		args = append(args, k.Keychain)
	}
	out, err := exec.CommandContext(ctx, k.bin(), args...).Output()
	if err != nil {
		return nil, fmt.Errorf("keychain: dump-keychain: %w", err)
	}
	items := parseKeychainDump(out)
	var accts []Account
	for _, it := range items {
		h, err := k.readPassword(ctx, v, it.server, it.account)
		if err != nil {
			continue // unreadable item — skip, do not fail the export
		}
		accts = append(accts, Account{
			ID:       it.server + "/" + it.account,
			Site:     hostFromURL(it.server),
			URL:      it.server,
			Username: it.account,
			Secret:   h,
			Meta:     map[string]string{"name": it.server},
		})
	}
	return accts, nil
}

// readPassword runs `find-internet-password -s <server> -a <account> -w`, capturing the
// printed secret straight into the vault and wiping the transient buffer.
func (k *Keychain) readPassword(ctx context.Context, v *vault.Vault, server, account string) (*vault.Handle, error) {
	args := []string{"find-internet-password", "-s", server, "-a", account, "-w"}
	if k.Keychain != "" {
		args = append(args, k.Keychain)
	}
	cmd := exec.CommandContext(ctx, k.bin(), args...)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("keychain: find-internet-password: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	b := bytes.TrimRight(out.Bytes(), "\r\n")
	h := v.Store(b) // Store copies into locked memory and wipes b
	zero(out.Bytes())
	return h, nil
}

// UpdatePassword replaces an internet password. The keychain has no in-place edit, so
// the old item is deleted (best-effort) and a new one added. Server/account come from
// the round-trip-safe URL/Username fields (NOT Meta, which the staged list drops).
func (k *Keychain) UpdatePassword(ctx context.Context, v *vault.Vault, acct Account, newPassword *vault.Handle) error {
	server := acct.URL
	if server == "" {
		server = acct.Site
	}
	account := acct.Username
	if server == "" {
		return fmt.Errorf("keychain: account missing server — cannot locate the item to update")
	}
	pwBuf, err := v.Open(newPassword)
	if err != nil {
		return err
	}
	newpw := string(pwBuf.Bytes())

	// Best-effort delete of the existing item (a missing item is not an error here).
	delArgs := []string{"delete-internet-password", "-s", server, "-a", account}
	if k.Keychain != "" {
		delArgs = append(delArgs, k.Keychain)
	}
	_ = exec.CommandContext(ctx, k.bin(), delArgs...).Run()

	// NOTE: -w puts the new password on ARGV — unavoidable with the `security` CLI,
	// which offers no stdin path for add-internet-password. Documented in §8.
	addArgs := []string{"add-internet-password", "-s", server, "-a", account, "-w", newpw}
	if k.Keychain != "" {
		addArgs = append(addArgs, k.Keychain)
	}
	out, err := exec.CommandContext(ctx, k.bin(), addArgs...).CombinedOutput()
	wipeStr(&newpw)
	if err != nil {
		return fmt.Errorf("keychain: add-internet-password: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// parseKeychainDump scans `security dump-keychain` output for internet-password items,
// pulling the "srvr" (server) and "acct" (account) attributes from each block. A block
// starts at a `keychain:` line; `class: "inet"` marks it as an internet password. Other
// classes (e.g. "genp") are ignored.
func parseKeychainDump(out []byte) []kcItem {
	var items []kcItem
	var cur kcItem
	var isInet bool
	flush := func() {
		if isInet && cur.server != "" {
			items = append(items, cur)
		}
		cur = kcItem{}
		isInet = false
	}
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "keychain:"):
			flush() // new item block begins
		case strings.HasPrefix(t, "class:"):
			isInet = strings.Contains(t, `"inet"`)
		case strings.HasPrefix(t, `"srvr"`):
			if val, ok := kcAttrValue(t); ok {
				cur.server = val
			}
		case strings.HasPrefix(t, `"acct"`):
			if val, ok := kcAttrValue(t); ok {
				cur.account = val
			}
		}
	}
	flush()
	return items
}

// kcAttrValue extracts the quoted value from a dump-keychain attribute line such as
//
//	"srvr"<blob>="github.com"
//
// returning ("github.com", true). Lines with no value (`<NULL>`) return ok=false.
func kcAttrValue(line string) (string, bool) {
	i := strings.Index(line, "=")
	if i < 0 {
		return "", false
	}
	rhs := strings.TrimSpace(line[i+1:])
	if !strings.HasPrefix(rhs, `"`) {
		return "", false // e.g. =<NULL> or a hex 0x… form we don't decode
	}
	rhs = rhs[1:]
	if j := strings.LastIndex(rhs, `"`); j >= 0 {
		return rhs[:j], true
	}
	return "", false
}
