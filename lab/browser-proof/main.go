// Command browser-proof is the headless driver behind lab/browser-proof.sh: it
// runs the browserrot GiteaSite recipe through the FULL safety spine against a
// DISPOSABLE, containerized Gitea (127.0.0.1:<port>, throwaway account) — the
// browser analog of lab/podman-proof.sh's API-driver proof.
//
// Unlike lab/rung4-gitea-browser (which targets a REAL, self-owned instance and
// requires an explicit CHROME_BIN), this harness lets go-rod AUTO-DOWNLOAD its
// Chromium to ~/.cache/rod when CHROME_BIN is unset — no host package install.
// It performs no independent auth check itself: the shell wrapper does the
// ground-truth "OLD rejected / NEW works" proof over the Gitea API, so this binary
// only has to run the incredigo spine and report success.
//
// Safety spine (identical ordering to rung4's live path, mirroring the API drivers):
//   - Hard Rule 1: rotate.Snapshot (verified sealed backup) BEFORE any change.
//   - Hard Rule 2 (browser variant): the site invalidates the OLD password the
//     instant the NEW one is set, so we STORE immediately after Rotate, then Verify.
//   - Hard Rule 3: secrets cross as vault []byte only — never logged, never argv.
//   - Hard Rule 5: self-owned throwaway account, one credential, no MFA bypass.
//
// Env (all provided by browser-proof.sh):
//
//	GITEA_BASE            scheme+host of the disposable container, e.g. http://127.0.0.1:41234
//	GITEA_USER            the throwaway account login
//	GITEA_STORE_PATH      gopass entry holding the OLD password (line 1)   [default gitea/login-creds]
//	INCREDIGO_PASSPHRASE  seal passphrase for the mandatory backup gate    [required]
//	CHROME_BIN            optional Chromium path; unset -> go-rod auto-downloads to ~/.cache/rod
//	BACKUP_DIR            dir for the sealed backup .age                    [default ./.backups]
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"incredigo/internal/browserrot"
	"incredigo/internal/discover"
	"incredigo/internal/pwgen"
	"incredigo/internal/rotate"
	"incredigo/internal/sink"
	"incredigo/internal/vault"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nBROWSER_ROT_HARNESS_FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	base := os.Getenv("GITEA_BASE")
	user := os.Getenv("GITEA_USER")
	storePath := env("GITEA_STORE_PATH", "gitea/login-creds")
	chrome := os.Getenv("CHROME_BIN") // "" -> go-rod auto-downloads
	pass := os.Getenv("INCREDIGO_PASSPHRASE")
	backupDir := env("BACKUP_DIR", ".backups")
	if base == "" || user == "" {
		return fmt.Errorf("GITEA_BASE and GITEA_USER are required")
	}
	if pass == "" {
		return fmt.Errorf("INCREDIGO_PASSPHRASE required for the mandatory backup gate")
	}

	// Generous overall bound: the FIRST run downloads Chromium inside the initial
	// browser Open (unbounded by this ctx), then each rod op is bounded by the
	// driver's per-op Timeout below. 6 min comfortably covers the spine's ~4 browser
	// sessions (pre-change login, change, verify-new, verify-stored) on loopback.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	v := vault.New()
	defer v.Purge()

	gp := &sink.Gopass{}
	if !gp.Available() {
		return fmt.Errorf("gopass not found on PATH")
	}

	// Load the OLD password (line 1 of the entry) into the vault as a handle.
	oldH, err := gp.Show(ctx, v, storePath)
	if err != nil {
		return fmt.Errorf("load old secret from %q: %w", storePath, err)
	}
	cred := discover.Credential{
		Source:   "browser-proof",
		Identity: user + " @ " + base,
		Location: storePath,
		Secret:   oldH,
		Meta:     map[string]string{"username": user},
	}

	site := browserrot.GiteaSite(base, user)
	// Insecure=false: the disposable container serves plain http on loopback, so
	// there is no TLS chain to skip. Headless=true: no host display needed.
	drv := &browserrot.RodDriver{Bin: chrome, Headless: true, Insecure: false, Timeout: 45 * time.Second}
	rot := browserrot.New(site, drv, pwgen.DefaultPolicy())

	fmt.Fprintf(os.Stderr, "target : %s (user %s)\n", base, user)
	fmt.Fprintf(os.Stderr, "driver : %s (chrome=%q auto-download=%v)\n", drv.Name(), chrome, chrome == "")
	fmt.Fprintf(os.Stderr, "proof  : recipe level = %v\n\n", rot.Proof())

	// Hard Rule 1 — MANDATORY verified backup gate, BEFORE any change.
	passH := v.Store([]byte(pass))
	passBuf, err := v.Open(passH)
	if err != nil {
		return fmt.Errorf("open passphrase: %w", err)
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return err
	}
	backupOut := filepath.Join(backupDir, "gitea-browser-proof-"+time.Now().UTC().Format("2006-01-02T15-04-05Z")+".age")
	n, err := rotate.Snapshot(ctx, gp, "gitea", &sink.Age{}, passBuf, backupOut)
	if err != nil {
		return fmt.Errorf("backup gate failed — refusing to rotate: %w", err)
	}
	fmt.Fprintf(os.Stderr, "BACKUP_GATE_OK: %d gitea entr(ies) sealed + verified -> %s\n", n, backupOut)

	// Rotate: pre-change login(OLD) -> change form -> site confirms. On success the
	// OLD password is now DEAD at the site and newH holds the working new secret.
	fmt.Fprintln(os.Stderr, "ROTATE: driving the headless change-password flow…")
	newH, err := rot.Rotate(ctx, cred, v)
	if err != nil {
		return fmt.Errorf("rotate failed (old secret kept if change did not submit): %w", err)
	}
	fmt.Fprintln(os.Stderr, "ROTATE_OK: site confirmed the password change.")

	// STORE IMMEDIATELY — close the lockout window before anything else.
	if err := gp.InsertAt(ctx, v, storePath, newH, true); err != nil {
		return fmt.Errorf("STORE FAILED after a successful change — new password ACTIVE at %s but NOT saved to gopass %q: %w", cred.Identity, storePath, err)
	}
	fmt.Fprintf(os.Stderr, "STORE_OK: new password persisted at gopass %q.\n", storePath)

	// Verify: re-login with the new secret (from vault), then re-read from gopass and
	// re-login again to prove the stored bytes are the working secret.
	fmt.Fprintln(os.Stderr, "VERIFY: re-login with the new password…")
	if err := rot.Verify(ctx, newH, v); err != nil {
		v.Forget(newH)
		return fmt.Errorf("verify(new) failed but the new password IS stored: %w", err)
	}
	v.Forget(newH)

	rh, err := gp.Show(ctx, v, storePath)
	if err != nil {
		return fmt.Errorf("re-read stored secret: %w", err)
	}
	if err := rot.Verify(ctx, rh, v); err != nil {
		v.Forget(rh)
		return fmt.Errorf("verify(stored) failed: %w", err)
	}
	v.Forget(rh)

	// RevokeOld is a no-op for a website password (the site already invalidated old).
	if err := rot.RevokeOld(ctx, cred, v); err != nil {
		return fmt.Errorf("revoke-old: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nBROWSER_ROT_HARNESS_OK: %s (backup %s)\n", cred.Identity, backupOut)
	return nil
}
