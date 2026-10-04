// Command rung4-gitea-browser is the M-B4 live-fire harness: it drives the
// browserrot engine against a REAL, self-owned Gitea account to rotate the login
// PASSWORD in the browser (not an API PAT — that was rung-3). It is deliberately a
// dedicated one-shot program because browserrot is not wired into the CLI `rotate`
// command yet; this run is exactly the run that PROMOTES the GiteaSite recipe from
// UNPROVEN to LIVE-REAL, so it cannot go through the proof gate that would skip it.
//
// It honors the same safety spine as the API drivers:
//   - Hard Rule 1: rotate.Snapshot (verified sealed backup) runs BEFORE any change.
//   - Hard Rule 2 (adapted for browser): a website invalidates the OLD password the
//     instant the new one is set — RevokeOld is a no-op and "revoke" happens AT the
//     change, not after. So the only lockout window is between form-submit and the
//     gopass store. We therefore STORE the new secret IMMEDIATELY after Rotate
//     succeeds, then Verify by re-login. (The API-spine order verify->store is for
//     creds whose old value stays valid until an explicit revoke; that guarantee
//     does not exist for a browser password change.)
//   - Hard Rule 3: no plaintext on disk — secrets cross as vault []byte only.
//   - Hard Rule 5: self-owned account, one credential, no MFA bypass (if a second
//     factor appears the success marker won't match and we fail SAFE, old kept).
//
// Secrets come from gopass/env ONLY, never argv. Two modes (env MODE):
//   probe (default) — read-only: log in with the OLD password to validate the login
//                     selectors + success marker against the live instance. No writes,
//                     no backup, no change. Run this first.
//   live            — the irreversible rotation: backup -> Rotate -> store -> Verify.
//
// Env:
//   INCREDIGO_PASSPHRASE  seal passphrase for the backup gate (live mode)   [required in live]
//   CHROME_BIN            path to a Chromium binary                          [required]
//   GITEA_BASE            scheme+host (default https://100.117.177.50:3030)
//   GITEA_USER            account login  (default trill-technician)
//   GITEA_STORE_PATH      gopass entry   (default gitea/login-creds)
//   GITEA_INSECURE=1      accept the self-signed cert (Tailscale host)       [set for 100.x]
//   MODE                  probe | live  (default probe)
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
		fmt.Fprintf(os.Stderr, "\n✗ %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	mode := env("MODE", "probe")
	base := env("GITEA_BASE", "https://100.117.177.50:3030")
	user := env("GITEA_USER", "trill-technician")
	storePath := env("GITEA_STORE_PATH", "gitea/login-creds")
	chrome := os.Getenv("CHROME_BIN")
	insecure := os.Getenv("GITEA_INSECURE") == "1"
	if chrome == "" {
		return fmt.Errorf("CHROME_BIN is required (a Chromium binary)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
		Source:   "browserrot-rung4",
		Identity: user + " @ " + base,
		Location: storePath,
		Secret:   oldH,
		Meta:     map[string]string{"username": user},
	}

	site := browserrot.GiteaSite(base, user)
	drv := &browserrot.RodDriver{Bin: chrome, Headless: true, Insecure: insecure, Timeout: 45 * time.Second}
	rot := browserrot.New(site, drv, pwgen.DefaultPolicy())

	fmt.Fprintf(os.Stderr, "target : %s (user %s)\n", base, user)
	fmt.Fprintf(os.Stderr, "driver : %s  insecure=%v\n", drv.Name(), insecure)
	fmt.Fprintf(os.Stderr, "mode   : %s\n\n", mode)

	switch mode {
	case "probe":
		// Read-only: a login with the OLD password. Verify(old) opens a session,
		// runs the Login flow, and checks Login.SuccessText. No writes, no change.
		fmt.Fprintln(os.Stderr, "PROBE: logging in with the OLD password (read-only, no writes)…")
		if err := rot.Verify(ctx, oldH, v); err != nil {
			return fmt.Errorf("probe login failed — fix login selectors/marker before live: %w", err)
		}
		fmt.Fprintln(os.Stderr, "✓ PROBE OK: login selectors + success marker validated against the live instance.")
		fmt.Fprintln(os.Stderr, "  Re-run with MODE=live to perform the irreversible rotation.")
		return nil

	case "live":
		return live(ctx, gp, v, rot, cred, storePath)

	default:
		return fmt.Errorf("unknown MODE %q (want probe|live)", mode)
	}
}

func live(ctx context.Context, gp *sink.Gopass, v *vault.Vault, rot *browserrot.Rotator, cred discover.Credential, storePath string) error {
	// Hard Rule 1 — MANDATORY verified backup gate, BEFORE any change.
	passEnv := os.Getenv("INCREDIGO_PASSPHRASE")
	if passEnv == "" {
		return fmt.Errorf("INCREDIGO_PASSPHRASE required for the backup gate in live mode")
	}
	passH := v.Store([]byte(passEnv))
	passBuf, err := v.Open(passH)
	if err != nil {
		return fmt.Errorf("open passphrase: %w", err)
	}

	dir := ".backups"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	backupOut := filepath.Join(dir, "gitea-rung4-browser-"+time.Now().UTC().Format("2006-01-02T15-04-05Z")+".age")
	n, err := rotate.Snapshot(ctx, gp, "gitea", &sink.Age{}, passBuf, backupOut)
	if err != nil {
		return fmt.Errorf("backup gate failed — refusing to rotate: %w", err)
	}
	fmt.Fprintf(os.Stderr, "✓ backup gate: %d gitea entr(ies) sealed + verified -> %s\n\n", n, backupOut)

	// Rotate: pre-change login(OLD) -> change form -> site confirms. On success the
	// OLD password is now DEAD at the site and newH holds the working new secret.
	fmt.Fprintln(os.Stderr, "ROTATE: driving the browser change-password flow…")
	newH, err := rot.Rotate(ctx, cred, v)
	if err != nil {
		// Rotate forgets newH itself on any internal failure; if the fill/submit
		// never landed the OLD password is still valid (safe). If it DID land but the
		// success marker missed, see the recovery note below.
		return fmt.Errorf("rotate failed (old secret kept if change did not submit): %w", err)
	}
	fmt.Fprintln(os.Stderr, "✓ site confirmed the password change.")

	// STORE IMMEDIATELY — close the lockout window before doing anything else. The
	// new secret is now the only working credential; persist it first, verify second.
	if err := gp.InsertAt(ctx, v, storePath, newH, true); err != nil {
		// Worst case: new password active at the site but the store failed. Print the
		// recovery path loudly. (We never print the secret.)
		return fmt.Errorf("STORE FAILED after a successful change — the new password is ACTIVE at %s but NOT saved to gopass %q. Recover via the tea API token or the Gitea server CLI, then re-run store: %w", cred.Identity, storePath, err)
	}
	fmt.Fprintf(os.Stderr, "✓ new password stored at gopass %q (metadata lines dropped — re-add username/url/notes if desired).\n", storePath)

	// Verify: re-login with the new secret (from vault), then re-read from gopass and
	// re-login again to prove the stored bytes are the working secret.
	fmt.Fprintln(os.Stderr, "VERIFY: re-login with the new password…")
	if err := rot.Verify(ctx, newH, v); err != nil {
		v.Forget(newH)
		return fmt.Errorf("verify(new) failed but the new password IS stored — check the account manually: %w", err)
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

	fmt.Fprintf(os.Stderr, "\n✓✓ LIVE-REAL rotation complete: %s\n", cred.Identity)
	fmt.Fprintf(os.Stderr, "   backup: %s\n", backupOut)
	fmt.Fprintln(os.Stderr, "   Promote GiteaSite recipe to ProofLiveReal.")
	return nil
}
