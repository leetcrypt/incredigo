// Command incredigo-browserrot-host is the small native-messaging host that Chrome
// SPAWNS for the browserrot MV3 extension (internal/browserrot/extension/). When the
// extension calls chrome.runtime.connectNative("org.incredigo.browserrot"), Chrome
// starts this program and wires the native-messaging pipe to its stdio:
//
//	os.Stdin   <- result frames the extension posts back    (command RESULTS)
//	os.Stdout  -> command frames Chrome delivers to the ext  (COMMANDS)
//
// so the zero-value &browserrot.ExtensionDriver{} (which defaults In/Out to os.Stdin/
// os.Stdout) is exactly the production driver. This host then runs the SAME safety
// spine as lab/browser-proof/main.go — mandatory verified backup gate (rotate.Snapshot)
// -> Rotate (via the extension, against the user's already-open, already-authenticated
// tab) -> store immediately -> Verify — for ONE configured credential.
//
// Safety spine (identical ordering to the go-rod browser-proof path and the API drivers):
//   - Hard Rule 1: rotate.Snapshot (verified sealed backup) BEFORE any change.
//   - Hard Rule 2 (browser variant): the site invalidates the OLD password the instant
//     the NEW one is set, so we STORE immediately after Rotate, then Verify.
//   - Hard Rule 3: secrets cross as vault []byte only — never logged, never argv, never
//     written to os.Stdout (which is the native-messaging pipe; only os.Stderr is used
//     for human-readable status here).
//   - Outcome unknown: if the submit's result cannot be read and no login probe settles it,
//     the new secret is saved at "<entry>.pending" (never over the old) and the run stops.
//   - Hard Rule 4 (fail SAFE): a site rejection / MFA / CAPTCHA makes the success marker
//     not match, Rotate fails cleanly, and the OLD secret is kept (browserrot.go).
//
// CONFIG — from ENV (the channel Chrome-spawned hosts actually get) with optional flag
// overrides for a manual/interactive invocation. NOTHING is hardcoded:
//
//	INCREDIGO_SITE_BASE            scheme+host of the target, e.g. https://git.example.org   [required]
//	INCREDIGO_SITE_USER            the account login for that site                            [required]
//	INCREDIGO_RECIPE               curated recipe to use: "gitea" (default; selectable)
//	INCREDIGO_STORE_PREFIX         gopass path prefix (joined with the credential key)        [default ""]
//	INCREDIGO_CREDENTIAL           gopass credential key holding the OLD password (line 1)    [default gitea/login-creds]
//	INCREDIGO_BACKUP_DIR           dir for the sealed backup .age                             [default ~/.incredigo/browserrot-backups]
//	INCREDIGO_LOGIN_BEFORE_CHANGE  "0"/"false" to skip the pre-change login (unnecessary when
//	                               the extension drives an already-authenticated tab)         [default true]
//	INCREDIGO_PASSPHRASE           seal passphrase for the mandatory backup gate              [required]
//
// The matching flags (-site-base, -site-user, -recipe, -store-prefix, -credential,
// -backup-dir, -login-before-change) override the env when set. Chrome passes its own
// argv (the extension origin, a parent-window handle); unrecognized flags there are
// ignored so the host still starts from the environment.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/term"

	"incredigo/internal/browserrot"
	"incredigo/internal/discover"
	"incredigo/internal/pwgen"
	"incredigo/internal/rotate"
	"incredigo/internal/sink"
	"incredigo/internal/vault"
)

// version is stamped for the -version path; a bare identifier is fine for a lab host.
const version = "incredigo-browserrot-host 0.1.0"

func main() {
	os.Exit(realMain(os.Args[1:], os.Getenv, os.Stdin, os.Stderr))
}

// realMain is the testable entry point. It resolves config, applies the no-pipe guard,
// and runs the spine. It returns a process exit code (0 = ok / clean help/guard exit).
func realMain(args []string, getenv func(string) string, stdin *os.File, logw io.Writer) int {
	ov, showHelp, showVersion, err := parseFlags(args, logw)
	if err != nil {
		// A flag error here almost always means Chrome-passed argv (extension origin /
		// parent-window handle). Report it and fall through to env-only resolution
		// rather than refusing to start.
		fmt.Fprintf(logw, "note: ignoring unrecognized arguments (%v); using environment config\n", err)
		ov = overrides{}
	}
	if showHelp {
		printUsage(logw)
		return 0
	}
	if showVersion {
		fmt.Fprintln(logw, version)
		return 0
	}

	// No-pipe guard: this host is meant to be SPAWNED by Chrome with the native-messaging
	// pipe on stdio. Run interactively (stdin is a TTY) it would block forever on the first
	// readFrame. Detect that and exit cleanly with guidance instead of hanging.
	if term.IsTerminal(int(stdin.Fd())) {
		fmt.Fprintln(logw, "incredigo-browserrot-host: native-messaging host — Chrome spawns this with a pipe on stdin/stdout.")
		fmt.Fprintln(logw, "Run interactively there is no pipe; nothing to do. See -h for the config it reads, or")
		fmt.Fprintln(logw, "internal/browserrot/extension/README.md + lab/extension-proof.md for the install steps.")
		return 0
	}

	cfg, err := buildConfig(getenv, ov)
	if err != nil {
		fmt.Fprintf(logw, "incredigo-browserrot-host: %v\n", err)
		return 2
	}
	if err := run(context.Background(), cfg, getenv, logw); err != nil {
		fmt.Fprintf(logw, "\nBROWSER_ROT_HOST_FAIL: %v\n", err)
		return 1
	}
	return 0
}

// overrides carries only the flags a caller actually SET, so unset flags fall through
// to the environment (nil pointer = not set).
type overrides struct {
	siteBase, siteUser, recipe, storePrefix, credential, backupDir *string
	loginBeforeChange                                              *bool
}

// parseFlags parses argv leniently. It returns the set-flag overrides plus whether help
// or version was requested. flag.ErrHelp (from -h/--help) is reported as showHelp, not
// an error, so the caller prints usage and exits 0.
func parseFlags(args []string, logw io.Writer) (ov overrides, showHelp, showVersion bool, err error) {
	fs := flag.NewFlagSet("incredigo-browserrot-host", flag.ContinueOnError)
	fs.SetOutput(logw)
	// No-op usage: -h returns flag.ErrHelp, and the caller prints usage exactly once
	// (avoids the double print flag's default Usage would cause).
	fs.Usage = func() {}

	siteBase := fs.String("site-base", "", "scheme+host of the target site (env INCREDIGO_SITE_BASE)")
	siteUser := fs.String("site-user", "", "account login for the target site (env INCREDIGO_SITE_USER)")
	recipe := fs.String("recipe", "", "curated recipe: gitea (env INCREDIGO_RECIPE)")
	storePrefix := fs.String("store-prefix", "", "gopass path prefix (env INCREDIGO_STORE_PREFIX)")
	credential := fs.String("credential", "", "gopass credential key holding the OLD password (env INCREDIGO_CREDENTIAL)")
	backupDir := fs.String("backup-dir", "", "directory for the sealed backup (env INCREDIGO_BACKUP_DIR)")
	loginBefore := fs.Bool("login-before-change", true, "log in with the OLD secret before the change page (env INCREDIGO_LOGIN_BEFORE_CHANGE; false for an already-authenticated tab)")
	ver := fs.Bool("version", false, "print version and exit")

	if perr := fs.Parse(args); perr != nil {
		if perr == flag.ErrHelp {
			return overrides{}, true, false, nil
		}
		return overrides{}, false, false, perr
	}
	if *ver {
		return overrides{}, false, true, nil
	}
	// Only pass through flags that were explicitly set, so env defaults still apply
	// to the rest.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "site-base":
			ov.siteBase = siteBase
		case "site-user":
			ov.siteUser = siteUser
		case "recipe":
			ov.recipe = recipe
		case "store-prefix":
			ov.storePrefix = storePrefix
		case "credential":
			ov.credential = credential
		case "backup-dir":
			ov.backupDir = backupDir
		case "login-before-change":
			ov.loginBeforeChange = loginBefore
		}
	})
	return ov, false, false, nil
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `incredigo-browserrot-host — native-messaging host for the browserrot MV3 extension.

Chrome spawns this binary (name org.incredigo.browserrot) and wires the native-messaging
pipe to stdin/stdout. It runs the incredigo safety spine — verified backup gate -> Rotate
(via the extension, against the user's open tab) -> store -> Verify — for one credential.

Config comes from the ENVIRONMENT (Chrome-spawned) with optional flag overrides:

  INCREDIGO_SITE_BASE            scheme+host, e.g. https://git.example.org   [required]
  INCREDIGO_SITE_USER            account login for that site                 [required]
  INCREDIGO_RECIPE               recipe: gitea (default)
  INCREDIGO_STORE_PREFIX         gopass path prefix                          [default ""]
  INCREDIGO_CREDENTIAL           gopass credential key (OLD password)        [default gitea/login-creds]
  INCREDIGO_BACKUP_DIR           sealed-backup dir                           [default ~/.incredigo/browserrot-backups]
  INCREDIGO_LOGIN_BEFORE_CHANGE  0/false to skip pre-change login            [default true]
  INCREDIGO_PASSPHRASE           backup-gate seal passphrase                 [required]

Flags: -site-base -site-user -recipe -store-prefix -credential -backup-dir
       -login-before-change -version -h

The secret is NEVER logged, written to disk in plaintext, or placed on os.Stdout (the pipe).
`)
}

// config is the fully-resolved, validated run configuration (no secret bytes).
type config struct {
	SiteBase          string
	SiteUser          string
	Recipe            string
	StorePath         string // joined prefix + credential key — the gopass entry to rotate
	BackupDir         string
	LoginBeforeChange bool
}

// buildConfig resolves config from env (overridden by any set flags), applies defaults,
// and validates. getenv is injected so it is unit-testable without touching the process
// environment.
func buildConfig(getenv func(string) string, ov overrides) (config, error) {
	pick := func(o *string, envKey, def string) string {
		if o != nil {
			return *o
		}
		if v := getenv(envKey); v != "" {
			return v
		}
		return def
	}

	c := config{
		SiteBase:  strings.TrimSpace(pick(ov.siteBase, "INCREDIGO_SITE_BASE", "")),
		SiteUser:  strings.TrimSpace(pick(ov.siteUser, "INCREDIGO_SITE_USER", "")),
		Recipe:    strings.ToLower(strings.TrimSpace(pick(ov.recipe, "INCREDIGO_RECIPE", "gitea"))),
		BackupDir: pick(ov.backupDir, "INCREDIGO_BACKUP_DIR", defaultBackupDir(getenv)),
	}

	prefix := pick(ov.storePrefix, "INCREDIGO_STORE_PREFIX", "")
	credential := pick(ov.credential, "INCREDIGO_CREDENTIAL", "gitea/login-creds")
	c.StorePath = joinStore(prefix, credential)

	// login-before-change: default true (mirrors the GiteaSite recipe + browser-proof).
	c.LoginBeforeChange = true
	if ov.loginBeforeChange != nil {
		c.LoginBeforeChange = *ov.loginBeforeChange
	} else if v := getenv("INCREDIGO_LOGIN_BEFORE_CHANGE"); v != "" {
		c.LoginBeforeChange = !isFalsey(v)
	}

	if c.SiteBase == "" || c.SiteUser == "" {
		return c, fmt.Errorf("INCREDIGO_SITE_BASE and INCREDIGO_SITE_USER are required (site to rotate)")
	}
	if c.StorePath == "" {
		return c, fmt.Errorf("a gopass credential key is required (INCREDIGO_CREDENTIAL / -credential)")
	}
	if _, err := siteFor(c.Recipe, c.SiteBase, c.SiteUser); err != nil {
		return c, err
	}
	return c, nil
}

// siteFor builds the curated Site for a recipe name. Adding a recipe is one case here;
// an unknown recipe fails cleanly (never a silent wrong target).
func siteFor(recipe, base, user string) (browserrot.Site, error) {
	switch recipe {
	case "", "gitea":
		return browserrot.GiteaSite(base, user), nil
	default:
		return browserrot.Site{}, fmt.Errorf("unknown recipe %q (want: gitea)", recipe)
	}
}

// joinStore combines a gopass prefix and a credential key into one entry path.
func joinStore(prefix, credential string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	credential = strings.Trim(strings.TrimSpace(credential), "/")
	if prefix == "" {
		return credential
	}
	if credential == "" {
		return prefix
	}
	return prefix + "/" + credential
}

func defaultBackupDir(getenv func(string) string) string {
	return filepath.Join(getenv("HOME"), ".incredigo", "browserrot-backups")
}

func isFalsey(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

// run executes the safety spine for one credential over the extension driver. It mirrors
// lab/browser-proof/main.go exactly, swapping RodDriver for the ExtensionDriver: the
// spine ordering (backup gate -> Rotate -> store -> Verify -> revoke) is unchanged, and
// on any failure the OLD secret is kept.
func run(ctx context.Context, cfg config, getenv func(string) string, logw io.Writer) error {
	pass := getenv("INCREDIGO_PASSPHRASE")
	if pass == "" {
		return fmt.Errorf("INCREDIGO_PASSPHRASE required for the mandatory backup gate")
	}

	// Generous overall bound: the human logs the tab in by hand, then triggers; each
	// extension op is additionally bounded by the driver Timeout below.
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()

	v := vault.New()
	defer v.Purge()

	gp := &sink.Gopass{}
	if !gp.Available() {
		return fmt.Errorf("gopass not found on PATH")
	}

	// Load the OLD password (line 1 of the entry) into the vault as a handle.
	oldH, err := gp.Show(ctx, v, cfg.StorePath)
	if err != nil {
		return fmt.Errorf("load old secret from %q: %w", cfg.StorePath, err)
	}
	cred := discover.Credential{
		Source:   "browserrot-host",
		Identity: cfg.SiteUser + " @ " + cfg.SiteBase,
		Location: cfg.StorePath,
		Secret:   oldH,
		Meta:     map[string]string{"username": cfg.SiteUser},
	}

	site, err := siteFor(cfg.Recipe, cfg.SiteBase, cfg.SiteUser)
	if err != nil {
		return err
	}
	// The extension drives the user's REAL, already-authenticated tab, so a pre-change
	// re-login with the OLD secret is normally unnecessary (lab/extension-proof.md step 5).
	// Default keeps the recipe's setting; -login-before-change=false skips it.
	site.LoginBeforeChange = cfg.LoginBeforeChange

	// Zero-value driver: In/Out default to os.Stdin/os.Stdout, which Chrome has wired to
	// the native-messaging pipe. Per-op timeout mirrors the go-rod proof.
	drv := &browserrot.ExtensionDriver{Timeout: 45 * time.Second}
	rot := browserrot.New(site, drv, pwgen.DefaultPolicy())

	fmt.Fprintf(logw, "target : %s (user %s, recipe %s)\n", cfg.SiteBase, cfg.SiteUser, cfg.Recipe)
	fmt.Fprintf(logw, "driver : %s (login-before-change=%v)\n", drv.Name(), site.LoginBeforeChange)
	fmt.Fprintf(logw, "proof  : recipe level = %v\n\n", rot.Proof())

	// Hard Rule 1 — MANDATORY verified backup gate, BEFORE any change.
	passH := v.Store([]byte(pass))
	passBuf, err := v.Open(passH)
	if err != nil {
		return fmt.Errorf("open passphrase: %w", err)
	}
	if err := os.MkdirAll(cfg.BackupDir, 0o700); err != nil {
		return err
	}
	backupOut := filepath.Join(cfg.BackupDir, "browserrot-host-"+time.Now().UTC().Format("2006-01-02T15-04-05Z")+".age")
	n, err := backupGate(ctx, gp, cfg.StorePath, &sink.Age{}, passBuf, backupOut)
	if err != nil {
		return fmt.Errorf("backup gate failed — refusing to rotate: %w", err)
	}
	fmt.Fprintf(logw, "BACKUP_GATE_OK: %d entr(ies) under %q sealed + verified -> %s\n", n, cfg.StorePath, backupOut)

	// Rotate: over the extension, drive the change-password flow in the open tab. On
	// success the OLD password is now DEAD at the site and newH holds the working secret.
	fmt.Fprintln(logw, "ROTATE: driving the change-password flow over the extension…")
	newH, err := rot.Rotate(ctx, cred, v)
	if errors.Is(err, browserrot.ErrOutcomeUnknown) && newH != nil {
		return outcomeUnknown(ctx, gp, v, cfg.StorePath, cred.Identity, newH, err, logw)
	}
	if err != nil {
		return fmt.Errorf("rotate failed (old secret kept if change did not submit): %w", err)
	}
	fmt.Fprintln(logw, "ROTATE_OK: site confirmed the password change.")

	// STORE IMMEDIATELY — close the lockout window before anything else.
	if err := gp.InsertAt(ctx, v, cfg.StorePath, newH, true); err != nil {
		return fmt.Errorf("STORE FAILED after a successful change — new password ACTIVE at %s but NOT saved to gopass %q: %w", cred.Identity, cfg.StorePath, err)
	}
	fmt.Fprintf(logw, "STORE_OK: new password persisted at gopass %q.\n", cfg.StorePath)

	// Verify: re-login with the new secret (from vault), then re-read from gopass and
	// re-login again to prove the stored bytes are the working secret.
	fmt.Fprintln(logw, "VERIFY: re-login with the new password…")
	if err := rot.Verify(ctx, newH, v); err != nil {
		v.Forget(newH)
		return fmt.Errorf("verify(new) failed but the new password IS stored: %w", err)
	}
	v.Forget(newH)

	rh, err := gp.Show(ctx, v, cfg.StorePath)
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

	fmt.Fprintf(logw, "\nBROWSER_ROT_HOST_OK: %s (backup %s)\n", cred.Identity, backupOut)
	return nil
}

// outcomeUnknown handles a submitted change whose result neither password could prove: the
// site may already accept ONLY the new one. The new secret is kept beside the old entry —
// never over it — and the run stops with instructions for the human. Always returns an error.
func outcomeUnknown(ctx context.Context, gp *sink.Gopass, v *vault.Vault, storePath, identity string, newH *vault.Handle, cause error, logw io.Writer) error {
	pending, err := keepPendingSecret(ctx, gp, v, storePath, newH)
	v.Forget(newH)
	if err != nil {
		return fmt.Errorf("OUTCOME UNKNOWN and the new password could NOT be saved (%v) — check %s now: %w", err, identity, cause)
	}
	fmt.Fprintf(logw, "OUTCOME_UNKNOWN: old kept at gopass %q, new saved at %q.\n", storePath, pending)
	return fmt.Errorf("OUTCOME UNKNOWN: log in to %s with each of gopass %q and %q, keep whichever works at %q: %w", identity, storePath, pending, storePath, cause)
}

// keepPendingSecret stores a new secret whose rotation outcome is unknown at
// "<storePath>.pending", leaving the old entry untouched, and returns that path.
func keepPendingSecret(ctx context.Context, gp *sink.Gopass, v *vault.Vault, storePath string, newH *vault.Handle) (string, error) {
	pending := storePath + ".pending"
	if err := gp.InsertAt(ctx, v, pending, newH, true); err != nil {
		return "", err
	}
	return pending, nil
}

// backupGate is Hard Rule 1 for this host: a verified, sealed backup that CONTAINS the entry
// about to be rotated. The export prefix is the rotated entry's own path (never a literal), so
// whatever INCREDIGO_STORE_PREFIX/INCREDIGO_CREDENTIAL resolve to is what gets sealed; string-
// prefix siblings (e.g. "<path>-old") may ride along, which is harmless. Fails closed — before
// anything is written — if the exact entry is not in the store listing.
func backupGate(ctx context.Context, gp *sink.Gopass, storePath string, sealer sink.Sealer, pass *memguard.LockedBuffer, out string) (int, error) {
	paths, err := gp.ListPaths(ctx, storePath)
	if err != nil {
		return 0, err
	}
	found := false
	for _, p := range paths {
		if p == storePath {
			found = true
			break
		}
	}
	if !found {
		return 0, fmt.Errorf("backup would not contain the rotated entry %q (not in gopass listing)", storePath)
	}
	n, err := rotate.Snapshot(ctx, gp, storePath, sealer, pass, out)
	if err != nil {
		return 0, err
	}
	if n < 1 {
		os.Remove(out)
		return 0, fmt.Errorf("backup sealed 0 entries under %q", storePath)
	}
	return n, nil
}
