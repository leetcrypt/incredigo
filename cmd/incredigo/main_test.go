package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"incredigo/internal/discover"
)

// runCLI drives the real root command with args, capturing os.Stdout/os.Stderr.
// It swaps the process stdio around Execute so the CLI's direct fmt.Fprintln(os.Stdout,…)
// writes are captured; goroutines drain the pipes to avoid blocking on large output.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	outR, outW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	errR, errW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	var ob, eb bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(&ob, outR) }()
	go func() { defer wg.Done(); io.Copy(&eb, errR) }()

	// The file scanner's --path targets are process-global; reset so a prior test's
	// (now-deleted) fixture path can't leak into this invocation.
	discover.ClearPaths()
	root := newRootCmd()
	root.SetArgs(args)
	err = root.Execute()

	os.Stdout, os.Stderr = origOut, origErr
	outW.Close()
	errW.Close()
	wg.Wait()
	outR.Close()
	errR.Close()
	return ob.String(), eb.String(), err
}

// fakeGopassOnPath installs a stub `gopass` as the first entry on PATH and points it
// at a fresh file-backed store, so CLI commands that build sink.Gopass{} (using the
// default "gopass" binary) never touch the user's real store. failShow makes `gopass
// show` exit non-zero, used to force a backup-gate failure. Returns the store dir.
func fakeGopassOnPath(t *testing.T, failShow bool, seed map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "gopass")
	showBody := `cat "$store/$3"`
	if failShow {
		showBody = `echo "show failed" >&2; exit 1`
	}
	script := `#!/usr/bin/env bash
store="$FAKE_GOPASS_STORE"
case "$1" in
  ls) (cd "$store" 2>/dev/null && find . -type f | sed 's#^\./##' | sort) ;;
  show) ` + showBody + ` ;;
  insert)
    shift; path=""
    for a in "$@"; do case "$a" in --multiline=false|-f) ;; *) path="$a";; esac; done
    mkdir -p "$store/$(dirname "$path")"; cat > "$store/$path" ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	for p, s := range seed {
		full := filepath.Join(store, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("FAKE_GOPASS_STORE", store)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return store
}

// fixtureDir writes files as credential material and returns the dir, for discovery
// via `--path <dir> --source file`. Isolating discovery to the file scanner keeps the
// host's real aws/env/ssh secrets out of the test.
func fixtureDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// isolateHome points HOME at a throwaway dir so no host dotfiles are ever scanned or
// written, and the rotate default backup dir (~/.incredigo) lands under the temp dir.
func isolateHome(t *testing.T) { t.Setenv("HOME", t.TempDir()) }

func TestScanFindsFixtureViaPath(t *testing.T) {
	isolateHome(t)
	dir := fixtureDir(t, map[string]string{"deploy.key": "unique-scan-secret-value"})
	out, serr, err := runCLI(t, "scan", "--source", "file", "--path", dir)
	if err != nil {
		t.Fatalf("scan: %v (stderr=%s)", err, serr)
	}
	if !strings.Contains(out, "deploy.key") {
		t.Errorf("scan output missing fixture identity:\n%s", out)
	}
	if strings.Contains(out, "unique-scan-secret-value") {
		t.Errorf("scan leaked the secret value:\n%s", out)
	}
	if !strings.Contains(serr, "credential(s) found") {
		t.Errorf("scan summary missing:\n%s", serr)
	}
}

func TestStatusHappyPath(t *testing.T) {
	isolateHome(t)
	dir := fixtureDir(t, map[string]string{"token.txt": "status-secret"})
	out, _, err := runCLI(t, "status", "--source", "file", "--path", dir)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "STATE") || !strings.Contains(out, "token.txt") {
		t.Errorf("status output unexpected:\n%s", out)
	}
}

func TestWorklistHappyPath(t *testing.T) {
	isolateHome(t)
	dir := fixtureDir(t, map[string]string{"aws.creds": "worklist-secret"})
	out, _, err := runCLI(t, "worklist", "--source", "file", "--path", dir)
	if err != nil {
		t.Fatalf("worklist: %v", err)
	}
	if strings.Contains(out, "worklist-secret") {
		t.Errorf("worklist leaked a secret:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "rotat") {
		t.Errorf("worklist output does not look like a worklist:\n%s", out)
	}
}

func TestMigrateDedupeAndForce(t *testing.T) {
	isolateHome(t)
	store := fakeGopassOnPath(t, false, nil)
	dir := fixtureDir(t, map[string]string{"svc.token": "migrate-secret"})

	// First migrate: stores the credential.
	out, _, err := runCLI(t, "migrate", "--source", "file", "--path", dir, "--prefix", "imported/")
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !strings.Contains(out, "store imported/file/") {
		t.Errorf("first migrate did not store:\n%s", out)
	}
	// The secret must be in the store (streamed via stdin, never argv).
	got := readAnyUnder(t, filepath.Join(store, "imported/file"))
	if got != "migrate-secret" {
		t.Errorf("stored value = %q, want migrate-secret", got)
	}

	// Second migrate with --dedupe: the same entry is skipped, not overwritten.
	out2, _, err := runCLI(t, "migrate", "--source", "file", "--path", dir, "--prefix", "imported/", "--dedupe")
	if err != nil {
		t.Fatalf("migrate --dedupe: %v", err)
	}
	if !strings.Contains(out2, "(exists)") {
		t.Errorf("--dedupe did not skip an existing entry:\n%s", out2)
	}
}

func TestExportImportRoundTripCLI(t *testing.T) {
	isolateHome(t)
	t.Setenv("INCREDIGO_PASSPHRASE", "round-trip-pass")
	seed := map[string]string{
		"imported/aws/default": "AKIA/roundtrip+secret",
		"imported/env/api":     "tok-末-value",
	}
	store := fakeGopassOnPath(t, false, seed)
	bundle := filepath.Join(t.TempDir(), "backup.age")

	// export from store A
	_, serr, err := runCLI(t, "export", "--out", bundle, "--prefix", "imported/")
	if err != nil {
		t.Fatalf("export: %v (stderr=%s)", err, serr)
	}
	if fi, e := os.Stat(bundle); e != nil || fi.Size() == 0 {
		t.Fatalf("bundle missing/empty: %v", e)
	}
	if !strings.Contains(serr, "sealed 2") {
		t.Errorf("export summary unexpected:\n%s", serr)
	}
	// The bundle must not contain the plaintext secret.
	if b, _ := os.ReadFile(bundle); bytes.Contains(b, []byte("AKIA/roundtrip+secret")) {
		t.Fatal("sealed bundle leaked plaintext")
	}

	// import into a fresh empty store B
	storeB := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", storeB)
	_, serr, err = runCLI(t, "import", "--in", bundle, "--force")
	if err != nil {
		t.Fatalf("import: %v (stderr=%s)", err, serr)
	}
	for path, want := range seed {
		got, e := os.ReadFile(filepath.Join(storeB, path))
		if e != nil {
			t.Fatalf("restored %s missing: %v", path, e)
		}
		if string(got) != want {
			t.Errorf("%s restored %q, want %q", path, got, want)
		}
	}
	_ = store
}

func TestExportRefusesToOverwrite(t *testing.T) {
	isolateHome(t)
	t.Setenv("INCREDIGO_PASSPHRASE", "pw")
	fakeGopassOnPath(t, false, map[string]string{"imported/env/api": "v"})
	bundle := filepath.Join(t.TempDir(), "exists.age")
	if err := os.WriteFile(bundle, []byte("preexisting"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "export", "--out", bundle, "--prefix", "imported/"); err == nil {
		t.Fatal("export overwrote an existing bundle")
	}
}

// --- Gate refusals (the safety-critical CLI contracts) ---

func TestRotateExecuteRefusedWithoutEnv(t *testing.T) {
	isolateHome(t)
	os.Unsetenv("INCREDIGO_ALLOW_EXECUTE")
	fakeGopassOnPath(t, false, map[string]string{"imported/env/api": "v"})
	_, _, err := runCLI(t, "rotate", "--execute", "--prefix", "imported/")
	if err == nil {
		t.Fatal("rotate --execute ran without INCREDIGO_ALLOW_EXECUTE=1")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExportMissingPassphrase(t *testing.T) {
	isolateHome(t)
	t.Setenv("INCREDIGO_PASSPHRASE", "") // set-but-empty is an explicit error
	fakeGopassOnPath(t, false, map[string]string{"imported/env/api": "v"})
	bundle := filepath.Join(t.TempDir(), "b.age")
	_, _, err := runCLI(t, "export", "--out", bundle, "--prefix", "imported/")
	if err == nil {
		t.Fatal("export proceeded with an empty passphrase")
	}
	if !strings.Contains(err.Error(), "PASSPHRASE") {
		t.Errorf("unexpected error: %v", err)
	}
	// export opens the output file before reading the passphrase, so an empty file
	// may remain — but it must never contain sealed (or any) content.
	if fi, e := os.Stat(bundle); e == nil && fi.Size() != 0 {
		t.Errorf("bundle has %d bytes despite the passphrase error", fi.Size())
	}
}

// TestRotateExecuteBackupGateAborts proves the backup gate blocks execute BEFORE any
// driver runs: with authorization present but `gopass show` failing, Snapshot fails
// and the command aborts with a backup-gate error — no rotation is attempted.
func TestRotateExecuteBackupGateAborts(t *testing.T) {
	isolateHome(t)
	t.Setenv("INCREDIGO_ALLOW_EXECUTE", "1")
	t.Setenv("INCREDIGO_PASSPHRASE", "pw")
	// ls returns a path so ExportTo tries to read it, but show fails → Snapshot fails.
	fakeGopassOnPath(t, true, map[string]string{"imported/env/api": "v"})
	out, _, err := runCLI(t, "rotate", "--execute", "--prefix", "imported/")
	if err == nil {
		t.Fatal("rotate --execute proceeded despite a failing backup gate")
	}
	if !strings.Contains(err.Error(), "backup gate failed") {
		t.Errorf("expected a backup-gate error, got: %v", err)
	}
	// The rotation results table must never have been printed.
	if strings.Contains(out, "ROTATED") || strings.Contains(out, "DRIVER") {
		t.Errorf("rotation ran despite the backup gate failing:\n%s", out)
	}
}

func TestUnknownSealerRejected(t *testing.T) {
	isolateHome(t)
	t.Setenv("INCREDIGO_PASSPHRASE", "pw")
	fakeGopassOnPath(t, false, map[string]string{"imported/env/api": "v"})
	bundle := filepath.Join(t.TempDir(), "b.age")
	_, _, err := runCLI(t, "export", "--out", bundle, "--prefix", "imported/", "--sealer", "rot13")
	if err == nil || !strings.Contains(err.Error(), "unknown sealer") {
		t.Fatalf("expected unknown-sealer error, got: %v", err)
	}
}

// --- Objective 1: rotate --stale (policy-driven selection) ---

// TestRotateStale proves `rotate --stale --dry-run` plans/walks ONLY the
// credentials the expiry policy marks Warn/Stale: a fresh fixture file (mtime now,
// OK) is excluded while a backdated one (>90d, Stale) is walked through the noop
// spine. No service is touched and nothing is persisted (dry-run).
func TestRotateStale(t *testing.T) {
	isolateHome(t)
	t.Setenv("INCREDIGO_PASSPHRASE", "stale-pass")
	// The mandatory backup gate needs a working gopass; empty store is fine (the
	// plan/dry-run set comes from the file scanner, not gopass).
	fakeGopassOnPath(t, false, nil)

	dir := fixtureDir(t, map[string]string{
		"fresh.token": "fresh-secret", // mtime = now -> OK -> excluded
		"old.token":   "old-secret",   // backdated below -> STALE -> included
	})
	// Backdate old.token well past the 90d stale threshold.
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "old.token"), old, old); err != nil {
		t.Fatal(err)
	}

	out, serr, err := runCLI(t, "rotate", "--stale", "--dry-run", "--source", "file", "--path", dir)
	// Stale credentials remain to act on -> the exit-code contract returns code 2.
	assertExitCode(t, err, 2)

	if !strings.Contains(out, "old.token") {
		t.Errorf("stale credential missing from --stale plan:\n%s", out)
	}
	if strings.Contains(out, "fresh.token") {
		t.Errorf("--stale planned an OK (fresh) credential:\n%s\nstderr=%s", out, serr)
	}
	if strings.Contains(out, "fresh-secret") || strings.Contains(out, "old-secret") {
		t.Errorf("rotate leaked a secret value:\n%s", out)
	}
	// Dry-run must walk exactly the one stale credential.
	if !strings.Contains(serr, "1 credential(s) walked") {
		t.Errorf("dry-run did not walk exactly the stale credential:\n%s", serr)
	}
}

// --- Objective 2: --json + exit codes ---

// TestStatusJSON proves `status --json` emits valid, secret-free JSON and honors
// the exit-code contract: exit 0 when every credential is OK, non-zero (2) when at
// least one is Warn/Stale.
func TestStatusJSON(t *testing.T) {
	// Case 1: a stale credential -> valid JSON marking it STALE + exit code 2.
	t.Run("stale-nonzero", func(t *testing.T) {
		isolateHome(t)
		dir := fixtureDir(t, map[string]string{"aging.token": "json-secret"})
		old := time.Now().Add(-200 * 24 * time.Hour)
		if err := os.Chtimes(filepath.Join(dir, "aging.token"), old, old); err != nil {
			t.Fatal(err)
		}
		out, _, err := runCLI(t, "status", "--json", "--source", "file", "--path", dir)
		assertExitCode(t, err, 2)

		var rows []struct {
			State    string `json:"state"`
			AgeDays  int    `json:"age_days"`
			Source   string `json:"source"`
			Identity string `json:"identity"`
		}
		if e := json.Unmarshal([]byte(out), &rows); e != nil {
			t.Fatalf("status --json did not emit valid JSON: %v\n%s", e, out)
		}
		if len(rows) != 1 || rows[0].Identity != "aging.token" || rows[0].State != "STALE" {
			t.Fatalf("unexpected JSON rows: %+v", rows)
		}
		if strings.Contains(out, "json-secret") {
			t.Errorf("status --json leaked a secret:\n%s", out)
		}
	})

	// Case 2: only fresh credentials -> exit 0 (clean, nothing to do).
	t.Run("clean-zero", func(t *testing.T) {
		isolateHome(t)
		dir := fixtureDir(t, map[string]string{"fresh.token": "ok-secret"})
		out, _, err := runCLI(t, "status", "--json", "--source", "file", "--path", dir)
		if err != nil {
			t.Fatalf("status --json (clean) returned non-nil err/exit: %v", err)
		}
		var rows []map[string]any
		if e := json.Unmarshal([]byte(out), &rows); e != nil {
			t.Fatalf("status --json did not emit valid JSON: %v\n%s", e, out)
		}
		if len(rows) != 1 || rows[0]["state"] != "OK" {
			t.Fatalf("expected one OK row, got: %+v", rows)
		}
	})
}

// --- Objective 3: rotate emits the manual/unrotated remainder as a worklist ---

// TestRotateEmitsWorklist proves a headless `rotate --dry-run` run, after handling the
// automatable credentials (walked through the noop spine), writes the manual/unrotated
// remainder to rotate-worklist.md under the incredigo state dir. The fixture mixes an
// automatable credential (an SSH key — the `ssh` driver claims Source "ssh") with a
// manual one (a file-scanned token — no driver). The emitted worklist must list only
// the manual credential, contain no secrets, and the command must exit sanely.
func TestRotateEmitsWorklist(t *testing.T) {
	isolateHome(t)
	home := os.Getenv("HOME")
	t.Setenv("INCREDIGO_PASSPHRASE", "worklist-pass")
	// The mandatory backup gate needs a working gopass; an empty store is fine (the
	// plan/dry-run set comes from the scanners, not gopass).
	fakeGopassOnPath(t, false, nil)

	// Automatable: an SSH private key in ~/.ssh -> Source "ssh" -> driver exists.
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const sshSecret = "-----BEGIN OPENSSH PRIVATE KEY-----\nssh-key-secret-body\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte(sshSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	// Manual: a plain token file -> Source "file" -> no driver.
	const fileSecret = "manual-token-secret-value"
	dir := fixtureDir(t, map[string]string{"service.token": fileSecret})

	out, serr, err := runCLI(t, "rotate", "--dry-run", "--source", "ssh,file", "--path", dir)
	// Credentials remain to act on -> the exit-code contract returns code 2.
	assertExitCode(t, err, 2)

	// The worklist landed at the default path under the state dir.
	wlPath := filepath.Join(home, ".incredigo", "rotate-worklist.md")
	b, rerr := os.ReadFile(wlPath)
	if rerr != nil {
		t.Fatalf("rotate did not write %s: %v\nstderr=%s", wlPath, rerr, serr)
	}
	wl := string(b)

	// Lists the manual credential...
	if !strings.Contains(wl, "service.token") {
		t.Errorf("worklist missing the manual credential:\n%s", wl)
	}
	// ...and NOT the automatable one (it was handled).
	if strings.Contains(wl, "id_ed25519") {
		t.Errorf("worklist listed the automatable ssh credential; remainder should exclude it:\n%s", wl)
	}
	// Never any secret material.
	for _, secret := range []string{fileSecret, "ssh-key-secret-body", "PRIVATE KEY"} {
		if strings.Contains(wl, secret) {
			t.Errorf("worklist leaked a secret (%q):\n%s", secret, wl)
		}
	}
	// The plan output itself must also never leak a secret.
	if strings.Contains(out, fileSecret) || strings.Contains(out, "ssh-key-secret-body") {
		t.Errorf("rotate output leaked a secret:\n%s", out)
	}
	// The run announced the emission.
	if !strings.Contains(serr, "manual-rotation worklist") {
		t.Errorf("rotate did not announce the worklist emission:\n%s", serr)
	}
}

// assertExitCode fails unless err carries the expected process exit code via the
// exitError contract (a nil err means exit 0).
func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()
	if want == 0 {
		if err != nil {
			t.Fatalf("expected exit 0, got err: %v", err)
		}
		return
	}
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected an exitError with code %d, got: %v", want, err)
	}
	if ee.code != want {
		t.Fatalf("exit code = %d, want %d", ee.code, want)
	}
}

// readAnyUnder returns the contents of the first regular file under root (tests seed
// exactly one), or fails.
func readAnyUnder(t *testing.T, root string) string {
	t.Helper()
	var found string
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && found == "" {
			b, _ := os.ReadFile(p)
			found = string(b)
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no file found under %s", root)
	}
	return found
}
