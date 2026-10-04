package sink

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"

	"github.com/awnumar/memguard"
)

// frameRecord builds a single well-formed bundle record: path then one secret chunk
// then the secret end marker. No trailing stream sentinel (callers add it).
func frameRecord(path, secret string) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint16(len(path)))
	b.WriteString(path)
	binary.Write(&b, binary.BigEndian, uint32(len(secret)))
	b.WriteString(secret)
	binary.Write(&b, binary.BigEndian, uint32(0)) // secret end
	return b.Bytes()
}

func streamSentinel() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint16(0))
	return b.Bytes()
}

// TestCountBundleRecordsZeroRecord proves an empty bundle (just the sentinel) counts
// as zero records without error.
func TestCountBundleRecordsZeroRecord(t *testing.T) {
	n, err := CountBundleRecords(bytes.NewReader(streamSentinel()))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("zero-record bundle counted %d", n)
	}
}

// TestCountBundleRecordsCleanEOF proves a stream that ends after complete records
// (no explicit sentinel) still counts correctly — ImportFrom tolerates this, so the
// counter must agree.
func TestCountBundleRecordsCleanEOF(t *testing.T) {
	var b bytes.Buffer
	b.Write(frameRecord("imported/aws/default", "AKIA-secret"))
	b.Write(frameRecord("imported/env/api", "token-value"))
	// no sentinel — clean EOF
	n, err := CountBundleRecords(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("counted %d records, want 2", n)
	}
}

// TestCountBundleRecordsTruncated proves a stream truncated mid-record is reported
// as an error, not silently under-counted — the backup gate must not accept a short
// backup as complete.
func TestCountBundleRecordsTruncated(t *testing.T) {
	full := frameRecord("imported/aws/default", "AKIA-secret-value")
	cases := map[string]int{
		"mid-path":      3,              // inside the path bytes
		"mid-chunk-len": 2 + 20 + 2,     // partway through the chunk length prefix
		"mid-secret":    2 + 20 + 4 + 3, // inside the secret chunk body
	}
	for name, cut := range cases {
		t.Run(name, func(t *testing.T) {
			if cut >= len(full) {
				t.Skipf("cut %d beyond record length %d", cut, len(full))
			}
			_, err := CountBundleRecords(bytes.NewReader(full[:cut]))
			if err == nil {
				t.Fatal("truncated bundle counted without error")
			}
		})
	}
}

// TestWritePathOversized proves a path longer than the uint16 frame field is
// rejected rather than silently wrapping to a short length (which would corrupt the
// stream and hide entries from the backup).
func TestWritePathOversized(t *testing.T) {
	var w bytes.Buffer
	long := strings.Repeat("a", 0x10000) // 65536 > 0xffff
	if err := writePath(&w, long); err == nil {
		t.Fatal("oversized path accepted")
	}
	if w.Len() != 0 {
		t.Fatalf("oversized path wrote %d bytes before failing", w.Len())
	}
}

// TestExportImportSecretNeverInArgv proves Hard Rule #3 at the wrapper boundary: a
// secret streamed through Insert/Import never appears in the child process argv. The
// fake gopass records its full argv; we assert the secret is absent from it.
func TestExportImportSecretNeverInArgv(t *testing.T) {
	secret := "s3cr3t-must-not-appear-in-argv"
	argvLog := filepath.Join(t.TempDir(), "argv.log")
	bin := writeArgvLoggingGopass(t, argvLog)
	gp := &Gopass{Bin: bin}
	ctx := context.Background()

	store := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", store)

	// Build a one-record bundle and import it (spawns `gopass insert`).
	var bundle bytes.Buffer
	bundle.Write(frameRecord("imported/env/api", secret))
	bundle.Write(streamSentinel())
	if _, err := gp.ImportFrom(ctx, &bundle, true); err != nil {
		t.Fatalf("import: %v", err)
	}

	logged, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("read argv log: %v", err)
	}
	if strings.Contains(string(logged), secret) {
		t.Fatalf("secret leaked into gopass argv: %s", logged)
	}
	// Sanity: the secret did land in the store (via stdin, not argv).
	got, err := os.ReadFile(filepath.Join(store, "imported/env/api"))
	if err != nil {
		t.Fatalf("stored entry missing: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("stored %q, want %q", got, secret)
	}
}

// TestGopassShowAndExists exercises the Show (into vault) and Exists wrapper paths
// against the fake binary.
func TestGopassShowAndExists(t *testing.T) {
	bin := writeFakeGopass(t)
	gp := &Gopass{Bin: bin}
	ctx := context.Background()

	store := t.TempDir()
	seed(t, store, map[string]string{"imported/env/api": "token-xyz\n"})
	t.Setenv("FAKE_GOPASS_STORE", store)

	v := vault.New()
	defer v.Purge()
	h, err := gp.Show(ctx, v, "imported/env/api")
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	buf, err := v.Open(h)
	if err != nil {
		t.Fatalf("vault open: %v", err)
	}
	if got := string(buf.Bytes()); got != "token-xyz" { // trailing newline trimmed
		t.Fatalf("show returned %q, want %q", got, "token-xyz")
	}

	if !gp.Exists(ctx, "imported/env/api") {
		t.Error("Exists reported false for a present entry")
	}
	if gp.Exists(ctx, "imported/nope") {
		t.Error("Exists reported true for an absent entry")
	}
}

// TestGopassInsert proves the rotation write-back paths (Insert and InsertAt) stream
// a vaulted secret into gopass, that Insert forgets the handle afterwards, and that
// InsertAt writes to an exact path without forgetting.
func TestGopassInsert(t *testing.T) {
	bin := writeFakeGopass(t)
	gp := &Gopass{Bin: bin}
	ctx := context.Background()

	store := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", store)

	v := vault.New()
	defer v.Purge()

	// Insert derives the path from Source+Identity via StorePath.
	c := discover.Credential{Source: "env", Identity: "API_TOKEN", Secret: v.Store([]byte("inserted-secret"))}
	if err := gp.Insert(ctx, v, c, true); err != nil {
		t.Fatalf("insert: %v", err)
	}
	want := filepath.Join(store, gp.StorePath(c))
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("Insert did not write %s: %v", gp.StorePath(c), err)
	}
	if string(got) != "inserted-secret" {
		t.Fatalf("Insert stored %q, want %q", got, "inserted-secret")
	}
	// Insert must forget the handle (secret is now in gopass).
	if _, err := v.Open(c.Secret); err == nil {
		t.Error("Insert did not forget the handle")
	}

	// InsertAt writes a fresh handle to an exact path and keeps it usable.
	h := v.Store([]byte("rotated-value"))
	if err := gp.InsertAt(ctx, v, "imported/env/rotated", h, true); err != nil {
		t.Fatalf("insertAt: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(store, "imported/env/rotated"))
	if err != nil {
		t.Fatalf("InsertAt did not write: %v", err)
	}
	if string(got) != "rotated-value" {
		t.Fatalf("InsertAt stored %q, want %q", got, "rotated-value")
	}
	if _, err := v.Open(h); err != nil {
		t.Error("InsertAt should not forget the handle (caller may re-read)")
	}
}

// TestGopassAvailable proves Available reflects whether the binary resolves on PATH.
func TestGopassAvailable(t *testing.T) {
	if (&Gopass{Bin: writeFakeGopass(t)}).Available() != true {
		t.Error("Available false for an existing binary")
	}
	if (&Gopass{Bin: "definitely-not-a-real-binary-xyz"}).Available() != false {
		t.Error("Available true for a missing binary")
	}
}

// TestExportSealOpenPipeline proves the whole backup path the rotation gate depends
// on: export a store → seal it (age) → open it → the record count and secrets match.
// This is the completeness+authenticity contract of a verified backup end-to-end.
func TestExportSealOpenPipeline(t *testing.T) {
	bin := writeFakeGopass(t)
	gp := &Gopass{Bin: bin}
	ctx := context.Background()

	src := t.TempDir()
	entries := map[string]string{
		"imported/aws/default": "AKIA/secret+with=specials",
		"imported/env/api":     "unicode-末-\U0001f511",
	}
	seed(t, src, entries)
	t.Setenv("FAKE_GOPASS_STORE", src)

	// export → plaintext bundle
	var plain bytes.Buffer
	n, err := gp.ExportTo(ctx, &plain, "imported/")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if n != 2 {
		t.Fatalf("exported %d, want 2", n)
	}

	// seal → open
	sealer := &Age{WorkFactor: 10}
	pass := memguard.NewBufferFromBytes([]byte("backup-pass"))
	var sealed bytes.Buffer
	if err := sealer.Seal(ctx, bytes.NewReader(plain.Bytes()), &sealed, pass); err != nil {
		t.Fatalf("seal: %v", err)
	}
	var opened bytes.Buffer
	if err := sealer.Open(ctx, &sealed, &opened, memguard.NewBufferFromBytes([]byte("backup-pass"))); err != nil {
		t.Fatalf("open: %v", err)
	}

	// completeness: count matches
	cnt, err := CountBundleRecords(bytes.NewReader(opened.Bytes()))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if cnt != 2 {
		t.Fatalf("opened bundle has %d records, want 2", cnt)
	}

	// authenticity: import into a fresh store restores the exact secrets
	dst := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", dst)
	if _, err := gp.ImportFrom(ctx, bytes.NewReader(opened.Bytes()), true); err != nil {
		t.Fatalf("import: %v", err)
	}
	for path, exp := range entries {
		got, err := os.ReadFile(filepath.Join(dst, path))
		if err != nil {
			t.Fatalf("restored %s: %v", path, err)
		}
		if string(got) != exp {
			t.Errorf("%s: restored %q want %q", path, got, exp)
		}
	}
}

// TestExportFailsOnGopassShowError proves ExportTo surfaces a `gopass show` failure
// as an error rather than silently emitting a short (incomplete) backup — the backup
// gate must never treat a partial export as a complete one.
func TestExportFailsOnGopassShowError(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gopass")
	// ls lists one path; show always fails.
	script := `#!/usr/bin/env bash
case "$1" in
  ls) echo "imported/env/api" ;;
  show) echo "boom" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	gp := &Gopass{Bin: bin}
	var buf bytes.Buffer
	if _, err := gp.ExportTo(context.Background(), &buf, "imported/"); err == nil {
		t.Fatal("ExportTo ignored a gopass show failure")
	}
}

// TestImportFailsOnInsertError proves ImportFrom surfaces a `gopass insert` failure
// rather than silently dropping an entry on restore.
func TestImportFailsOnInsertError(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gopass")
	script := `#!/usr/bin/env bash
case "$1" in
  insert) cat >/dev/null; echo "denied" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	gp := &Gopass{Bin: bin}

	var bundle bytes.Buffer
	bundle.Write(frameRecord("imported/env/api", "value"))
	bundle.Write(streamSentinel())
	if _, err := gp.ImportFrom(context.Background(), &bundle, true); err == nil {
		t.Fatal("ImportFrom ignored a gopass insert failure")
	}
}

// writeArgvLoggingGopass is like writeFakeGopass but appends the full argv of every
// invocation to logPath, so a test can assert the secret never rode in argv.
func writeArgvLoggingGopass(t *testing.T, logPath string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gopass")
	script := `#!/usr/bin/env bash
echo "$@" >> "` + logPath + `"
store="$FAKE_GOPASS_STORE"
case "$1" in
  ls) (cd "$store" 2>/dev/null && find . -type f | sed 's#^\./##' | sort) ;;
  show) cat "$store/$3" ;;
  insert)
    shift; path=""
    for a in "$@"; do case "$a" in --multiline=false|-f) ;; *) path="$a";; esac; done
    mkdir -p "$store/$(dirname "$path")"; cat > "$store/$path" ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}
