package sink

// Targeted coverage for the fail-closed error paths the round-trip/tamper tests
// (sealer_test.go) and the happy-path wrapper tests (bundle_test.go,
// framing_test.go) don't reach: subprocess start failures, truncated/short reads,
// and mid-stream writer failures. These matter because a backup pipeline that
// silently swallows a write/read error would produce (or restore) a short,
// incomplete bundle instead of failing loudly — exactly what Hard Rule #1 (backup
// before rotate) depends on not happening.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// failingWriter accepts `allowed` successful Write calls, then errors on every
// call after that — used to force the write-failure branches of the framing and
// sealer code without needing a real broken pipe.
type failingWriter struct {
	allowed int
	calls   int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > w.allowed {
		return 0, fmt.Errorf("failingWriter: write %d failed (limit %d)", w.calls, w.allowed)
	}
	return len(p), nil
}

// TestSealerHelperDefaults exercises the pure default-vs-custom branches of the
// bin()/workFactor() helpers directly, without paying for a subprocess or a real
// scrypt derivation.
func TestSealerHelperDefaults(t *testing.T) {
	if got := (&Gopass{}).bin(); got != "gopass" {
		t.Errorf("Gopass.bin() default = %q, want gopass", got)
	}
	if got := (&Gopass{Bin: "custom-gopass"}).bin(); got != "custom-gopass" {
		t.Errorf("Gopass.bin() custom = %q, want custom-gopass", got)
	}
	if got := (&HMACSealer{}).bin(); got != "openssl" {
		t.Errorf("HMACSealer.bin() default = %q, want openssl", got)
	}
	if got := (&HMACSealer{Bin: "custom-openssl"}).bin(); got != "custom-openssl" {
		t.Errorf("HMACSealer.bin() custom = %q, want custom-openssl", got)
	}
	if got := (&Age{}).workFactor(); got != 18 {
		t.Errorf("Age.workFactor() default = %d, want 18", got)
	}
	if got := (&Age{WorkFactor: 5}).workFactor(); got != 5 {
		t.Errorf("Age.workFactor() custom = %d, want 5", got)
	}
}

// TestHMACSealWriteErrors proves the HMAC sealer surfaces a failure writing either
// the MAC header or the ciphertext body, rather than silently emitting a partial
// (unauthenticated-looking) bundle.
func TestHMACSealWriteErrors(t *testing.T) {
	ctx := context.Background()
	sealer := &HMACSealer{Iter: 1000}

	t.Run("mac-write-fails", func(t *testing.T) {
		w := &failingWriter{allowed: 0}
		if err := sealer.Seal(ctx, bytes.NewReader([]byte("x")), w, newPass("pw")); err == nil {
			t.Fatal("expected error when the MAC header write fails")
		}
	})
	t.Run("ciphertext-write-fails", func(t *testing.T) {
		w := &failingWriter{allowed: 1} // MAC header succeeds, ciphertext body fails
		if err := sealer.Seal(ctx, bytes.NewReader([]byte("x")), w, newPass("pw")); err == nil {
			t.Fatal("expected error when the ciphertext body write fails")
		}
	})
}

// TestWritePathBodyWriteFails proves writePath surfaces a failure writing the path
// bytes themselves, not just a failure writing the length prefix (already covered
// by TestWritePathOversized).
func TestWritePathBodyWriteFails(t *testing.T) {
	w := &failingWriter{allowed: 1} // length prefix succeeds, path body fails
	if err := writePath(w, "imported/env/api"); err == nil {
		t.Fatal("expected error when the path body write fails")
	}
}

// TestStreamSecretBadBinary proves streamSecret surfaces a subprocess start
// failure (missing gopass binary) rather than silently emitting an empty chunk.
func TestStreamSecretBadBinary(t *testing.T) {
	g := &Gopass{Bin: "/nonexistent/gopass-xyz"}
	var buf bytes.Buffer
	if err := g.streamSecret(context.Background(), &buf, "imported/env/api"); err == nil {
		t.Fatal("expected error starting a nonexistent gopass binary")
	}
}

// TestStreamSecretWriterFails proves streamSecret surfaces a failure writing the
// chunk-length prefix and the chunk body, at the point each is written.
func TestStreamSecretWriterFails(t *testing.T) {
	bin := writeFakeGopass(t)
	store := t.TempDir()
	seed(t, store, map[string]string{"imported/env/api": "secret-value"})
	t.Setenv("FAKE_GOPASS_STORE", store)
	g := &Gopass{Bin: bin}

	t.Run("chunk-len-write-fails", func(t *testing.T) {
		w := &failingWriter{allowed: 0}
		if err := g.streamSecret(context.Background(), w, "imported/env/api"); err == nil {
			t.Fatal("expected error when the chunk-length write fails")
		}
	})
	t.Run("chunk-body-write-fails", func(t *testing.T) {
		w := &failingWriter{allowed: 1} // chunk length succeeds, chunk body fails
		if err := g.streamSecret(context.Background(), w, "imported/env/api"); err == nil {
			t.Fatal("expected error when the chunk-body write fails")
		}
	})
}

// TestStreamSecretEndMarkerWriteFails proves streamSecret surfaces a failure
// writing the zero-length end-of-secret marker (exercised in isolation via an
// empty secret, so the marker write is the very first write attempted).
func TestStreamSecretEndMarkerWriteFails(t *testing.T) {
	bin := writeFakeGopass(t)
	store := t.TempDir()
	seed(t, store, map[string]string{"imported/env/empty": ""})
	t.Setenv("FAKE_GOPASS_STORE", store)
	g := &Gopass{Bin: bin}

	w := &failingWriter{allowed: 0}
	if err := g.streamSecret(context.Background(), w, "imported/env/empty"); err == nil {
		t.Fatal("expected error when the end-marker write fails")
	}
}

// TestExportToWritePathFails proves ExportTo surfaces a writer failure while
// framing a path, rather than continuing on to stream a headerless secret.
func TestExportToWritePathFails(t *testing.T) {
	bin := writeFakeGopass(t)
	store := t.TempDir()
	seed(t, store, map[string]string{"imported/env/api": "v"})
	t.Setenv("FAKE_GOPASS_STORE", store)
	g := &Gopass{Bin: bin}

	w := &failingWriter{allowed: 0}
	if _, err := g.ExportTo(context.Background(), w, "imported/"); err == nil {
		t.Fatal("expected ExportTo to surface a path-write failure")
	}
}

// TestExportToSentinelWriteFails proves ExportTo surfaces a failure writing the
// end-of-stream sentinel, even for an otherwise-empty export (zero matching
// entries) — a swallowed error here would look identical to a legitimately empty
// backup.
func TestExportToSentinelWriteFails(t *testing.T) {
	bin := writeFakeGopass(t)
	store := t.TempDir() // no entries
	t.Setenv("FAKE_GOPASS_STORE", store)
	g := &Gopass{Bin: bin}

	w := &failingWriter{allowed: 0}
	if _, err := g.ExportTo(context.Background(), w, "imported/"); err == nil {
		t.Fatal("expected ExportTo to surface a sentinel-write failure")
	}
}

// TestImportFromTruncatedPathLen proves ImportFrom distinguishes a clean EOF
// (tolerated, see TestCountBundleRecordsCleanEOF-equivalent behaviour) from a
// stream that dies mid-way through the two-byte path-length prefix — the latter
// must be a hard error, not a silently short import.
func TestImportFromTruncatedPathLen(t *testing.T) {
	g := &Gopass{}
	if _, err := g.ImportFrom(context.Background(), bytes.NewReader([]byte{0x01}), true); err == nil {
		t.Fatal("expected error on a path-length prefix truncated mid-read")
	}
}

// TestImportFromTruncatedPathBody proves ImportFrom errors when the stream ends
// before the number of path bytes promised by the length prefix.
func TestImportFromTruncatedPathBody(t *testing.T) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint16(10))
	b.WriteString("abc") // promised 10 bytes, only 3 present
	g := &Gopass{}
	if _, err := g.ImportFrom(context.Background(), &b, true); err == nil {
		t.Fatal("expected error on a path body truncated mid-read")
	}
}

// TestCopySecretTruncatedChunkLen and TestCopySecretTruncatedChunkBody prove
// copySecret errors on a stream that dies inside the chunk framing rather than
// silently inserting a truncated secret into gopass.
func TestCopySecretTruncatedChunkLen(t *testing.T) {
	var dst bytes.Buffer
	if err := copySecret(&dst, bytes.NewReader([]byte{0x01})); err == nil {
		t.Fatal("expected error on a chunk-length prefix truncated mid-read")
	}
}

func TestCopySecretTruncatedChunkBody(t *testing.T) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(10))
	b.WriteString("abc") // promised 10 bytes, only 3 present
	var dst bytes.Buffer
	if err := copySecret(&dst, &b); err == nil {
		t.Fatal("expected error on a chunk body truncated mid-read")
	}
}

// TestCopySecretDestWriteFails proves copySecret surfaces a failure writing to
// the destination (gopass stdin) rather than silently dropping bytes.
func TestCopySecretDestWriteFails(t *testing.T) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(5))
	b.WriteString("hello")
	w := &failingWriter{allowed: 0}
	if err := copySecret(w, &b); err == nil {
		t.Fatal("expected error when the destination write fails")
	}
}

// TestGopassInsertPropagatesError proves Insert surfaces an InsertAt/gopass
// failure and — critically — does NOT forget the handle in that case, since the
// secret never actually made it into gopass.
func TestGopassInsertPropagatesError(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gopass")
	script := "#!/usr/bin/env bash\necho denied >&2\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	g := &Gopass{Bin: bin}
	v := vault.New()
	defer v.Purge()

	c := discover.Credential{Source: "env", Identity: "X", Secret: v.Store([]byte("s"))}
	if err := g.Insert(context.Background(), v, c, true); err == nil {
		t.Fatal("expected Insert to surface a gopass insert failure")
	}
	if _, err := v.Open(c.Secret); err != nil {
		t.Error("Insert forgot the handle despite the underlying insert failing")
	}
}

// TestGopassInsertAtInvalidHandle proves InsertAt surfaces a vault.Open failure
// (e.g. a handle already forgotten) instead of panicking on a nil buffer.
func TestGopassInsertAtInvalidHandle(t *testing.T) {
	g := &Gopass{Bin: writeFakeGopass(t)}
	v := vault.New()
	defer v.Purge()

	h := v.Store([]byte("temp"))
	v.Forget(h)
	if err := g.InsertAt(context.Background(), v, "imported/x", h, true); err == nil {
		t.Fatal("expected InsertAt to fail opening an already-forgotten handle")
	}
}

// TestGopassShowCommandFails proves Show surfaces a `gopass show` failure rather
// than storing a partial/garbage value into the vault.
func TestGopassShowCommandFails(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gopass")
	script := "#!/usr/bin/env bash\necho boom >&2\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	g := &Gopass{Bin: bin}
	v := vault.New()
	defer v.Purge()

	if _, err := g.Show(context.Background(), v, "imported/x"); err == nil {
		t.Fatal("expected Show to surface a gopass show failure")
	}
}

// TestGopassExistsCommandFails proves Exists reports false (not a panic or a
// stale-looking true) when the underlying `gopass ls` fails to run at all.
func TestGopassExistsCommandFails(t *testing.T) {
	g := &Gopass{Bin: "/nonexistent/gopass-xyz"}
	if g.Exists(context.Background(), "imported/x") {
		t.Fatal("Exists reported true when the ls command could not even run")
	}
}
