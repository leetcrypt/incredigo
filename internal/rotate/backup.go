package rotate

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/awnumar/memguard"

	"incredigo/internal/sink"
)

// Snapshot is the MANDATORY backup gate (docs/ROTATION.md §3). It MUST succeed
// before any credential is rotated.
//
// It exports the gopass entries under prefix into a sealed, authenticated bundle
// at outPath (refusing to overwrite), then re-opens and walks the bundle to
// confirm it decrypts/authenticates and contains exactly the number of entries
// that were sealed. It returns the verified entry count. Any error — failure to
// seal, to re-open/authenticate, or an entry-count mismatch — means the caller
// MUST NOT proceed with rotation.
func Snapshot(ctx context.Context, gp *sink.Gopass, prefix string, sealer sink.Sealer, pass *memguard.LockedBuffer, outPath string) (int, error) {
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("backup: create %s (use a fresh path): %w", outPath, err)
	}

	// export (framed plaintext) -> Sealer -> file
	type exp struct {
		n   int
		err error
	}
	ch := make(chan exp, 1)
	pr, pw := io.Pipe()
	go func() {
		n, e := gp.ExportTo(ctx, pw, prefix)
		pw.CloseWithError(e)
		ch <- exp{n, e}
	}()
	sealErr := sealer.Seal(ctx, pr, f, pass)
	closeErr := f.Close()
	res := <-ch // synchronizes the exported count

	if res.err != nil {
		os.Remove(outPath)
		return 0, fmt.Errorf("backup: export: %w", res.err)
	}
	if sealErr != nil {
		os.Remove(outPath)
		return 0, fmt.Errorf("backup: seal: %w", sealErr)
	}
	if closeErr != nil {
		return 0, closeErr
	}

	verified, err := verifyBundle(ctx, sealer, pass, outPath)
	if err != nil {
		return 0, fmt.Errorf("backup: VERIFY FAILED for %s — do NOT rotate: %w", outPath, err)
	}
	if verified != res.n {
		return 0, fmt.Errorf("backup: integrity mismatch — sealed %d entries but verified %d; do NOT rotate", res.n, verified)
	}
	return verified, nil
}

// verifyBundle re-opens a sealed bundle, authenticates it via the Sealer, and
// counts its records — without writing anything anywhere.
func verifyBundle(ctx context.Context, sealer sink.Sealer, pass *memguard.LockedBuffer, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sealer.Open(ctx, f, pw, pass)) }()
	return sink.CountBundleRecords(pr)
}
