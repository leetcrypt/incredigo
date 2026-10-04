package sink

// Bundle framing — the PLAINTEXT side of the Sealer.
//
// A bundle is a flat stream of records, each one gopass entry. It is produced by
// ExportTo and consumed by ImportFrom; in between it only ever exists encrypted
// (the Sealer wraps it) or in-flight through an io.Pipe. The wire format is:
//
//	record*  end
//	record := uint16 pathLen            // big-endian; pathLen==0 is the end sentinel
//	          [pathLen]byte path        // non-secret gopass path, UTF-8
//	          chunk* secretEnd
//	chunk  := uint32 chunkLen           // big-endian; chunkLen==0 ends this secret
//	          [chunkLen]byte chunk      // a slice of the secret value
//	end    := uint16 0                  // zero-length path terminates the stream
//
// Secrets are streamed in chunks so a complete secret value is never assembled in
// one buffer and never becomes a Go string: bytes flow gopass.stdout -> frame ->
// pipe (export), and pipe -> frame -> gopass.stdin (import). Paths are not secret.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

const exportChunk = 32 * 1024

// ListPaths returns the gopass entry paths under prefix, in gopass's order.
func (g *Gopass) ListPaths(ctx context.Context, prefix string) ([]string, error) {
	out, err := exec.CommandContext(ctx, g.bin(), "ls", "--flat").Output()
	if err != nil {
		return nil, fmt.Errorf("gopass ls: %w", err)
	}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(line)
		if p == "" {
			continue
		}
		if prefix == "" || strings.HasPrefix(p, prefix) {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// ExportTo writes the framed plaintext record stream for every entry under prefix
// to w. Each secret is streamed straight from `gopass show -o` into the frame; it
// is never buffered whole and never converted to a string. Returns the entry count.
func (g *Gopass) ExportTo(ctx context.Context, w io.Writer, prefix string) (int, error) {
	paths, err := g.ListPaths(ctx, prefix)
	if err != nil {
		return 0, err
	}
	for _, p := range paths {
		if err := writePath(w, p); err != nil {
			return 0, err
		}
		if err := g.streamSecret(ctx, w, p); err != nil {
			return 0, err
		}
	}
	// end-of-stream sentinel: a zero-length path
	if err := binary.Write(w, binary.BigEndian, uint16(0)); err != nil {
		return 0, err
	}
	return len(paths), nil
}

// streamSecret pipes one entry's secret value into w as a chunk sequence followed
// by a zero-length end marker.
func (g *Gopass) streamSecret(ctx context.Context, w io.Writer, path string) error {
	cmd := exec.CommandContext(ctx, g.bin(), "show", "-o", path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	buf := make([]byte, exportChunk)
	for {
		n, rerr := stdout.Read(buf)
		if n > 0 {
			if err := binary.Write(w, binary.BigEndian, uint32(n)); err != nil {
				_ = cmd.Wait()
				return err
			}
			if _, err := w.Write(buf[:n]); err != nil {
				_ = cmd.Wait()
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = cmd.Wait()
			return rerr
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("gopass show %q: %w", path, err)
	}
	// zero-length chunk ends this secret
	return binary.Write(w, binary.BigEndian, uint32(0))
}

// ImportFrom reads a framed plaintext record stream from r and re-inserts every
// entry into gopass. Each secret streams frame -> gopass stdin without ever being
// held whole or stringified. force overwrites existing entries. Returns the count.
func (g *Gopass) ImportFrom(ctx context.Context, r io.Reader, force bool) (int, error) {
	var n int
	for {
		var pathLen uint16
		if err := binary.Read(r, binary.BigEndian, &pathLen); err != nil {
			if err == io.EOF {
				return n, nil // tolerate missing sentinel at clean EOF
			}
			return n, err
		}
		if pathLen == 0 {
			return n, nil // end-of-stream sentinel
		}
		pb := make([]byte, pathLen)
		if _, err := io.ReadFull(r, pb); err != nil {
			return n, err
		}
		if err := g.insertStream(ctx, r, string(pb), force); err != nil {
			return n, err
		}
		n++
	}
}

// insertStream spawns `gopass insert` for path and feeds it the chunked secret
// from r (consuming exactly up to this record's zero-length end marker).
func (g *Gopass) insertStream(ctx context.Context, r io.Reader, path string, force bool) error {
	args := []string{"insert", "--multiline=false"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, path)

	cmd := exec.CommandContext(ctx, g.bin(), args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	copyErr := copySecret(stdin, r)
	stdin.Close()
	if werr := cmd.Wait(); werr != nil {
		return fmt.Errorf("gopass insert %q: %w", path, werr)
	}
	return copyErr
}

// copySecret streams one secret's chunks from r to dst until the zero-length end
// marker. Uses io.CopyN so a full secret is never buffered.
func copySecret(dst io.Writer, r io.Reader) error {
	for {
		var chunkLen uint32
		if err := binary.Read(r, binary.BigEndian, &chunkLen); err != nil {
			return err
		}
		if chunkLen == 0 {
			return nil
		}
		if _, err := io.CopyN(dst, r, int64(chunkLen)); err != nil {
			return err
		}
	}
}

// CountBundleRecords walks a decrypted bundle stream and returns how many records
// (entries) it contains, writing nothing. It is the completeness half of backup
// verification: a bundle that the Sealer can Open is authentic; counting its
// records confirms every expected entry is present. Secret bytes are read only to
// skip past them (discarded).
func CountBundleRecords(r io.Reader) (int, error) {
	var n int
	for {
		var pathLen uint16
		if err := binary.Read(r, binary.BigEndian, &pathLen); err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
		if pathLen == 0 {
			return n, nil // end-of-stream sentinel
		}
		if _, err := io.CopyN(io.Discard, r, int64(pathLen)); err != nil {
			return n, err
		}
		for { // skip the secret's chunks up to the zero-length marker
			var chunkLen uint32
			if err := binary.Read(r, binary.BigEndian, &chunkLen); err != nil {
				return n, err
			}
			if chunkLen == 0 {
				break
			}
			if _, err := io.CopyN(io.Discard, r, int64(chunkLen)); err != nil {
				return n, err
			}
		}
		n++
	}
}

func writePath(w io.Writer, path string) error {
	if len(path) > 0xffff {
		return fmt.Errorf("gopass path too long: %d bytes", len(path))
	}
	if err := binary.Write(w, binary.BigEndian, uint16(len(path))); err != nil {
		return err
	}
	_, err := io.WriteString(w, path)
	return err
}
