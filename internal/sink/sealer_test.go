package sink

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/awnumar/memguard"
)

// newPass returns a fresh locked buffer for s. A fresh buffer is used per Seal/Open
// call because memguard.NewBufferFromBytes wipes its source slice, and reusing one
// buffer across operations would couple unrelated calls.
func newPass(s string) *memguard.LockedBuffer {
	return memguard.NewBufferFromBytes([]byte(s))
}

// authenticatedSealers fail closed on tamper / wrong passphrase. openssl is
// deliberately excluded — it is unauthenticated (see openssl.go) and its tamper
// behaviour is asserted separately in TestOpenSSLTamperUnauthenticated.
func authenticatedSealers() map[string]Sealer {
	return map[string]Sealer{
		"age":  &Age{WorkFactor: 10}, // low cost keeps the test fast; correctness is unaffected
		"hmac": &HMACSealer{Iter: 1000},
	}
}

func allSealers() map[string]Sealer {
	s := authenticatedSealers()
	s["openssl"] = &OpenSSL{Iter: 1000}
	return s
}

// TestSealerRoundTrip proves every sealer is byte-exact: seal → open == original,
// including empty and binary payloads.
func TestSealerRoundTrip(t *testing.T) {
	ctx := context.Background()
	payloads := map[string][]byte{
		"ascii":   []byte("AKIA/secret+with=specials"),
		"binary":  {0x00, 0xff, 0x0a, 0x0d, 0x1b, 0x7f, 0x80},
		"unicode": []byte("unicode-末-\U0001f511"),
		"empty":   {},
		"large":   bytes.Repeat([]byte("credential-storage-turnover "), 4096),
	}
	for name, sealer := range allSealers() {
		for pname, pt := range payloads {
			t.Run(name+"/"+pname, func(t *testing.T) {
				var sealed bytes.Buffer
				if err := sealer.Seal(ctx, bytes.NewReader(pt), &sealed, newPass("correct horse")); err != nil {
					t.Fatalf("seal: %v", err)
				}
				// Sealed form must not be the plaintext (except that an empty
				// plaintext may legitimately produce a tiny header-only blob).
				if len(pt) > 0 && bytes.Contains(sealed.Bytes(), pt) {
					t.Fatal("plaintext leaked into sealed output")
				}
				var opened bytes.Buffer
				if err := sealer.Open(ctx, &sealed, &opened, newPass("correct horse")); err != nil {
					t.Fatalf("open: %v", err)
				}
				if !bytes.Equal(opened.Bytes(), pt) {
					t.Fatalf("round-trip mismatch: got %q want %q", opened.Bytes(), pt)
				}
			})
		}
	}
}

// TestSealerWrongPassphrase proves that opening with the wrong passphrase fails
// cleanly and yields no plaintext for the authenticated sealers. openssl (CBC,
// unauthenticated) may or may not error, so it is tested for the weaker property:
// it must never reproduce the original plaintext under a wrong passphrase.
func TestSealerWrongPassphrase(t *testing.T) {
	ctx := context.Background()
	pt := []byte("verify-new-before-revoke-old")

	t.Run("authenticated-fail-closed", func(t *testing.T) {
		for name, sealer := range authenticatedSealers() {
			var sealed bytes.Buffer
			if err := sealer.Seal(ctx, bytes.NewReader(pt), &sealed, newPass("right-pass")); err != nil {
				t.Fatalf("%s seal: %v", name, err)
			}
			var opened bytes.Buffer
			err := sealer.Open(ctx, &sealed, &opened, newPass("wrong-pass"))
			if err == nil {
				t.Errorf("%s: wrong passphrase opened without error", name)
			}
			if opened.Len() != 0 {
				t.Errorf("%s: emitted %d bytes on wrong passphrase (want 0)", name, opened.Len())
			}
		}
	})

	t.Run("openssl-no-plaintext-recovery", func(t *testing.T) {
		sealer := &OpenSSL{Iter: 1000}
		var sealed bytes.Buffer
		if err := sealer.Seal(ctx, bytes.NewReader(pt), &sealed, newPass("right-pass")); err != nil {
			t.Fatalf("seal: %v", err)
		}
		var opened bytes.Buffer
		// Unauthenticated: an error is acceptable but not guaranteed; the invariant
		// is that the original plaintext is never recovered.
		_ = sealer.Open(ctx, &sealed, &opened, newPass("wrong-pass"))
		if bytes.Equal(opened.Bytes(), pt) {
			t.Fatal("openssl recovered plaintext under a wrong passphrase")
		}
	})
}

// TestSealerTamperFailsClosed proves the authenticated sealers reject a bundle
// whose ciphertext has been altered. This is the property the backup gate leans on:
// a corrupt backup must fail to open rather than restore silent garbage.
func TestSealerTamperFailsClosed(t *testing.T) {
	ctx := context.Background()
	pt := []byte("backup before rotate, always")

	for name, sealer := range authenticatedSealers() {
		t.Run(name, func(t *testing.T) {
			var sealed bytes.Buffer
			if err := sealer.Seal(ctx, bytes.NewReader(pt), &sealed, newPass("pw")); err != nil {
				t.Fatalf("seal: %v", err)
			}
			b := sealed.Bytes()
			if len(b) == 0 {
				t.Fatal("empty sealed output")
			}
			// Flip a byte near the end (well inside the ciphertext body for both
			// the age payload and the hmac mac||ct layout).
			b[len(b)-1] ^= 0x01

			var opened bytes.Buffer
			err := sealer.Open(ctx, bytes.NewReader(b), &opened, newPass("pw"))
			if err == nil {
				t.Errorf("%s: opened a tampered bundle without error", name)
			}
			if opened.Len() != 0 {
				t.Errorf("%s: emitted %d bytes from a tampered bundle (want 0)", name, opened.Len())
			}
		})
	}
}

// TestHMACTamperInMACHeader proves the HMAC sealer rejects a bundle whose MAC (the
// first 32 bytes) has been altered — verified before any decryption is attempted.
func TestHMACTamperInMACHeader(t *testing.T) {
	ctx := context.Background()
	pt := []byte("integrity first")
	sealer := &HMACSealer{Iter: 1000}

	var sealed bytes.Buffer
	if err := sealer.Seal(ctx, bytes.NewReader(pt), &sealed, newPass("pw")); err != nil {
		t.Fatalf("seal: %v", err)
	}
	b := sealed.Bytes()
	b[0] ^= 0xff // corrupt the MAC header

	var opened bytes.Buffer
	if err := sealer.Open(ctx, bytes.NewReader(b), &opened, newPass("pw")); err == nil {
		t.Error("hmac: opened a bundle with a corrupt MAC without error")
	}
	if opened.Len() != 0 {
		t.Errorf("hmac: emitted %d bytes despite MAC corruption", opened.Len())
	}
}

// TestHMACShortBundle proves the HMAC sealer rejects a bundle too short to contain
// a MAC rather than panicking on the slice.
func TestHMACShortBundle(t *testing.T) {
	sealer := &HMACSealer{Iter: 1000}
	var opened bytes.Buffer
	err := sealer.Open(context.Background(), strings.NewReader("tiny"), &opened, newPass("pw"))
	if err == nil {
		t.Error("hmac: accepted a bundle shorter than a MAC")
	}
}

// TestSealerNames pins the wire/name identity of each sealer (used in backup
// metadata and CLI selection).
func TestSealerNames(t *testing.T) {
	for want, s := range map[string]Sealer{"age": &Age{}, "hmac": &HMACSealer{}, "openssl": &OpenSSL{}} {
		if got := s.Name(); got != want {
			t.Errorf("Name() = %q, want %q", got, want)
		}
	}
}

// TestSealerDefaultConfig exercises the zero-value default paths of the openssl-based
// sealers (default bin "openssl", default iter) with a real round-trip. Age's default
// work factor (18, ~256 MiB scrypt) is intentionally not exercised here for speed.
func TestSealerDefaultConfig(t *testing.T) {
	ctx := context.Background()
	pt := []byte("default-config round trip")
	for name, s := range map[string]Sealer{"openssl": &OpenSSL{}, "hmac": &HMACSealer{}} {
		t.Run(name, func(t *testing.T) {
			var sealed, opened bytes.Buffer
			if err := s.Seal(ctx, bytes.NewReader(pt), &sealed, newPass("pw")); err != nil {
				t.Fatalf("seal: %v", err)
			}
			if err := s.Open(ctx, &sealed, &opened, newPass("pw")); err != nil {
				t.Fatalf("open: %v", err)
			}
			if !bytes.Equal(opened.Bytes(), pt) {
				t.Fatalf("round-trip mismatch")
			}
		})
	}
}

// TestOpenSSLBadBinary proves a failure to launch the openssl subprocess surfaces
// as an error (the backup gate must not treat a failed seal as success).
func TestOpenSSLBadBinary(t *testing.T) {
	s := &OpenSSL{Bin: "/nonexistent/openssl", Iter: 1000}
	var out bytes.Buffer
	if err := s.Seal(context.Background(), strings.NewReader("x"), &out, newPass("pw")); err == nil {
		t.Fatal("seal with a missing openssl binary returned no error")
	}
}

// TestAgeEmptyPassphrase proves age rejects an empty passphrase at seal time rather
// than producing an unopenable or weakly-keyed bundle.
func TestAgeEmptyPassphrase(t *testing.T) {
	s := &Age{WorkFactor: 10}
	var out bytes.Buffer
	if err := s.Seal(context.Background(), strings.NewReader("x"), &out, newPass("")); err == nil {
		t.Fatal("age sealed with an empty passphrase")
	}
}

// TestOpenSSLTamperUnauthenticated documents — as an executable contract — that the
// openssl sealer is UNAUTHENTICATED: tampering is NOT guaranteed to be detected. The
// only invariant is that the corrupted bundle does not reproduce the plaintext. This
// is why age is the default and openssl carries a loud warning in its doc comment.
func TestOpenSSLTamperUnauthenticated(t *testing.T) {
	ctx := context.Background()
	pt := []byte("prefer the age sealer for anything you care about")
	sealer := &OpenSSL{Iter: 1000}

	var sealed bytes.Buffer
	if err := sealer.Seal(ctx, bytes.NewReader(pt), &sealed, newPass("pw")); err != nil {
		t.Fatalf("seal: %v", err)
	}
	b := sealed.Bytes()
	b[len(b)-1] ^= 0x01

	var opened bytes.Buffer
	_ = sealer.Open(ctx, bytes.NewReader(b), &opened, newPass("pw"))
	// We assert only the weak property. If this ever starts failing because the
	// output equals pt, the sealer would be leaking exact plaintext from a tampered
	// bundle, which would be a genuine regression.
	if bytes.Equal(opened.Bytes(), pt) {
		t.Fatal("openssl reproduced exact plaintext from a tampered bundle")
	}
}
