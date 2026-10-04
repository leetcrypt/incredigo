package pwgen

import (
	"strings"
	"testing"

	"incredigo/internal/vault"
)

// read returns the generated password bytes as a string for assertions ONLY.
// (Tests are the one place we materialize the plaintext to check its shape.)
func read(t *testing.T, v *vault.Vault, h *vault.Handle) string {
	t.Helper()
	buf, err := v.Open(h)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return string(buf.Bytes())
}

func TestGenerateLengthAndClasses(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	h, err := Generate(v, DefaultPolicy())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pw := read(t, v, h)
	if len(pw) != 20 {
		t.Errorf("length = %d, want 20", len(pw))
	}
	if !strings.ContainsAny(pw, lowerAll) || !strings.ContainsAny(pw, upperAll) ||
		!strings.ContainsAny(pw, digitsAll) || !strings.ContainsAny(pw, symbolsAll) {
		t.Errorf("password %q missing a required class", pw)
	}
}

func TestGenerateExcludeAmbiguous(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	p := DefaultPolicy()
	p.ExcludeAmbiguous = true
	p.Length = 64
	// Generate several so we'd very likely hit an ambiguous char if not excluded.
	for i := 0; i < 50; i++ {
		h, err := Generate(v, p)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		pw := read(t, v, h)
		if strings.ContainsAny(pw, ambiguous) {
			t.Fatalf("password %q contains an ambiguous char despite ExcludeAmbiguous", pw)
		}
		v.Forget(h)
	}
}

func TestGenerateCustomSymbolSet(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	p := Policy{Length: 30, Lower: true, Symbols: true, SymbolSet: "#-_"}
	h, err := Generate(v, p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pw := read(t, v, h)
	for _, r := range pw {
		if !strings.ContainsRune(lowerAll+"#-_", r) {
			t.Fatalf("password %q contains %q outside the allowed alphabet", pw, r)
		}
	}
}

func TestGenerateUniqueness(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		h, err := Generate(v, DefaultPolicy())
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		pw := read(t, v, h)
		if seen[pw] {
			t.Fatalf("duplicate password generated: %q", pw)
		}
		seen[pw] = true
		v.Forget(h)
	}
}

func TestPolicyErrors(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	// No classes enabled.
	if _, err := Generate(v, Policy{Length: 10}); err == nil {
		t.Error("expected error when no classes are enabled")
	}
	// Length shorter than the number of required classes.
	if _, err := Generate(v, Policy{Length: 2, Upper: true, Lower: true, Digits: true, Symbols: true}); err == nil {
		t.Error("expected error when length < number of classes")
	}
}

// TestDistribution is a weak bias smoke check: over many single-char picks from a
// small alphabet, every symbol should appear (rejection sampling guarantees
// uniform coverage, so absences would signal a broken sampler).
func TestDistribution(t *testing.T) {
	counts := map[byte]int{}
	for i := 0; i < 5000; i++ {
		b, err := pick(digitsAll)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		counts[b]++
	}
	for i := 0; i < len(digitsAll); i++ {
		if counts[digitsAll[i]] == 0 {
			t.Errorf("digit %c never sampled in 5000 draws", digitsAll[i])
		}
	}
}
