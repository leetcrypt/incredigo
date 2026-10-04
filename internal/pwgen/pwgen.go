// Package pwgen generates strong passwords for the browser/password-manager
// rotation path. It uses crypto/rand with rejection sampling (no modulo bias),
// guarantees at least one character from every enabled class, and writes the
// result STRAIGHT INTO the RAM vault — it never returns the plaintext as a Go
// string (strings are immutable, GC-managed, and cannot be reliably wiped).
package pwgen

import (
	"crypto/rand"
	"fmt"

	"incredigo/internal/vault"
)

// Character classes. Ambiguous glyphs (O/0/l/1/I) are split out so a policy can
// drop them when a human may have to retype the password.
const (
	lowerAll  = "abcdefghijklmnopqrstuvwxyz"
	upperAll  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitsAll = "0123456789"
	// A conservative symbol set that the large majority of sites accept.
	symbolsAll = "!@#$%^&*()-_=+[]{};:,.?"
	ambiguous  = "O0l1I"
)

// Policy describes the shape of a generated password. The zero value is not
// useful; use DefaultPolicy and adjust.
type Policy struct {
	Length           int    // total length
	Upper            bool   // include A-Z
	Lower            bool   // include a-z
	Digits           bool   // include 0-9
	Symbols          bool   // include punctuation
	ExcludeAmbiguous bool   // drop O/0/l/1/I from every class
	SymbolSet        string // override the symbol alphabet (some sites reject specific symbols)
}

// DefaultPolicy is a strong, broadly-accepted default: 20 chars, all classes.
func DefaultPolicy() Policy {
	return Policy{Length: 20, Upper: true, Lower: true, Digits: true, Symbols: true}
}

// classAlphabets returns the per-class alphabets a policy enables, after applying
// ExcludeAmbiguous and any SymbolSet override. Each returned alphabet is non-empty.
func (p Policy) classAlphabets() ([]string, error) {
	add := func(out []string, base string) []string {
		s := base
		if p.ExcludeAmbiguous {
			s = strip(s, ambiguous)
		}
		if s != "" {
			return append(out, s)
		}
		return out
	}
	var classes []string
	if p.Lower {
		classes = add(classes, lowerAll)
	}
	if p.Upper {
		classes = add(classes, upperAll)
	}
	if p.Digits {
		classes = add(classes, digitsAll)
	}
	if p.Symbols {
		sym := p.SymbolSet
		if sym == "" {
			sym = symbolsAll
		}
		classes = add(classes, sym)
	}
	if len(classes) == 0 {
		return nil, fmt.Errorf("pwgen: policy enables no character classes")
	}
	if p.Length < len(classes) {
		return nil, fmt.Errorf("pwgen: length %d is shorter than the %d required classes", p.Length, len(classes))
	}
	return classes, nil
}

// Generate produces a password matching the policy and stores it in v, returning
// only a handle. The transient plaintext buffer is wiped before returning.
func Generate(v *vault.Vault, p Policy) (*vault.Handle, error) {
	classes, err := p.classAlphabets()
	if err != nil {
		return nil, err
	}
	combined := ""
	for _, c := range classes {
		combined += c
	}

	out := make([]byte, p.Length)
	// 1. One guaranteed character from each enabled class (fills the first
	//    len(classes) positions; they are shuffled across the whole slice next).
	for i, c := range classes {
		b, err := pick(c)
		if err != nil {
			wipe(out)
			return nil, err
		}
		out[i] = b
	}
	// 2. Fill the remainder from the combined alphabet.
	for i := len(classes); i < p.Length; i++ {
		b, err := pick(combined)
		if err != nil {
			wipe(out)
			return nil, err
		}
		out[i] = b
	}
	// 3. Shuffle so the guaranteed class characters are not always up front.
	if err := shuffle(out); err != nil {
		wipe(out)
		return nil, err
	}

	// Store copies into a locked buffer AND wipes our source slice.
	return v.Store(out), nil
}

// pick returns one uniformly-random byte from alphabet using rejection sampling
// to avoid modulo bias.
func pick(alphabet string) (byte, error) {
	n := len(alphabet)
	// Largest multiple of n that fits in a byte; reject samples at/above it.
	limit := 256 - (256 % n)
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return alphabet[int(b[0])%n], nil
		}
	}
}

// shuffle performs an unbiased Fisher-Yates shuffle over buf using crypto/rand.
func shuffle(buf []byte) error {
	for i := len(buf) - 1; i > 0; i-- {
		j, err := intn(i + 1)
		if err != nil {
			return err
		}
		buf[i], buf[j] = buf[j], buf[i]
	}
	return nil
}

// intn returns a uniformly-random int in [0,n) via rejection sampling.
func intn(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("pwgen: intn domain")
	}
	limit := 256 - (256 % n)
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}

// strip removes every byte of cut from s.
func strip(s, cut string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !contains(cut, s[i]) {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func contains(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
