package vault

import (
	"bytes"
	"testing"
)

func TestStoreWipesCallerAndRoundTrips(t *testing.T) {
	v := New()
	defer v.Purge()

	secret := []byte("super-secret-value")
	want := append([]byte(nil), secret...)

	h := v.Store(secret)

	// Store must wipe the caller's slice (memguard NewBufferFromBytes contract).
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Errorf("Store did not wipe caller slice, got %q", secret)
	}

	buf, err := v.Open(h)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("round-trip mismatch: got %q want %q", buf.Bytes(), want)
	}
}

func TestForgetZeroizes(t *testing.T) {
	v := New()
	defer v.Purge()

	h := v.Store([]byte("wipe-me"))
	buf, err := v.Open(h)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !buf.IsAlive() {
		t.Fatal("buffer should be alive before Forget")
	}

	v.Forget(h)

	if buf.IsAlive() {
		t.Error("buffer should be destroyed (zeroized) after Forget")
	}
	if _, err := v.Open(h); err == nil {
		t.Error("Open after Forget should return an error for the dead handle")
	}
}

func TestPurgeDestroysAll(t *testing.T) {
	v := New()
	h1 := v.Store([]byte("a"))
	h2 := v.Store([]byte("b"))

	v.Purge()

	if _, err := v.Open(h1); err == nil {
		t.Error("h1 should be gone after Purge")
	}
	if _, err := v.Open(h2); err == nil {
		t.Error("h2 should be gone after Purge")
	}
}
