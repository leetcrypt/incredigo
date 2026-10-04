package discover

import (
	"context"
	"errors"
	"testing"

	"incredigo/internal/vault"
)

// fakeScanner is a minimal Scanner used to exercise the registry (Register/
// Scanners/ScanAll) without depending on the real filesystem-backed scanners
// registered by the package's own init() functions.
type fakeScanner struct {
	name      string
	available bool
	creds     []Credential
	err       error
}

func (f *fakeScanner) Name() string    { return f.name }
func (f *fakeScanner) Available() bool { return f.available }
func (f *fakeScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	return f.creds, f.err
}

func TestRegisterAndScanners(t *testing.T) {
	fake := &fakeScanner{name: "zz-fake-registry-test", available: true}
	Register(fake)

	t.Run("named lookup returns exactly the registered scanner", func(t *testing.T) {
		got := Scanners("zz-fake-registry-test")
		if len(got) != 1 || got[0].Name() != "zz-fake-registry-test" {
			t.Fatalf("Scanners(name) = %+v, want just the fake", got)
		}
	})

	t.Run("unknown name is silently ignored", func(t *testing.T) {
		got := Scanners("zz-does-not-exist")
		if len(got) != 0 {
			t.Fatalf("Scanners(unknown) = %+v, want empty", got)
		}
	})

	t.Run("mixed known/unknown names returns only the known one", func(t *testing.T) {
		got := Scanners("zz-fake-registry-test", "zz-does-not-exist")
		if len(got) != 1 || got[0].Name() != "zz-fake-registry-test" {
			t.Fatalf("Scanners(mixed) = %+v, want just the fake", got)
		}
	})

	t.Run("no names returns all registered scanners, sorted, including the fake", func(t *testing.T) {
		got := Scanners()
		if len(got) < 2 { // the fake plus every real scanner from init()
			t.Fatalf("Scanners() = %+v, want at least 2 (fake + real scanners)", got)
		}
		found := false
		for i, s := range got {
			if s.Name() == "zz-fake-registry-test" {
				found = true
			}
			if i > 0 && got[i-1].Name() > s.Name() {
				t.Errorf("Scanners() not sorted by name: %q before %q", got[i-1].Name(), s.Name())
			}
		}
		if !found {
			t.Errorf("Scanners() missing the registered fake: %+v", got)
		}
	})

	t.Run("re-registering the same name overwrites, not duplicates", func(t *testing.T) {
		Register(&fakeScanner{name: "zz-fake-registry-test", available: false})
		count := 0
		for _, s := range Scanners() {
			if s.Name() == "zz-fake-registry-test" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("re-registering duplicated the scanner: count=%d", count)
		}
	})
}

func TestScanAllSkipsUnavailable(t *testing.T) {
	Register(&fakeScanner{name: "zz-unavailable", available: false, creds: []Credential{{Source: "zz-unavailable"}}})

	v := vault.New()
	defer v.Purge()
	creds, err := ScanAll(context.Background(), v, "zz-unavailable")
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("ScanAll should have skipped the unavailable scanner, got %+v", creds)
	}
}

func TestScanAllAggregatesAvailable(t *testing.T) {
	Register(&fakeScanner{name: "zz-avail-a", available: true, creds: []Credential{{Source: "zz-avail-a", Identity: "one"}}})
	Register(&fakeScanner{name: "zz-avail-b", available: true, creds: []Credential{{Source: "zz-avail-b", Identity: "two"}}})

	v := vault.New()
	defer v.Purge()
	creds, err := ScanAll(context.Background(), v, "zz-avail-a", "zz-avail-b")
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("ScanAll = %+v, want 2 aggregated creds", creds)
	}
}

func TestScanAllStopsAndReturnsPartialOnError(t *testing.T) {
	wantErr := errors.New("boom")
	// Scanners() always sorts its result alphabetically by name regardless of
	// the order names are requested in, so the "aaa"/"bbb" prefixes here are
	// what actually pins run order (aaa's credential collected before bbb errors).
	Register(&fakeScanner{name: "zz-aaa-ok-before-error", available: true, creds: []Credential{{Source: "zz-aaa-ok-before-error", Identity: "kept"}}})
	Register(&fakeScanner{name: "zz-bbb-erroring", available: true, err: wantErr})

	v := vault.New()
	defer v.Purge()
	creds, err := ScanAll(context.Background(), v, "zz-bbb-erroring", "zz-aaa-ok-before-error")
	if !errors.Is(err, wantErr) {
		t.Fatalf("ScanAll error = %v, want %v", err, wantErr)
	}
	if len(creds) != 1 || creds[0].Identity != "kept" {
		t.Errorf("ScanAll should keep results collected before the error, got %+v", creds)
	}
}

func TestScanAllNoScannersReturnsEmpty(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	creds, err := ScanAll(context.Background(), v, "zz-name-that-truly-does-not-exist")
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("ScanAll = %+v, want empty", creds)
	}
}
