package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteUsesInjectedClock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	log, err := Open(p, func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Write(Entry{Action: "scan", Source: "aws", Identity: "default / AKIA***", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}
	log.Close()

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.Contains(out, "2026-01-02T03:04:05Z") {
		t.Errorf("injected clock not used: %s", out)
	}
	if !strings.Contains(out, `"action":"scan"`) || !strings.Contains(out, `"source":"aws"`) {
		t.Errorf("entry not serialized as expected: %s", out)
	}
}

func TestNoopLogWhenPathEmpty(t *testing.T) {
	log, err := Open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Write(Entry{Action: "scan"}); err != nil {
		t.Errorf("no-op Write should not error: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Errorf("no-op Close should not error: %v", err)
	}
}
