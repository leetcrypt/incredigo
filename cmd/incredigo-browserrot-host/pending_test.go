package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/browserrot"
	"incredigo/internal/sink"
	"incredigo/internal/vault"
)

// TestKeepPendingSecret proves an outcome-unknown new secret is saved BESIDE the old entry,
// never over it, so the human can try both.
func TestKeepPendingSecret(t *testing.T) {
	const storePath = "imported/gitea/login-creds"
	gp := fakeGopass(t, map[string]string{storePath: "fake-old-pw"})
	store := os.Getenv("FAKE_GOPASS_STORE")

	v := vault.New()
	defer v.Purge()
	newH := v.Store([]byte("fake-new-pw"))

	pending, err := keepPendingSecret(context.Background(), gp, v, storePath, newH)
	if err != nil {
		t.Fatalf("keepPendingSecret: %v", err)
	}
	if pending != storePath+".pending" {
		t.Errorf("pending path = %q, want %q", pending, storePath+".pending")
	}
	got, err := os.ReadFile(filepath.Join(store, pending))
	if err != nil || string(got) != "fake-new-pw" {
		t.Fatalf("pending entry = %q (err %v), want the new secret", got, err)
	}
	old, _ := os.ReadFile(filepath.Join(store, storePath))
	if string(old) != "fake-old-pw" {
		t.Fatalf("old entry was modified: %q", old)
	}
}

// TestOutcomeUnknown covers both branches: the new secret is saved beside the old entry and
// the error still carries ErrOutcomeUnknown; if saving fails, the error says so loudly.
func TestOutcomeUnknown(t *testing.T) {
	const storePath = "gitea/login-creds"
	cause := fmt.Errorf("wrapped: %w", browserrot.ErrOutcomeUnknown)

	gp := fakeGopass(t, map[string]string{storePath: "fake-old-pw"})
	v := vault.New()
	defer v.Purge()
	var log bytes.Buffer
	err := outcomeUnknown(context.Background(), gp, v, storePath, "alice @ https://git.example.org", v.Store([]byte("fake-new-pw")), cause, &log)
	if !errors.Is(err, browserrot.ErrOutcomeUnknown) || !strings.Contains(err.Error(), storePath+".pending") {
		t.Fatalf("err = %v, want ErrOutcomeUnknown naming the pending entry", err)
	}
	if !strings.Contains(log.String(), "OUTCOME_UNKNOWN") || strings.Contains(log.String(), "fake-new-pw") {
		t.Errorf("log must flag the outcome and never contain the secret: %q", log.String())
	}

	broken := &sink.Gopass{Bin: filepath.Join(t.TempDir(), "no-such-gopass")}
	err = outcomeUnknown(context.Background(), broken, v, storePath, "alice", v.Store([]byte("fake-new-pw")), cause, io.Discard)
	if !errors.Is(err, browserrot.ErrOutcomeUnknown) || !strings.Contains(err.Error(), "could NOT be saved") {
		t.Fatalf("err = %v, want a could-NOT-be-saved error", err)
	}
}
