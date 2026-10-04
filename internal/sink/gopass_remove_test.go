package sink

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGopassRemove(t *testing.T) {
	gp := &Gopass{Bin: writeFakeGopass(t)}
	store := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", store)
	seed(t, store, map[string]string{
		"imported/pg/app.pending": "fake-new",
		"imported/pg/app":         "fake-old",
	})

	if err := gp.Remove(context.Background(), "imported/pg/app.pending"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store, "imported/pg/app.pending")); !os.IsNotExist(err) {
		t.Error("entry still present after Remove")
	}
	if _, err := os.Stat(filepath.Join(store, "imported/pg/app")); err != nil {
		t.Error("Remove touched a sibling entry")
	}
	if err := gp.Remove(context.Background(), "imported/pg/missing"); err == nil {
		t.Error("Remove of a missing entry must report an error")
	}
}
