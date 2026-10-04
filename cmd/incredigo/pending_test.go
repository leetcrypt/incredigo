package main

import (
	"context"
	"reflect"
	"testing"

	"incredigo/internal/sink"
	"incredigo/internal/vault"
)

// TestGopassCredsForExecute_pendingHeldBack proves a ".pending" copy is never rotated as a
// credential, and that its primary entry is held back until a human reconciles the pair (the
// service may accept only the pending secret; rotating from the primary would act on a dead
// one).
func TestGopassCredsForExecute_pendingHeldBack(t *testing.T) {
	fakeGopassOnPath(t, false, map[string]string{
		"imported/pg/app":         "fake-old",
		"imported/pg/app.pending": "fake-new",
		"imported/env/api":        "fake-tok",
	})
	v := vault.New()
	defer v.Purge()

	creds, held, err := gopassCredsForExecute(context.Background(), &sink.Gopass{}, v, "imported/")
	if err != nil {
		t.Fatalf("gopassCredsForExecute: %v", err)
	}
	var got []string
	for _, c := range creds {
		got = append(got, c.Location)
	}
	if !reflect.DeepEqual(got, []string{"imported/env/api"}) {
		t.Errorf("rotatable = %v, want only imported/env/api", got)
	}
	if !reflect.DeepEqual(held, []string{"imported/pg/app"}) {
		t.Errorf("held back = %v, want [imported/pg/app]", held)
	}
}
