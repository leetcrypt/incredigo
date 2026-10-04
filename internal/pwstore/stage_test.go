package pwstore

import (
	"bytes"
	"strings"
	"testing"

	"incredigo/internal/vault"
)

func TestStagedRoundTripNewPasswords(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	accts := []Account{
		{ID: "id1", URL: "https://a.test/", Username: "u1", Secret: v.Store([]byte("old1"))},
		{ID: "id2", URL: "https://b.test/", Username: "u2", Secret: v.Store([]byte("old2"))},
	}
	newPw := map[int]*vault.Handle{0: v.Store([]byte("NEW-1"))}

	var buf bytes.Buffer
	if err := WriteStaged(&buf, v, accts, newPw); err != nil {
		t.Fatalf("WriteStaged: %v", err)
	}
	// Sanity: stream carries the substituted/kept passwords (it is sealed in production).
	if !strings.Contains(buf.String(), "NEW-1") || !strings.Contains(buf.String(), "old2") {
		t.Fatalf("staged stream missing expected passwords:\n%s", buf.String())
	}

	v2 := vault.New()
	defer v2.Purge()
	got, err := ReadStaged(v2, &buf)
	if err != nil {
		t.Fatalf("ReadStaged: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].ID != "id1" || got[0].Site != "a.test" {
		t.Errorf("record0 = %+v", got[0])
	}
	if pw := handleStr(t, v2, got[0].Secret); pw != "NEW-1" {
		t.Errorf("record0 password = %q, want NEW-1", pw)
	}
	if pw := handleStr(t, v2, got[1].Secret); pw != "old2" {
		t.Errorf("record1 password = %q, want old2 (untouched)", pw)
	}
}

func TestStagedBackupKeepsOldPasswords(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	accts := []Account{{ID: "id1", URL: "https://a.test/", Username: "u1", Secret: v.Store([]byte("keepme"))}}

	var buf bytes.Buffer
	if err := WriteStaged(&buf, v, accts, nil); err != nil { // nil newPw = backup of current store
		t.Fatalf("WriteStaged: %v", err)
	}
	v2 := vault.New()
	defer v2.Purge()
	got, err := ReadStaged(v2, &buf)
	if err != nil {
		t.Fatalf("ReadStaged: %v", err)
	}
	if pw := handleStr(t, v2, got[0].Secret); pw != "keepme" {
		t.Errorf("backup password = %q, want keepme", pw)
	}
}
