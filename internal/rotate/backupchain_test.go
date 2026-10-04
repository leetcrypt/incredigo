package rotate

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"incredigo/internal/sink"
)

// fakeBundlePlaintext builds a valid framed bundle stream (see sink/bundle.go)
// with one record per path, so a sealed copy both opens (authenticated) and
// counts as a real, complete backup during verification.
func fakeBundlePlaintext(paths ...string) []byte {
	var b bytes.Buffer
	for _, p := range paths {
		_ = binary.Write(&b, binary.BigEndian, uint16(len(p)))
		b.WriteString(p)
		secret := []byte("secret-for-" + p)
		_ = binary.Write(&b, binary.BigEndian, uint32(len(secret)))
		b.Write(secret)
		_ = binary.Write(&b, binary.BigEndian, uint32(0)) // end this secret
	}
	_ = binary.Write(&b, binary.BigEndian, uint16(0)) // end-of-stream sentinel
	return b.Bytes()
}

// seedBackup writes one genuinely sealed backup at path with the given modtime.
func seedBackup(t *testing.T, sealer sink.Sealer, pass *memguard.LockedBuffer, path string, mod time.Time) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealer.Seal(context.Background(), bytes.NewReader(fakeBundlePlaintext("imported/aws/default")), f, pass); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func TestBackupPrune(t *testing.T) {
	sealer := &sink.Age{WorkFactor: 10} // low cost keeps the test fast; correctness unaffected
	pass := memguard.NewBufferFromBytes([]byte("turnover-pass"))
	defer pass.Destroy()

	dir := t.TempDir()
	const (
		total = 15
		keep  = 10
	)
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	names := make([]string, total)
	for i := 0; i < total; i++ {
		// Timestamped, sortable names; older files get older mtimes.
		name := base.Add(time.Duration(i) * time.Minute).Format("2006-01-02T15-04-05Z") + ".age"
		names[i] = name
		seedBackup(t, sealer, pass, filepath.Join(dir, name), base.Add(time.Duration(i)*time.Minute))
	}

	// A non-backup sibling file must survive the prune untouched.
	readme := filepath.Join(dir, "README.txt")
	if err := os.WriteFile(readme, []byte("do not delete me"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Guard "nothing outside the dir is touched": a decoy tree next to it.
	outside := t.TempDir()
	decoy := filepath.Join(outside, "keep-me.age")
	if err := os.WriteFile(decoy, []byte("outside the prune dir"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := PruneBackups(context.Background(), dir, keep, sealer, pass)
	if err != nil {
		t.Fatalf("PruneBackups: %v", err)
	}

	// Exactly the newest `keep` .age files remain.
	remaining := listAgeNames(t, dir)
	if len(remaining) != keep {
		t.Fatalf("after prune %d .age files remain, want %d: %v", len(remaining), keep, remaining)
	}
	wantKept := append([]string(nil), names[total-keep:]...) // newest keep, oldest-first
	sort.Strings(wantKept)
	if len(remaining) != len(wantKept) {
		t.Fatalf("remaining set size mismatch")
	}
	for i := range wantKept {
		if remaining[i] != wantKept[i] {
			t.Fatalf("retained set = %v, want the newest %d %v", remaining, keep, wantKept)
		}
	}

	// The oldest names (the first total-keep) must be gone.
	for _, gone := range names[:total-keep] {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be deleted, stat err=%v", gone, err)
		}
	}

	// Result bookkeeping.
	if len(res.Kept) != keep {
		t.Fatalf("res.Kept = %d, want %d", len(res.Kept), keep)
	}
	if len(res.Deleted) != total-keep {
		t.Fatalf("res.Deleted = %d, want %d", len(res.Deleted), total-keep)
	}

	// The oldest RETAINED backup still opens + authenticates after the prune.
	oldestRetained := filepath.Join(dir, wantKept[0])
	if res.VerifiedOldest != oldestRetained {
		t.Fatalf("VerifiedOldest = %q, want %q", res.VerifiedOldest, oldestRetained)
	}
	if n, err := verifyBundle(context.Background(), sealer, pass, oldestRetained); err != nil || n != 1 {
		t.Fatalf("oldest retained backup must still verify: n=%d err=%v", n, err)
	}

	// The non-backup sibling survived.
	if _, err := os.Stat(readme); err != nil {
		t.Fatalf("non-backup sibling README.txt must be untouched: %v", err)
	}
	// Nothing outside the prune dir was touched.
	if b, err := os.ReadFile(decoy); err != nil || string(b) != "outside the prune dir" {
		t.Fatalf("file outside the prune dir was touched: err=%v", err)
	}
	if outNames := listAgeNames(t, outside); len(outNames) != 1 {
		t.Fatalf("outside dir changed: %v", outNames)
	}
}

func TestBackupPruneNoOpWhenUnderKeep(t *testing.T) {
	sealer := &sink.Age{WorkFactor: 10}
	pass := memguard.NewBufferFromBytes([]byte("pw"))
	defer pass.Destroy()

	dir := t.TempDir()
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		name := base.Add(time.Duration(i) * time.Minute).Format("2006-01-02T15-04-05Z") + ".age"
		seedBackup(t, sealer, pass, filepath.Join(dir, name), base.Add(time.Duration(i)*time.Minute))
	}

	res, err := PruneBackups(context.Background(), dir, 10, sealer, pass)
	if err != nil {
		t.Fatalf("PruneBackups: %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Fatalf("nothing should be deleted when count <= keep, deleted %d", len(res.Deleted))
	}
	if got := listAgeNames(t, dir); len(got) != 3 {
		t.Fatalf("all 3 backups should remain, got %v", got)
	}
}

func TestBackupPruneRejectsBadKeep(t *testing.T) {
	sealer := &sink.Age{WorkFactor: 10}
	pass := memguard.NewBufferFromBytes([]byte("pw"))
	defer pass.Destroy()
	dir := t.TempDir()
	seedBackup(t, sealer, pass, filepath.Join(dir, "a.age"), time.Now())

	if _, err := PruneBackups(context.Background(), dir, 0, sealer, pass); err == nil {
		t.Error("keep=0 must be rejected (never delete the whole chain)")
	}
	// A rejected prune must delete nothing.
	if got := listAgeNames(t, dir); len(got) != 1 {
		t.Fatalf("rejected prune must not delete: %v", got)
	}
}

func TestBackupPruneFailsClosedOnCorruptRetained(t *testing.T) {
	sealer := &sink.Age{WorkFactor: 10}
	pass := memguard.NewBufferFromBytes([]byte("pw"))
	defer pass.Destroy()

	dir := t.TempDir()
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	// 4 good newer backups + 1 older good one that we then corrupt.
	for i := 0; i < 5; i++ {
		name := base.Add(time.Duration(i) * time.Minute).Format("2006-01-02T15-04-05Z") + ".age"
		seedBackup(t, sealer, pass, filepath.Join(dir, name), base.Add(time.Duration(i)*time.Minute))
	}
	all := listAgeNames(t, dir) // oldest-first by sortable name
	// With keep=4, the oldest-retained is all[1]; corrupt it (preserving its
	// mtime so it keeps its position in the newest-first ordering).
	victim := filepath.Join(dir, all[1])
	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(victim, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(victim, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}

	if _, err := PruneBackups(context.Background(), dir, 4, sealer, pass); err == nil {
		t.Fatal("prune must fail closed when the oldest retained backup does not verify")
	}
	// Fail-closed: NOTHING deleted, chain intact.
	if got := listAgeNames(t, dir); len(got) != 5 {
		t.Fatalf("fail-closed prune must delete nothing, got %v", got)
	}
}

// listAgeNames returns the sorted .age filenames directly inside dir.
func listAgeNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".age" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}
