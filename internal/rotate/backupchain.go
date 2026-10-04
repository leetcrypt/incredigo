package rotate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"incredigo/internal/sink"
)

// backupExt is the on-disk suffix every sealed rotation backup carries. The
// mandatory backup gate writes bundles as `<ts>.age` under
// ~/.incredigo/rotation-backups/ (see cmd/incredigo/main.go). Prune ONLY ever
// considers files with this suffix, so anything else living in the directory
// (a README, a partially-written temp file, a subdirectory) is never touched.
const backupExt = ".age"

// PruneResult reports what a prune did, for logging / audit trails. Paths are
// absolute and ordered newest-first.
type PruneResult struct {
	Kept           []string // backups retained
	Deleted        []string // backups removed
	VerifiedOldest string   // the oldest retained backup, proven to still open+authenticate (empty if nothing was deleted)
}

// PruneBackups enforces backup-chain turnover: it keeps the newest `keep`
// sealed backups in dir and deletes the older ones. It is a pure function over
// a directory path + keep count — it never launches a rotation, never mutates a
// repo, and only ever removes *.age files that live directly inside dir.
//
// Safety invariant (NEVER weakened): a sealed backup is itself credential
// storage AND the mandatory pre-rotation restore point, so the retained chain
// must never be left unreadable. PruneBackups therefore VERIFIES that the
// oldest backup it intends to KEEP still opens and authenticates *before it
// deletes anything*, and fails closed — on a verification failure it deletes
// nothing and returns an error. Removing older sibling files cannot affect a
// retained file's readability, so verifying before deletion proves exactly the
// same post-prune property ("the oldest retained backup still verifies") while
// being strictly safer: a corrupt retained backup can never trigger data loss.
//
// Ordering is by modification time (newest first), tie-broken by filename
// descending — which also matches the sortable `<ts>.age` timestamp naming.
func PruneBackups(ctx context.Context, dir string, keep int, sealer sink.Sealer, pass *memguard.LockedBuffer) (PruneResult, error) {
	var res PruneResult
	if keep < 1 {
		return res, fmt.Errorf("backup prune: keep must be >= 1, got %d (refusing to delete the whole chain)", keep)
	}
	if sealer == nil || pass == nil {
		return res, fmt.Errorf("backup prune: a sealer and passphrase are required to verify the retained chain")
	}

	backups, err := listBackups(dir)
	if err != nil {
		return res, err
	}

	if len(backups) <= keep {
		// Nothing older than the keep window — retain everything, delete nothing.
		for _, b := range backups {
			res.Kept = append(res.Kept, b.path)
		}
		return res, nil
	}

	res.Kept = make([]string, 0, keep)
	for _, b := range backups[:keep] {
		res.Kept = append(res.Kept, b.path)
	}
	toDelete := backups[keep:]

	// Verify the oldest backup we intend to keep BEFORE touching the chain.
	oldestRetained := res.Kept[len(res.Kept)-1]
	if _, err := verifyBundle(ctx, sealer, pass, oldestRetained); err != nil {
		return PruneResult{}, fmt.Errorf("backup prune: oldest retained backup %s failed verification — deleting NOTHING to keep the chain restorable: %w", oldestRetained, err)
	}
	res.VerifiedOldest = oldestRetained

	// Verified restorable — now it is safe to remove the older backups.
	for _, b := range toDelete {
		if err := os.Remove(b.path); err != nil {
			return res, fmt.Errorf("backup prune: remove %s: %w", b.path, err)
		}
		res.Deleted = append(res.Deleted, b.path)
	}
	return res, nil
}

// backupFile is one candidate sealed backup on disk.
type backupFile struct {
	path    string
	name    string
	modTime time.Time
}

// listBackups returns the sealed backups directly inside dir (*.age, files
// only), sorted newest-first. Non-.age files and subdirectories are ignored so
// prune can never remove anything but a backup bundle.
func listBackups(dir string) ([]backupFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("backup prune: read dir %s: %w", dir, err)
	}
	var out []backupFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, backupExt) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("backup prune: stat %s: %w", name, err)
		}
		out = append(out, backupFile{
			path:    filepath.Join(dir, name),
			name:    name,
			modTime: info.ModTime(),
		})
	}
	// Newest first: modtime descending, tie-broken by name descending so the
	// order is deterministic even when mtimes collide.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].modTime.Equal(out[j].modTime) {
			return out[i].modTime.After(out[j].modTime)
		}
		return out[i].name > out[j].name
	})
	return out, nil
}
