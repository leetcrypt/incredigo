// Command incredigo is a local-first, encrypted, RAM-only credential custody tool.
//
// v1 subcommands: scan, migrate, status, export, import.
// See DESIGN.md for the full architecture and threat model.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"incredigo/internal/audit"
	"incredigo/internal/blast"
	"incredigo/internal/discover"
	"incredigo/internal/policy"
	"incredigo/internal/rotate"
	"incredigo/internal/sink"
	"incredigo/internal/tui"
	"incredigo/internal/vault"
	"incredigo/internal/worklist"
)

var (
	flagSources  []string
	flagPaths    []string
	flagPrefix   string
	flagDedupe   bool
	flagForce    bool
	flagJSON     bool
	flagDryRun   bool
	flagAuditLog string
	flagConfig   string
	flagSealer   string
)

// exitError carries a process exit code out of a RunE. A meaningful non-zero code
// lets cron/CI react to a headless run without parsing text: 0 = clean/nothing to
// do, non-zero = manual items remain / action needed. When msg is empty the code
// is a normal, expected outcome (not a failure), so main() prints nothing.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(os.Stderr, "incredigo:", ee.msg)
			}
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "incredigo:", err)
		os.Exit(1)
	}
}

// newRootCmd builds the fully-wired root command. Extracted from main so tests can
// drive the real CLI (persistent flags + every subcommand) with SetArgs/Execute.
// Because the flag vars are package-level and pflag writes each default into its
// bound variable at registration, constructing a fresh root per call also resets
// flag state between test invocations.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "incredigo",
		Short:         "Local-first, encrypted, RAM-only credential custody",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "do not write anything")
	root.PersistentFlags().StringVar(&flagAuditLog, "audit-log", "", "append-only redacted audit log path")
	root.PersistentFlags().StringVar(&flagConfig, "config", "", "policy.yaml path")
	root.PersistentFlags().StringVar(&flagSealer, "sealer", "age", "backup sealer: age (default, authenticated), hmac (authenticated, openssl-only), or openssl (unauthenticated)")

	root.AddCommand(scanCmd(), migrateCmd(), statusCmd(), exportCmd(), importCmd(), rotateCmd(), worklistCmd(), guideCmd(), passwordsCmd())
	return root
}

// applyPaths registers any --path targets with the file scanner and, when an
// explicit --source filter is in play, makes sure "file" is included so --path
// just works alongside it.
func applyPaths() {
	for _, p := range flagPaths {
		discover.AddPath(p)
	}
	if len(flagPaths) == 0 || len(flagSources) == 0 {
		return
	}
	for _, s := range flagSources {
		if s == "file" {
			return
		}
	}
	flagSources = append(flagSources, "file")
}

// gopassCredsForExecute sources the credentials to rotate from gopass (Mode A).
// It lists the entries under prefix, loads each secret into the vault, and rebuilds
// a Credential whose Source is the path's first segment after the prefix
// (e.g. imported/postgres/labapp -> Source "postgres") so the right driver Detects
// it, and whose Location is the exact gopass path the new secret must overwrite.
//
// A "<entry>.pending" copy (left by an interrupted rotation, see rotate.Execute) is never a
// credential to rotate, and its primary entry is HELD BACK (returned in held) until a human
// reconciles the pair: the service may accept only the pending secret.
func gopassCredsForExecute(ctx context.Context, gp *sink.Gopass, v *vault.Vault, prefix string) (creds []discover.Credential, held []string, err error) {
	paths, err := gp.ListPaths(ctx, prefix)
	if err != nil {
		return nil, nil, err
	}
	pending := map[string]bool{}
	for _, p := range paths {
		if rotate.IsPendingPath(p) {
			pending[strings.TrimSuffix(p, rotate.PendingSuffix)] = true
		}
	}
	for _, p := range paths {
		if rotate.IsPendingPath(p) {
			continue
		}
		if pending[p] {
			held = append(held, p)
			continue
		}
		h, err := gp.Show(ctx, v, p)
		if err != nil {
			return nil, nil, err
		}
		creds = append(creds, discover.Credential{
			Source:   sourceFromStorePath(p, prefix),
			Identity: p,
			Location: p,
			Secret:   h,
		})
	}
	return creds, held, nil
}

// sourceFromStorePath recovers the scanner source from a gopass entry path:
// "<prefix>/<source>/<slug...>" -> "<source>".
func sourceFromStorePath(p, prefix string) string {
	rest := strings.TrimPrefix(p, strings.TrimSuffix(prefix, "/")+"/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// withVault sets up the RAM vault and guarantees it is purged on exit.
func withVault(fn func(ctx context.Context, v *vault.Vault) error) error {
	v := vault.New()
	defer v.Purge()
	return fn(context.Background(), v)
}

func scanCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "scan",
		Short: "Discover credentials (no secrets printed)",
		RunE: func(cmd *cobra.Command, args []string) error {
			applyPaths()
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				creds, err := discover.ScanAll(ctx, v, flagSources...)
				if err != nil {
					return err
				}
				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()
				w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
				fmt.Fprintln(w, "SOURCE\tKIND\tIDENTITY\tLOCATION")
				for _, cr := range creds {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", cr.Source, cr.Kind, cr.Identity, cr.Location)
					log.Write(audit.Entry{Action: "scan", Source: cr.Source,
						Kind: string(cr.Kind), Identity: cr.Identity, Location: cr.Location, Outcome: "ok"})
				}
				w.Flush()
				fmt.Fprintf(os.Stderr, "\n%d credential(s) found across %d source(s)\n",
					len(creds), countSources(creds))
				return nil
			})
		},
	}
	c.Flags().StringSliceVar(&flagSources, "source", nil, "limit to these scanners (comma-separated)")
	c.Flags().StringArrayVar(&flagPaths, "path", nil, "extra file or directory to harvest (repeatable)")
	c.Flags().BoolVar(&flagJSON, "json", false, "json output")
	return c
}

func migrateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate discovered credentials into gopass (plaintext never hits disk)",
		RunE: func(cmd *cobra.Command, args []string) error {
			applyPaths()
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				gp := &sink.Gopass{Prefix: flagPrefix}
				if !gp.Available() {
					return fmt.Errorf("gopass not found on PATH")
				}
				creds, err := discover.ScanAll(ctx, v, flagSources...)
				if err != nil {
					return err
				}
				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()

				var done, skipped int
				for _, cr := range creds {
					sp := gp.StorePath(cr)
					if flagDedupe && gp.Exists(ctx, sp) {
						skipped++
						fmt.Printf("skip  %s (exists)\n", sp)
						log.Write(audit.Entry{Action: "migrate", Source: cr.Source, Kind: string(cr.Kind),
							Identity: cr.Identity, Outcome: "skipped"})
						continue
					}
					if flagDryRun {
						fmt.Printf("would %s\n", sp)
						continue
					}
					if err := gp.Insert(ctx, v, cr, flagForce); err != nil {
						log.Write(audit.Entry{Action: "migrate", Source: cr.Source, Kind: string(cr.Kind),
							Identity: cr.Identity, Outcome: err.Error()})
						return err
					}
					done++
					fmt.Printf("store %s\n", sp)
					log.Write(audit.Entry{Action: "migrate", Source: cr.Source, Kind: string(cr.Kind),
						Identity: cr.Identity, Outcome: "ok"})
				}
				fmt.Fprintf(os.Stderr, "\nmigrated %d, skipped %d\n", done, skipped)
				return nil
			})
		},
	}
	c.Flags().StringSliceVar(&flagSources, "source", nil, "limit to these scanners")
	c.Flags().StringArrayVar(&flagPaths, "path", nil, "extra file or directory to harvest (repeatable)")
	c.Flags().StringVar(&flagPrefix, "prefix", "imported/", "gopass path prefix")
	c.Flags().BoolVar(&flagDedupe, "dedupe", false, "skip entries that already exist")
	c.Flags().BoolVar(&flagForce, "force", false, "overwrite existing entries")
	return c
}

func statusCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "status",
		Short: "Report credential age vs expiry policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			applyPaths()
			pol, err := policy.Load(flagConfig)
			if err != nil {
				return err
			}
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				creds, err := discover.ScanAll(ctx, v, flagSources...)
				if err != nil {
					return err
				}
				now := time.Now()

				// A credential the policy marks Warn or Stale is "action needed";
				// the exit code reports whether any exist so cron/CI can react.
				type statusRow struct {
					State    string `json:"state"`
					AgeDays  int    `json:"age_days"`
					Source   string `json:"source"`
					Kind     string `json:"kind"`
					Identity string `json:"identity"`
				}
				var rows []statusRow
				attention := 0
				for _, cr := range creds {
					st, age := pol.Evaluate(cr, now)
					if st == policy.Warn || st == policy.Stale {
						attention++
					}
					rows = append(rows, statusRow{
						State:    strings.ToUpper(string(st)),
						AgeDays:  int(age.Hours() / 24),
						Source:   cr.Source,
						Kind:     string(cr.Kind),
						Identity: cr.Identity,
					})
				}

				if flagJSON {
					b, err := json.MarshalIndent(rows, "", "  ")
					if err != nil {
						return err
					}
					fmt.Fprintln(os.Stdout, string(b))
				} else {
					w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
					fmt.Fprintln(w, "STATE\tAGE\tSOURCE\tIDENTITY")
					for _, r := range rows {
						fmt.Fprintf(w, "%s\t%dd\t%s\t%s\n", r.State, r.AgeDays, r.Source, r.Identity)
					}
					w.Flush()
				}

				// Exit-code contract: 0 = all credentials OK (nothing to do),
				// non-zero = at least one Warn/Stale credential needs attention.
				if attention > 0 {
					return &exitError{code: 2}
				}
				return nil
			})
		},
	}
	c.Flags().StringSliceVar(&flagSources, "source", nil, "limit to these scanners")
	c.Flags().StringArrayVar(&flagPaths, "path", nil, "extra file or directory to harvest (repeatable)")
	c.Flags().BoolVar(&flagJSON, "json", false, "emit machine-readable JSON (exit 0 = all OK, non-zero = Warn/Stale present)")
	return c
}

func exportCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "export",
		Short: "Write a sealed backup bundle of the gopass prefix",
		RunE: func(cmd *cobra.Command, args []string) error {
			gp := &sink.Gopass{Prefix: flagPrefix}
			if !gp.Available() {
				return fmt.Errorf("gopass not found on PATH")
			}
			sealer, err := sealerFor(flagSealer)
			if err != nil {
				return err
			}
			if flagDryRun {
				paths, err := gp.ListPaths(context.Background(), flagPrefix)
				if err != nil {
					return err
				}
				for _, p := range paths {
					fmt.Printf("would export %s\n", p)
				}
				fmt.Fprintf(os.Stderr, "\n%d entr(ies) under %q\n", len(paths), flagPrefix)
				return nil
			}

			f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("create %s (use a fresh path; export refuses to overwrite): %w", out, err)
			}
			defer f.Close()

			return withVault(func(ctx context.Context, v *vault.Vault) error {
				h, err := readPassphrase(v, true)
				if err != nil {
					return err
				}
				pass, err := v.Open(h)
				if err != nil {
					return err
				}

				// gopass show -> framed plaintext -> pipe -> Sealer -> file.
				pr, pw := io.Pipe()
				var n int
				go func() {
					var gerr error
					n, gerr = gp.ExportTo(ctx, pw, flagPrefix)
					pw.CloseWithError(gerr)
				}()
				if err := sealer.Seal(ctx, pr, f, pass); err != nil {
					return err
				}
				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()
				log.Write(audit.Entry{Action: "export", Outcome: "ok",
					Location: out, Source: sealer.Name()})
				fmt.Fprintf(os.Stderr, "sealed %d entr(ies) with %s -> %s\n", n, sealer.Name(), out)
				return nil
			})
		},
	}
	c.Flags().StringVar(&out, "out", "backup.incredigo.age", "output bundle path (refuses to overwrite)")
	c.Flags().StringVar(&flagPrefix, "prefix", "imported/", "gopass prefix to export")
	return c
}

func importCmd() *cobra.Command {
	var in string
	c := &cobra.Command{
		Use:   "import",
		Short: "Restore a sealed bundle into gopass",
		RunE: func(cmd *cobra.Command, args []string) error {
			gp := &sink.Gopass{Prefix: flagPrefix}
			if !gp.Available() {
				return fmt.Errorf("gopass not found on PATH")
			}
			sealer, err := sealerFor(flagSealer)
			if err != nil {
				return err
			}
			f, err := os.Open(in)
			if err != nil {
				return err
			}
			defer f.Close()

			return withVault(func(ctx context.Context, v *vault.Vault) error {
				h, err := readPassphrase(v, false)
				if err != nil {
					return err
				}
				pass, err := v.Open(h)
				if err != nil {
					return err
				}

				// file -> Sealer.Open -> pipe -> framed plaintext -> gopass insert.
				pr, pw := io.Pipe()
				go func() {
					pw.CloseWithError(sealer.Open(ctx, f, pw, pass))
				}()
				n, err := gp.ImportFrom(ctx, pr, flagForce)
				if err != nil {
					return err
				}
				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()
				log.Write(audit.Entry{Action: "import", Outcome: "ok",
					Location: in, Source: sealer.Name()})
				fmt.Fprintf(os.Stderr, "restored %d entr(ies) from %s\n", n, in)
				return nil
			})
		},
	}
	c.Flags().StringVar(&in, "in", "backup.incredigo.age", "input bundle path")
	c.Flags().BoolVar(&flagForce, "force", false, "overwrite existing gopass entries")
	return c
}

// rotateCmd is the rotation entry point. It always runs the mandatory verified
// backup gate first, then either plans (default), walks the spine with the noop
// driver (--dry-run), or performs REAL destructive rotation (--execute, gated by
// INCREDIGO_ALLOW_EXECUTE=1 and a registered driver whose proof ≥ LIVE-VM). With
// --stale only the credentials the expiry policy marks Warn/Stale are planned or
// rotated; --json emits machine-readable output with meaningful exit codes.
func rotateCmd() *cobra.Command {
	var prefix, backupOut, worklistOut string
	var backupKeep int
	var execute, dryRun, blastScan, allowMock, stale bool
	var blastRoots []string
	c := &cobra.Command{
		Use:   "rotate",
		Short: "Plan/execute rotation behind a MANDATORY verified backup gate",
		Long: "Runs the MANDATORY backup gate (sealed, verified snapshot of the gopass prefix)\n" +
			"first, then EITHER plans (default) or executes rotation.\n\n" +
			"Default: prints the rotation plan and changes nothing. With --dry-run it walks the\n" +
			"full spine (rotate→verify→revoke) using the noop driver, touching no service.\n\n" +
			"--execute performs REAL, destructive rotation of the gopass entries under --prefix\n" +
			"(rotate→verify→store→re-read→revoke). It is refused unless INCREDIGO_ALLOW_EXECUTE=1\n" +
			"is set and at least one driver is registered. Only drivers proven against real\n" +
			"target software (proof ≥ LIVE-VM) run; MOCK-ONLY drivers are skipped unless\n" +
			"--allow-mock-proven is passed. See docs/ROTATION.md §16.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if execute {
				// Real, destructive rotation. Gated by an explicit env authorization
				// on top of the flag (ROTATION.md §16), and refused if no driver can
				// actually perform a rotation.
				if os.Getenv("INCREDIGO_ALLOW_EXECUTE") != "1" {
					return fmt.Errorf("rotate --execute refused: set INCREDIGO_ALLOW_EXECUTE=1 to authorize real, destructive rotation (see docs/ROTATION.md §16)")
				}
				if len(rotate.Drivers()) == 0 {
					return fmt.Errorf("rotate --execute refused: no rotation drivers registered")
				}
			}
			applyPaths()
			// --stale filters the rotation set to only the credentials the expiry
			// policy marks Warn/Stale, so a headless run touches only aging ones.
			var pol policy.Policy
			if stale {
				var perr error
				if pol, perr = policy.Load(flagConfig); perr != nil {
					return perr
				}
			}
			gp := &sink.Gopass{Prefix: prefix}
			if !gp.Available() {
				return fmt.Errorf("gopass not found on PATH")
			}
			sealer, err := sealerFor(flagSealer)
			if err != nil {
				return err
			}
			// pruneDir is set only when we own the default rotation-backups
			// directory, so backup-chain turnover never prunes a user-supplied
			// --backup-out path (which may hold unrelated .age files).
			var pruneDir string
			if backupOut == "" {
				dir := filepath.Join(os.Getenv("HOME"), ".incredigo", "rotation-backups")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return err
				}
				backupOut = filepath.Join(dir, time.Now().UTC().Format("2006-01-02T15-04-05Z")+".age")
				pruneDir = dir
			}
			// A headless rotate always emits the remainder — the credentials a human
			// must still finish — as a secrets-free worklist under the incredigo state
			// dir (default ~/.incredigo/rotate-worklist.md), configurable via
			// --worklist-out. worklist.Markdown carries only non-secret metadata + links.
			if worklistOut == "" {
				stateDir := filepath.Join(os.Getenv("HOME"), ".incredigo")
				if err := os.MkdirAll(stateDir, 0o700); err != nil {
					return err
				}
				worklistOut = filepath.Join(stateDir, "rotate-worklist.md")
			}

			return withVault(func(ctx context.Context, v *vault.Vault) error {
				h, err := readPassphrase(v, true)
				if err != nil {
					return err
				}
				pass, err := v.Open(h)
				if err != nil {
					return err
				}

				// MANDATORY backup gate — rotation may never run without this.
				n, err := rotate.Snapshot(ctx, gp, prefix, sealer, pass, backupOut)
				if err != nil {
					return fmt.Errorf("backup gate failed — rotation would be blocked: %w", err)
				}
				fmt.Fprintf(os.Stderr, "✓ backup gate: %d entr(ies) sealed + verified -> %s\n\n", n, backupOut)

				// Backup-chain turnover — a sealed backup is itself credential
				// storage, so the chain must turn over. This runs ONLY after the
				// new verified backup above exists (the safety spine's ordering is
				// never reordered), and PruneBackups re-verifies the oldest backup
				// it keeps before removing anything (fails closed). A prune problem
				// must never undo a successful backup/rotation, so it is surfaced
				// loudly but does not abort.
				if pruneDir != "" && backupKeep > 0 {
					if pr, perr := rotate.PruneBackups(ctx, pruneDir, backupKeep, sealer, pass); perr != nil {
						fmt.Fprintf(os.Stderr, "⚠ backup turnover skipped (chain left intact): %v\n\n", perr)
					} else if len(pr.Deleted) > 0 {
						fmt.Fprintf(os.Stderr, "✓ backup turnover: kept %d, deleted %d old backup(s); oldest retained re-verified -> %s\n\n",
							len(pr.Kept), len(pr.Deleted), pr.VerifiedOldest)
					}
				}

				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()

				if execute {
					// Mode A — rotate what's already in gopass. Source the stored
					// entries under the prefix (the backup gate just proved coverage
					// of exactly these), then run the real rotate→verify→store→
					// re-read→revoke spine. Backup has already succeeded above.
					ecreds, held, err := gopassCredsForExecute(ctx, gp, v, prefix)
					if err != nil {
						return err
					}
					for _, p := range held {
						fmt.Fprintf(os.Stderr, "⚠ HELD BACK %s: an earlier rotation left %s%s — log in with each, keep the working secret at %s, delete the .pending entry, then re-run.\n",
							p, p, rotate.PendingSuffix, p)
					}
					if stale {
						// Rotate only the expiry-flagged subset. NOTE: gopass-sourced
						// entries carry no mtime yet, so undated entries evaluate as
						// aged (kept) — a safe superset, never fewer than the policy asks.
						ecreds = rotate.SelectStale(pol, ecreds, time.Now())
					}
					results := rotate.Execute(ctx, gp, ecreds, v, allowMock)
					ew := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
					fmt.Fprintln(ew, "DRIVER\tPROOF\tENTRY\tROTATED\tVERIFIED\tSTORED\tREVOKED\tERROR")
					var rotated, failed, skipped int
					for _, r := range results {
						errStr := ""
						outcome := "ok"
						switch {
						case r.Skipped:
							errStr = "SKIPPED: " + r.SkipReason
							outcome = errStr
							skipped++
						case r.Err != nil:
							errStr = r.Err.Error()
							outcome = errStr
							failed++
						default:
							rotated++
						}
						fmt.Fprintf(ew, "%s\t%s\t%s\t%t\t%t\t%t\t%t\t%s\n",
							r.Driver, rotate.ProofLevelOf(r.Driver).String(), r.StorePath, r.Rotated, r.Verified, r.Stored, r.Revoked, errStr)
						log.Write(audit.Entry{Action: "rotate-execute", Source: r.Credential.Source,
							Identity: r.StorePath, Location: backupOut, Outcome: outcome})
					}
					ew.Flush()
					fmt.Fprintf(os.Stderr, "\nROTATED %d credential(s), %d failed, %d skipped (proof gate). Backup: %s\n", rotated, failed, skipped, backupOut)
					// Emit the remainder a human must finish: every entry the proof gate
					// skipped or that failed to rotate. Secrets-free (only non-secret
					// metadata + links via internal/worklist).
					var remainder []discover.Credential
					for _, r := range results {
						if r.Skipped || r.Err != nil {
							remainder = append(remainder, r.Credential)
						}
					}
					if err := writeManualWorklist(worklist.Build(remainder), worklistOut); err != nil {
						return err
					}
					fmt.Fprintf(os.Stderr, "wrote rotation worklist (%d unrotated item(s), no secrets) -> %s\n", len(remainder), worklistOut)
					if skipped > 0 {
						fmt.Fprintf(os.Stderr, "%d credential(s) skipped: driver proof below %s. Re-run with --allow-mock-proven to rotate them anyway.\n",
							skipped, rotate.MinExecuteProof)
					}
					if failed > 0 {
						return fmt.Errorf("rotation completed with %d failure(s) — see ERROR above: where a NEW secret was kept at <entry>%s the old one may no longer work; otherwise the old credential was left in place", failed, rotate.PendingSuffix)
					}
					return nil
				}

				// Non-destructive plan over discoverable credentials.
				creds, err := discover.ScanAll(ctx, v, flagSources...)
				if err != nil {
					return err
				}
				if stale {
					// Keep only the credentials the expiry policy flags Warn/Stale.
					creds = rotate.SelectStale(pol, creds, time.Now())
				}
				// Optional read-only blast-radius map: which files consume each
				// credential (searched by non-secret markers only — never the secret).
				var radius []blast.CredConsumers
				if blastScan {
					radius, err = blast.Map(creds, blast.Options{Roots: blastRoots})
					if err != nil {
						return err
					}
				}

				plans := rotate.PlanAll(creds)

				// planRow is the JSON/human view of one planned credential. PROOF is how
				// the driver's real-cutover path was validated (LIVE-VM vs MOCK-ONLY),
				// surfaced so a mock-only driver can never be mistaken for a live one.
				type planRow struct {
					Driver   string `json:"driver"`
					Proof    string `json:"proof"`
					Source   string `json:"source"`
					Identity string `json:"identity"`
				}
				rows := make([]planRow, 0, len(plans))
				for _, p := range plans {
					drv, proof := p.Driver, "-"
					if drv == "" {
						drv = "(none)"
					} else {
						proof = rotate.ProofLevelOf(p.Driver).String()
					}
					rows = append(rows, planRow{Driver: drv, Proof: proof,
						Source: p.Credential.Source, Identity: p.Credential.Identity})
				}

				// Optional dry-run: exercise the FULL rotation spine with the noop
				// driver (mint→verify→"revoke", persists nothing, touches no service).
				type dryRow struct {
					Driver   string `json:"driver"`
					Identity string `json:"identity"`
					Rotated  bool   `json:"rotated"`
					Verified bool   `json:"verified"`
					Revoked  bool   `json:"revoked"`
					Error    string `json:"error,omitempty"`
				}
				var dryRows []dryRow
				if dryRun {
					for _, r := range rotate.DryRun(ctx, &rotate.NoopRotator{}, creds, v) {
						errStr := ""
						if r.Err != nil {
							errStr = r.Err.Error()
						}
						dryRows = append(dryRows, dryRow{Driver: r.Driver, Identity: r.Credential.Identity,
							Rotated: r.Rotated, Verified: r.Verified, Revoked: r.Revoked, Error: errStr})
					}
				}

				mode := "plan"
				if dryRun {
					mode = "dry-run"
				}

				if flagJSON {
					out := struct {
						Mode        string    `json:"mode"`
						Backup      string    `json:"backup"`
						Stale       bool      `json:"stale"`
						Credentials []planRow `json:"credentials"`
						DryRun      []dryRow  `json:"dry_run_results,omitempty"`
					}{Mode: mode, Backup: backupOut, Stale: stale, Credentials: rows, DryRun: dryRows}
					b, err := json.MarshalIndent(out, "", "  ")
					if err != nil {
						return err
					}
					fmt.Fprintln(os.Stdout, string(b))
				} else {
					w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
					if blastScan {
						fmt.Fprintln(w, "DRIVER\tPROOF\tSOURCE\tIDENTITY\tCONSUMERS")
					} else {
						fmt.Fprintln(w, "DRIVER\tPROOF\tSOURCE\tIDENTITY")
					}
					for i, r := range rows {
						if blastScan {
							fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d file(s)\n",
								r.Driver, r.Proof, r.Source, r.Identity, len(radius[i].Files()))
						} else {
							fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Driver, r.Proof, r.Source, r.Identity)
						}
					}
					w.Flush()

					if blastScan {
						fmt.Fprintln(os.Stderr, "\nblast radius (read-only; matched by non-secret markers):")
						for _, cc := range radius {
							files := cc.Files()
							if len(files) == 0 {
								continue
							}
							fmt.Fprintf(os.Stderr, "  %s  ->  %s\n", cc.Credential.Identity, strings.Join(files, ", "))
						}
					}

					if dryRun {
						fmt.Fprintln(os.Stderr, "\n--dry-run: walking rotate→verify→revoke with the noop driver (touches no service)")
						dw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
						fmt.Fprintln(dw, "DRIVER\tIDENTITY\tROTATED\tVERIFIED\tREVOKED\tERROR")
						for _, r := range dryRows {
							fmt.Fprintf(dw, "%s\t%s\t%t\t%t\t%t\t%s\n",
								r.Driver, r.Identity, r.Rotated, r.Verified, r.Revoked, r.Error)
						}
						dw.Flush()
					}
				}

				log.Write(audit.Entry{Action: "rotate-" + mode, Outcome: "ok", Location: backupOut})

				// After the automatable credentials are handled (walked through the
				// spine in --dry-run), emit the remainder — every credential with no
				// automated driver — as a secrets-free worklist a human can finish.
				manual := manualOnly(worklist.Build(creds))
				if err := writeManualWorklist(manual, worklistOut); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "wrote manual-rotation worklist (%d item(s), no secrets) -> %s\n", len(manual), worklistOut)

				if dryRun {
					fmt.Fprintf(os.Stderr, "\nDRY RUN complete: %d credential(s) walked, nothing persisted, no service touched.\n", len(dryRows))
				} else {
					fmt.Fprintf(os.Stderr, "\nPLAN ONLY: %d credential(s) planned — nothing rotated. Add --execute (with INCREDIGO_ALLOW_EXECUTE=1) to rotate. See docs/ROTATION.md\n",
						len(rows))
				}

				// Exit-code contract: 0 = nothing to do, non-zero = action needed
				// (credentials remain to be rotated) so cron/CI can react.
				if len(rows) > 0 {
					return &exitError{code: 2}
				}
				return nil
			})
		},
	}
	c.Flags().StringVar(&prefix, "prefix", "imported/", "gopass prefix to back up and plan")
	c.Flags().StringVar(&backupOut, "backup-out", "", "backup bundle path (default ~/.incredigo/rotation-backups/<ts>.age)")
	c.Flags().IntVar(&backupKeep, "backup-keep", 10, "keep only the newest N rotation backups after a successful snapshot (turnover; only applies to the default backup dir; <1 disables)")
	c.Flags().StringVar(&worklistOut, "worklist-out", "", "write the manual/unrotated remainder as a secrets-free worklist here (default ~/.incredigo/rotate-worklist.md)")
	c.Flags().BoolVar(&execute, "execute", false, "perform REAL destructive rotation — gated by INCREDIGO_ALLOW_EXECUTE=1 and a registered driver (proof ≥ LIVE-VM)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "walk the full rotation spine with the noop driver (touches no service, persists nothing)")
	c.Flags().BoolVar(&stale, "stale", false, "rotate/plan only credentials the expiry policy marks Warn/Stale")
	c.Flags().BoolVar(&flagJSON, "json", false, "emit machine-readable JSON for the plan/dry-run (exit 0 = nothing to do, non-zero = credentials remain)")
	c.Flags().BoolVar(&allowMock, "allow-mock-proven", false, "also execute drivers proven only against a mock/emulator (MOCK-ONLY); default skips them")
	c.Flags().BoolVar(&blastScan, "blast", false, "map each credential's blast radius — which files consume it (read-only, non-secret markers)")
	c.Flags().StringArrayVar(&blastRoots, "blast-root", nil, "directories to search for consumers (default: current directory)")
	c.Flags().StringArrayVar(&flagPaths, "path", nil, "extra file or directory to include in the plan")
	c.Flags().StringSliceVar(&flagSources, "source", nil, "limit discovery to these scanners")
	return c
}

// worklistCmd emits a rotation worklist (links per credential, no secrets). It is
// read-only, offline, and rotates nothing.
func worklistCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "worklist",
		Short: "Generate a rotation worklist with per-credential change-password links (no secrets)",
		RunE: func(cmd *cobra.Command, args []string) error {
			applyPaths()
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				creds, err := discover.ScanAll(ctx, v, flagSources...)
				if err != nil {
					return err
				}
				md := worklist.Markdown(worklist.Build(creds))
				if out == "" {
					fmt.Print(md)
					return nil
				}
				if err := os.WriteFile(out, []byte(md), 0o644); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "wrote worklist (%d credential(s)) -> %s\n", len(creds), out)
				return nil
			})
		},
	}
	c.Flags().StringVar(&out, "out", "", "write the worklist to this file (default: stdout)")
	c.Flags().StringArrayVar(&flagPaths, "path", nil, "extra file or directory to include")
	c.Flags().StringSliceVar(&flagSources, "source", nil, "limit discovery to these scanners")
	return c
}

// guideCmd launches the interactive guided-rotation walk-through (TUI). It is
// read-only guidance: it shows each credential and its rotation link and can open
// it, but enters/stores/rotates no secret.
func guideCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "guide",
		Short: "Interactive walk-through of credentials to rotate manually (rotates nothing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			applyPaths()
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				creds, err := discover.ScanAll(ctx, v, flagSources...)
				if err != nil {
					return err
				}
				return tui.Run(worklist.Build(creds))
			})
		},
	}
	c.Flags().StringArrayVar(&flagPaths, "path", nil, "extra file or directory to include")
	c.Flags().StringSliceVar(&flagSources, "source", nil, "limit discovery to these scanners")
	return c
}

// sealerFor selects the backup sealer. age is the authenticated default; openssl
// is an unauthenticated fallback (see internal/sink/openssl.go).
func sealerFor(name string) (sink.Sealer, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "age":
		return &sink.Age{}, nil
	case "hmac":
		return &sink.HMACSealer{}, nil
	case "openssl":
		return &sink.OpenSSL{}, nil
	default:
		return nil, fmt.Errorf("unknown sealer %q (want: age, hmac, openssl)", name)
	}
}

// readPassphrase obtains a backup passphrase into the locked vault and returns its
// handle. Sources, in order: $INCREDIGO_PASSPHRASE (automation), an interactive
// no-echo TTY prompt, or one line from non-terminal stdin (piped). On a TTY,
// confirm re-prompts to guard against typos in a backup passphrase.
func readPassphrase(v *vault.Vault, confirm bool) (*vault.Handle, error) {
	if env, ok := os.LookupEnv("INCREDIGO_PASSPHRASE"); ok {
		if env == "" {
			return nil, fmt.Errorf("INCREDIGO_PASSPHRASE is set but empty")
		}
		return v.Store([]byte(env)), nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// piped stdin: read a single line as the passphrase
		line, err := readLine(os.Stdin)
		if err != nil {
			return nil, err
		}
		if len(line) == 0 {
			return nil, fmt.Errorf("empty passphrase on stdin")
		}
		return v.Store(line), nil
	}

	fmt.Fprint(os.Stderr, "Passphrase: ")
	pw1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pw1) == 0 {
		return nil, fmt.Errorf("empty passphrase")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		pw2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			wipe(pw1)
			return nil, err
		}
		eq := bytes.Equal(pw1, pw2)
		wipe(pw2)
		if !eq {
			wipe(pw1)
			return nil, fmt.Errorf("passphrases do not match")
		}
	}
	return v.Store(pw1), nil // Store wipes pw1
}

// readLine reads bytes up to (not including) the first newline.
func readLine(r io.Reader) ([]byte, error) {
	var out []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				return out, nil
			}
			out = append(out, b[0])
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// manualOnly keeps just the worklist items with no automated rotation driver — the
// credentials a human must rotate by hand.
func manualOnly(items []worklist.Item) []worklist.Item {
	m := make([]worklist.Item, 0, len(items))
	for _, it := range items {
		if it.Manual() {
			m = append(m, it)
		}
	}
	return m
}

// writeManualWorklist writes a secrets-free rotation worklist to out. worklist.Markdown
// carries only non-secret metadata + change-password links, so the file never contains
// a secret — this is the automatable-creds-handled remainder for a human to finish.
func writeManualWorklist(items []worklist.Item, out string) error {
	return os.WriteFile(out, []byte(worklist.Markdown(items)), 0o644)
}

func countSources(creds []discover.Credential) int {
	seen := map[string]struct{}{}
	for _, c := range creds {
		seen[c.Source] = struct{}{}
	}
	return len(seen)
}
