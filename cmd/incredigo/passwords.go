package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/awnumar/memguard"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"incredigo/internal/audit"
	"incredigo/internal/links"
	"incredigo/internal/pwgen"
	"incredigo/internal/pwstore"
	"incredigo/internal/sink"
	"incredigo/internal/vault"
)

// Phase-B "passwords" command group — the browser / password-manager propagation
// engine (docs/BROWSER-ROTATION.md). It does every safe, deterministic step
// (ingest → mandatory backup → generate → stage) and hands the human a ready-to-finish
// task at the MFA wall; only AFTER the human confirms the site accepted the new
// password does it commit the new value back into the manager. It never bypasses MFA.
var (
	flagPwManager    string
	flagAllowCSV     bool
	flagExportPath   string
	flagKdbxPath     string
	flagPassPrefix   string
	flagPwLength     int
	flagExcludeAmbig bool
	flagSymbolSet    string
	flagBackupOut    string
	flagStageOut     string
	flagStageIn      string
	flagWorklistOut  string
	flagVerified     string
)

func passwordsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "passwords",
		Short: "Rotate browser / password-manager logins (Phase B propagation engine)",
		Long: "Propagate new passwords into a password manager or browser store, safely.\n\n" +
			"Flow: ingest the store -> MANDATORY verified sealed backup -> generate fresh strong\n" +
			"passwords -> guided handoff (you change the site + complete MFA) -> commit the new\n" +
			"value into the manager ONLY after you confirm the site accepted it. MFA/CAPTCHA are\n" +
			"always your job; incredigo never bypasses them.\n\n" +
			"--manager selects the backend:\n" +
			"  in-place (CLI, no plaintext file): bitwarden | 1password | keepassxc |\n" +
			"     pass | gopass | keychain(macOS)\n" +
			"  CSV import/export (tmpfs + shred, needs --allow-csv + --export-path):\n" +
			"     chrome | firefox | edge | brave | safari | lastpass | dashlane |\n" +
			"     protonpass | nordpass | roboform | enpass(read-only)\n" +
			"CLI managers update one item in place over stdin (no plaintext file). CSV stores can\n" +
			"only be re-imported via a CSV, so they require --allow-csv (the file is written to\n" +
			"tmpfs and securely shredded after you confirm re-import).",
	}
	pf := c.PersistentFlags()
	pf.StringVar(&flagPwManager, "manager", "", "backend: bitwarden|1password|keepassxc|pass|gopass|keychain|chrome|firefox|edge|brave|safari|lastpass|dashlane|protonpass|nordpass|roboform|enpass")
	pf.BoolVar(&flagAllowCSV, "allow-csv", false, "allow the flag-gated browser/manager-CSV plaintext path (tmpfs + shred)")
	pf.StringVar(&flagExportPath, "export-path", "", "CSV managers: the CSV you exported from the browser/manager")
	pf.StringVar(&flagKdbxPath, "kdbx", "", "keepassxc: path to the .kdbx database")
	pf.StringVar(&flagPassPrefix, "pass-prefix", "", "pass/gopass: only rotate entries under this subtree (e.g. logins/)")
	c.AddCommand(pwScanCmd(), pwPlanCmd(), pwGuideCmd(), pwCommitCmd())
	return c
}

// buildManager constructs a configured adapter from the flags. Unlike the registry
// singletons (which are zero-valued), these carry the per-run paths/keys the command
// needs. KeePassXC's database passphrase is loaded into the vault from
// $INCREDIGO_KDBX_PASSPHRASE or a no-echo prompt.
func buildManager(v *vault.Vault) (pwstore.Manager, error) {
	switch strings.ToLower(strings.TrimSpace(flagPwManager)) {
	case "bitwarden":
		return &pwstore.Bitwarden{}, nil
	case "1password", "onepassword", "op":
		return &pwstore.OnePassword{}, nil
	case "keepassxc":
		if flagKdbxPath == "" {
			return nil, fmt.Errorf("keepassxc requires --kdbx <database.kdbx>")
		}
		k := &pwstore.KeePassXC{DBPath: flagKdbxPath}
		if env, ok := os.LookupEnv("INCREDIGO_KDBX_PASSPHRASE"); ok {
			if env == "" {
				return nil, fmt.Errorf("INCREDIGO_KDBX_PASSPHRASE is set but empty")
			}
			k.DBKey = v.Store([]byte(env))
		} else {
			h, err := promptSecret(v, "KeePassXC database passphrase: ")
			if err != nil {
				return nil, err
			}
			k.DBKey = h
		}
		return k, nil
	case "chrome":
		if flagExportPath == "" {
			return nil, fmt.Errorf("chrome requires --export-path <csv> (export from chrome://password-manager/settings)")
		}
		return &pwstore.ChromeCSV{ExportPath: flagExportPath}, nil
	case "firefox":
		if flagExportPath == "" {
			return nil, fmt.Errorf("firefox requires --export-path <csv> (export from about:logins)")
		}
		return &pwstore.FirefoxCSV{ExportPath: flagExportPath}, nil
	case "pass", "gopass":
		return &pwstore.PassStore{Flavor: strings.ToLower(strings.TrimSpace(flagPwManager)), Prefix: flagPassPrefix}, nil
	case "keychain":
		return &pwstore.Keychain{}, nil
	case "":
		return nil, fmt.Errorf("--manager is required (bitwarden|1password|keepassxc|chrome|firefox|pass|gopass|keychain|lastpass|dashlane|protonpass|nordpass|roboform|safari|edge|brave|enpass)")
	default:
		// CSV-based managers (lastpass, dashlane, protonpass, nordpass, roboform, safari,
		// edge, brave, enpass) all share the generic csvManager + tmpfs/shred staging.
		name := strings.ToLower(strings.TrimSpace(flagPwManager))
		if pwstore.IsCSV(name) {
			if flagExportPath == "" {
				return nil, fmt.Errorf("%s requires --export-path <csv> exported from %s", name, name)
			}
			return pwstore.NewCSV(name, flagExportPath)
		}
		return nil, fmt.Errorf("unknown --manager %q", flagPwManager)
	}
}

func pwPolicyFromFlags() pwgen.Policy {
	p := pwgen.DefaultPolicy()
	if flagPwLength > 0 {
		p.Length = flagPwLength
	}
	p.ExcludeAmbiguous = flagExcludeAmbig
	if flagSymbolSet != "" {
		p.Symbols = true
		p.SymbolSet = flagSymbolSet
	}
	return p
}

func addGenFlags(c *cobra.Command) {
	c.Flags().IntVar(&flagPwLength, "length", 0, "generated password length (default 20)")
	c.Flags().BoolVar(&flagExcludeAmbig, "exclude-ambiguous", false, "drop O/0/l/1/I (easier to hand-retype)")
	c.Flags().StringVar(&flagSymbolSet, "symbols", "", "override the symbol set (some sites reject specific symbols)")
}

// linkLabel renders an account's change-password URL (offline), or a clear note when
// no rotation page can be derived.
func linkLabel(a pwstore.Account) string {
	host := a.Site
	if host == "" {
		host = a.URL
	}
	l := links.For(host)
	if l.Source == links.SourceNone {
		return "(no rotation page known — change it in the account's settings)"
	}
	return l.URL
}

// ---- scan ----

func pwScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Count logins in the selected manager (no secrets, commits nothing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				m, err := buildManager(v)
				if err != nil {
					return err
				}
				if !m.Available() {
					return fmt.Errorf("%s backend not available (CLI not installed or export not found)", m.Name())
				}
				accts, err := m.Export(ctx, v)
				if err != nil {
					return err
				}
				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()
				w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
				fmt.Fprintln(w, "#\tIDENTITY\tCHANGE-PASSWORD LINK")
				for i, a := range accts {
					fmt.Fprintf(w, "%d\t%s\t%s\n", i+1, pwstore.RedactIdentity(a), linkLabel(a))
					log.Write(audit.Entry{Action: "pw-scan", Source: m.Name(),
						Identity: pwstore.RedactIdentity(a), Outcome: "ok"})
				}
				w.Flush()
				fmt.Fprintf(os.Stderr, "\n%s: %d login(s)\n", m.Name(), len(accts))
				return nil
			})
		},
	}
}

// ---- plan ----

func pwPlanCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "plan",
		Short: "Ingest + verified backup + generate staged new passwords + secrets-free worklist",
		Long: "Non-interactive preparation: reads the store, runs the MANDATORY verified sealed\n" +
			"backup, generates a fresh strong password per account, seals that staged list (--stage-out,\n" +
			"age-encrypted, never plaintext), and writes a SECRETS-FREE worklist (site, masked user,\n" +
			"change link, status). Commits nothing. Finish with `passwords commit --stage-in <file>`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				m, err := buildManager(v)
				if err != nil {
					return err
				}
				if !m.Available() {
					return fmt.Errorf("%s backend not available", m.Name())
				}
				sealer, err := sealerFor(flagSealer)
				if err != nil {
					return err
				}
				accts, err := m.Export(ctx, v)
				if err != nil {
					return err
				}
				if len(accts) == 0 {
					return fmt.Errorf("%s: no logins to plan", m.Name())
				}

				h, err := readPassphrase(v, true)
				if err != nil {
					return err
				}
				pass, err := v.Open(h)
				if err != nil {
					return err
				}

				backupOut := flagBackupOut
				if backupOut == "" {
					backupOut, err = defaultBundlePath("pw-backups")
					if err != nil {
						return err
					}
				}
				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()

				// MANDATORY backup gate — no staging proceeds without a verified backup.
				n, err := pwBackupGate(ctx, m, v, accts, sealer, pass, backupOut)
				if err != nil {
					return fmt.Errorf("backup gate failed — planning blocked: %w", err)
				}
				log.Write(audit.Entry{Action: "pw-export", Source: m.Name(), Location: backupOut, Outcome: "ok"})
				fmt.Fprintf(os.Stderr, "✓ backup gate: %d login(s) sealed + verified -> %s\n", n, backupOut)

				// Generate fresh passwords into the vault.
				policy := pwPolicyFromFlags()
				newPw := map[int]*vault.Handle{}
				for i := range accts {
					nh, err := pwgen.Generate(v, policy)
					if err != nil {
						return fmt.Errorf("generate new password: %w", err)
					}
					newPw[i] = nh
				}

				// Seal the staged NEW-password list (encrypted; never plaintext on disk).
				stageOut := flagStageOut
				if stageOut == "" {
					stageOut, err = defaultBundlePath("pw-stage")
					if err != nil {
						return err
					}
				}
				if err := pwSealStaged(ctx, v, accts, newPw, sealer, pass, stageOut); err != nil {
					return err
				}
				log.Write(audit.Entry{Action: "pw-stage", Source: m.Name(), Location: stageOut, Outcome: "ok"})

				// Secrets-free worklist.
				wl := renderPwWorklist(m.Name(), accts)
				if flagWorklistOut == "" {
					fmt.Print(wl)
				} else if err := os.WriteFile(flagWorklistOut, []byte(wl), 0o644); err != nil {
					return err
				}

				fmt.Fprintf(os.Stderr, "\nStaged %d new password(s) -> %s\n", len(accts), stageOut)
				fmt.Fprintf(os.Stderr, "Backup: %s\nWorklist: %s\n", backupOut, worklistDest())
				fmt.Fprintf(os.Stderr, "Next: change each site (complete MFA), then\n  incredigo passwords commit --manager %s --stage-in %s --verified <1,2,…|all>\n",
					m.Name(), stageOut)
				return nil
			})
		},
	}
	addGenFlags(c)
	c.Flags().StringVar(&flagBackupOut, "backup-out", "", "backup bundle path (default ~/.incredigo/pw-backups/<ts>.age)")
	c.Flags().StringVar(&flagStageOut, "stage-out", "", "sealed staged-list path (default ~/.incredigo/pw-stage/<ts>.age)")
	c.Flags().StringVar(&flagWorklistOut, "worklist-out", "", "write the secrets-free worklist here (default: stdout)")
	return c
}

// ---- guide ----

func pwGuideCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "guide",
		Short: "Interactive: per account → link + reveal new password + MFA handoff → commit",
		Long: "Single-session interactive walk-through. For each login it shows the change-password\n" +
			"link, reveals the new password on request, and waits for you to confirm the site\n" +
			"accepted it (after you complete MFA) BEFORE committing the new value into the manager.\n" +
			"If you cannot confirm, it keeps the old value and flags the account needs-human.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("guide is interactive and needs a TTY; for headless use `passwords plan` then `passwords commit`")
			}
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				m, err := buildManager(v)
				if err != nil {
					return err
				}
				if !m.Available() {
					return fmt.Errorf("%s backend not available", m.Name())
				}
				sealer, err := sealerFor(flagSealer)
				if err != nil {
					return err
				}
				accts, err := m.Export(ctx, v)
				if err != nil {
					return err
				}
				if len(accts) == 0 {
					return fmt.Errorf("%s: no logins to rotate", m.Name())
				}

				h, err := readPassphrase(v, true)
				if err != nil {
					return err
				}
				pass, err := v.Open(h)
				if err != nil {
					return err
				}
				backupOut := flagBackupOut
				if backupOut == "" {
					backupOut, err = defaultBundlePath("pw-backups")
					if err != nil {
						return err
					}
				}
				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()

				n, err := pwBackupGate(ctx, m, v, accts, sealer, pass, backupOut)
				if err != nil {
					return fmt.Errorf("backup gate failed — rotation blocked: %w", err)
				}
				fmt.Fprintf(os.Stderr, "✓ backup gate: %d login(s) sealed + verified -> %s\n", n, backupOut)

				policy := pwPolicyFromFlags()
				newPw := map[int]*vault.Handle{}
				for i := range accts {
					nh, err := pwgen.Generate(v, policy)
					if err != nil {
						return err
					}
					newPw[i] = nh
				}

				in := bufio.NewScanner(os.Stdin)
				iu, isIU := m.(pwstore.ItemUpdater)
				var csvVerified []int
				committed := 0

				for i, a := range accts {
					fmt.Printf("\n[%d/%d] %s\n", i+1, len(accts), pwstore.RedactIdentity(a))
					fmt.Printf("  change-password: %s\n", linkLabel(a))
					if ask(in, "  Reveal the new password to type into the site? [y/N] ") {
						buf, err := v.Open(newPw[i])
						if err != nil {
							return err
						}
						fmt.Printf("  NEW PASSWORD: %s\n", buf.Bytes())
					}
					if !ask(in, "  Did the site accept the new password (MFA complete)? [y/N] ") {
						fmt.Println("  → kept old value, flagged needs-human")
						log.Write(audit.Entry{Action: "pw-commit", Source: m.Name(),
							Identity: pwstore.RedactIdentity(a), Outcome: "skipped (needs-human)"})
						continue
					}
					if isIU {
						if err := iu.UpdatePassword(ctx, v, a, newPw[i]); err != nil {
							fmt.Printf("  ✗ commit failed: %v (old value left intact)\n", err)
							log.Write(audit.Entry{Action: "pw-commit", Source: m.Name(),
								Identity: pwstore.RedactIdentity(a), Outcome: err.Error()})
							continue
						}
						committed++
						fmt.Println("  ✓ committed in place")
						log.Write(audit.Entry{Action: "pw-commit", Source: m.Name(),
							Identity: pwstore.RedactIdentity(a), Outcome: "ok"})
					} else {
						csvVerified = append(csvVerified, i)
						committed++
						fmt.Println("  ✓ marked for CSV re-import")
					}
				}

				if !isIU && len(csvVerified) > 0 {
					if err := pwCSVReimport(ctx, m, v, accts, newPw, csvVerified, in, log); err != nil {
						return err
					}
				}
				fmt.Fprintf(os.Stderr, "\nGuide complete: %d committed, backup %s\n", committed, backupOut)
				return nil
			})
		},
	}
	addGenFlags(c)
	c.Flags().StringVar(&flagBackupOut, "backup-out", "", "backup bundle path (default ~/.incredigo/pw-backups/<ts>.age)")
	return c
}

// ---- commit ----

func pwCommitCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "commit",
		Short: "Headless: commit verified staged new passwords into the manager",
		Long: "Opens a sealed staged list (from `passwords plan`), runs the MANDATORY verified\n" +
			"backup of the CURRENT store, and commits the new password for the accounts you mark\n" +
			"--verified (1-based indices from the worklist, or 'all'). CLI managers update in place;\n" +
			"chrome/firefox re-import a tmpfs CSV (requires --allow-csv) which is shredded after.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if flagStageIn == "" {
				return fmt.Errorf("--stage-in <sealed staged list from `passwords plan`> is required")
			}
			if strings.TrimSpace(flagVerified) == "" {
				return fmt.Errorf("--verified <1,2,…|all> is required (only accounts you confirmed the site accepted)")
			}
			return withVault(func(ctx context.Context, v *vault.Vault) error {
				m, err := buildManager(v)
				if err != nil {
					return err
				}
				if !m.Available() {
					return fmt.Errorf("%s backend not available", m.Name())
				}
				sealer, err := sealerFor(flagSealer)
				if err != nil {
					return err
				}
				h, err := readPassphrase(v, false)
				if err != nil {
					return err
				}
				pass, err := v.Open(h)
				if err != nil {
					return err
				}

				// Mandatory backup of the CURRENT store before any commit (rule 1).
				cur, err := m.Export(ctx, v)
				if err != nil {
					return err
				}
				backupOut := flagBackupOut
				if backupOut == "" {
					backupOut, err = defaultBundlePath("pw-backups")
					if err != nil {
						return err
					}
				}
				log, _ := audit.Open(flagAuditLog, time.Now)
				defer log.Close()
				n, err := pwBackupGate(ctx, m, v, cur, sealer, pass, backupOut)
				if err != nil {
					return fmt.Errorf("backup gate failed — commit blocked: %w", err)
				}
				fmt.Fprintf(os.Stderr, "✓ backup gate: %d login(s) sealed + verified -> %s\n", n, backupOut)

				// Load the staged NEW-password list (Secret = new password).
				staged, err := pwOpenStaged(ctx, v, sealer, pass, flagStageIn)
				if err != nil {
					return err
				}
				idxs, err := parseVerified(flagVerified, len(staged))
				if err != nil {
					return err
				}

				if iu, ok := m.(pwstore.ItemUpdater); ok {
					committed, failed := 0, 0
					for _, i := range idxs {
						a := staged[i]
						if a.ID == "" {
							fmt.Printf("skip #%d %s — staged record has no item id\n", i+1, pwstore.RedactIdentity(a))
							continue
						}
						if err := iu.UpdatePassword(ctx, v, a, a.Secret); err != nil {
							failed++
							fmt.Printf("✗ #%d %s: %v\n", i+1, pwstore.RedactIdentity(a), err)
							log.Write(audit.Entry{Action: "pw-commit", Source: m.Name(),
								Identity: pwstore.RedactIdentity(a), Outcome: err.Error()})
							continue
						}
						committed++
						fmt.Printf("✓ #%d %s committed\n", i+1, pwstore.RedactIdentity(a))
						log.Write(audit.Entry{Action: "pw-commit", Source: m.Name(),
							Identity: pwstore.RedactIdentity(a), Outcome: "ok"})
					}
					fmt.Fprintf(os.Stderr, "\nCommitted %d, failed %d. Backup: %s\n", committed, failed, backupOut)
					if failed > 0 {
						return fmt.Errorf("%d commit(s) failed — restore from backup if needed", failed)
					}
					return nil
				}

				// Browser CSV manager: re-import a subset via tmpfs CSV + shred.
				si, ok := m.(pwstore.StagedImporter)
				if !ok {
					return fmt.Errorf("%s supports neither in-place update nor CSV import", m.Name())
				}
				if !flagAllowCSV {
					return fmt.Errorf("%s commit writes a plaintext CSV to tmpfs for the browser to re-read; pass --allow-csv to authorize (it is shredded after)", m.Name())
				}
				sub := make([]pwstore.Account, 0, len(idxs))
				for _, i := range idxs {
					sub = append(sub, staged[i])
				}
				path, cleanup, err := si.ImportStaged(v, sub, nil) // Secret already holds the new password
				if err != nil {
					return err
				}
				defer cleanup()
				log.Write(audit.Entry{Action: "pw-import", Source: m.Name(), Location: path,
					Outcome: fmt.Sprintf("staged %d account(s); plaintext CSV on tmpfs, will shred", len(sub))})
				where := "Re-import this CSV into the browser/manager"
				if r, ok := m.(pwstore.Reimporter); ok {
					if h := r.ReimportHint(); h != "" {
						where = h
					}
				}
				fmt.Printf("%s, then press Enter to shred it:\n  %s\n", where, path)
				if term.IsTerminal(int(os.Stdin.Fd())) {
					in := bufio.NewScanner(os.Stdin)
					in.Scan()
				}
				fmt.Fprintf(os.Stderr, "shredded %s\n", path)
				return nil
			})
		},
	}
	c.Flags().StringVar(&flagStageIn, "stage-in", "", "sealed staged list produced by `passwords plan`")
	c.Flags().StringVar(&flagVerified, "verified", "", "1-based indices to commit (e.g. 1,3,5) or 'all'")
	c.Flags().StringVar(&flagBackupOut, "backup-out", "", "backup bundle path (default ~/.incredigo/pw-backups/<ts>.age)")
	return c
}

// ---- shared helpers ----

// pwBackupGate seals the current store (old passwords) and verifies it round-trips,
// mirroring rotate.Snapshot for the password-manager path. No commit may proceed
// without this returning successfully (hard rule 1).
func pwBackupGate(ctx context.Context, m pwstore.Manager, v *vault.Vault, accts []pwstore.Account, sealer sink.Sealer, pass *memguard.LockedBuffer, out string) (int, error) {
	if len(accts) == 0 {
		return 0, fmt.Errorf("store is empty — nothing to back up")
	}
	if err := pwSealStaged(ctx, v, accts, nil, sealer, pass, out); err != nil { // nil newPw = current passwords
		return 0, err
	}
	// Verify: open + decrypt + parse + count must match. Read back into the SAME vault
	// (its handles are purged with the command); a throwaway vault must NOT be used here
	// because vault.Purge calls the process-global memguard.Purge, which would destroy
	// `pass` and every other live secret mid-run.
	got, err := pwOpenStaged(ctx, v, sealer, pass, out)
	if err != nil {
		return 0, fmt.Errorf("backup verify failed to reopen bundle: %w", err)
	}
	if len(got) != len(accts) {
		return 0, fmt.Errorf("backup verify mismatch: sealed %d, read back %d", len(accts), len(got))
	}
	return len(accts), nil
}

// pwSealStaged streams accts (with newPw substituted where present) through the Sealer
// into a fresh, refuse-to-overwrite file. The plaintext exists only inside the Sealer's
// encryption; nothing cleartext lands on disk.
func pwSealStaged(ctx context.Context, v *vault.Vault, accts []pwstore.Account, newPw map[int]*vault.Handle, sealer sink.Sealer, pass *memguard.LockedBuffer, out string) error {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s (use a fresh path; refuses to overwrite): %w", out, err)
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(pwstore.WriteStaged(pw, v, accts, newPw)) }()
	if err := sealer.Seal(ctx, pr, f, pass); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// pwOpenStaged decrypts a sealed staged/backup bundle and parses it back into Accounts
// whose Secret is the stored password (new for a stage file, old for a backup).
func pwOpenStaged(ctx context.Context, v *vault.Vault, sealer sink.Sealer, pass *memguard.LockedBuffer, in string) ([]pwstore.Account, error) {
	f, err := os.Open(in)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sealer.Open(ctx, f, pw, pass)) }()
	return pwstore.ReadStaged(v, pr)
}

// pwCSVReimport handles the browser-CSV commit at the end of an interactive guide:
// it writes a tmpfs CSV of the verified accounts' new passwords, waits for the human to
// re-import it, then shreds it. Requires --allow-csv.
func pwCSVReimport(ctx context.Context, m pwstore.Manager, v *vault.Vault, accts []pwstore.Account, newPw map[int]*vault.Handle, verified []int, in *bufio.Scanner, log *audit.Log) error {
	if !flagAllowCSV {
		return fmt.Errorf("browser re-import writes a plaintext CSV to tmpfs; re-run with --allow-csv to authorize (it is shredded after)")
	}
	si, ok := m.(pwstore.StagedImporter)
	if !ok {
		return fmt.Errorf("%s cannot import a CSV", m.Name())
	}
	sub := make([]pwstore.Account, 0, len(verified))
	subNew := map[int]*vault.Handle{}
	for j, i := range verified {
		sub = append(sub, accts[i])
		subNew[j] = newPw[i]
	}
	path, cleanup, err := si.ImportStaged(v, sub, subNew)
	if err != nil {
		return err
	}
	defer cleanup()
	if log != nil {
		log.Write(audit.Entry{Action: "pw-import", Source: m.Name(), Location: path,
			Outcome: fmt.Sprintf("staged %d account(s); plaintext CSV on tmpfs, will shred", len(sub))})
	}
	fmt.Printf("\nRe-import this CSV into your browser, then press Enter to shred it:\n  %s\n", path)
	in.Scan()
	fmt.Fprintf(os.Stderr, "shredded %s\n", path)
	return nil
}

// parseVerified turns "all" or "1,3,5" (1-based) into 0-based indices into an n-length
// staged list.
func parseVerified(spec string, n int) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if strings.EqualFold(spec, "all") {
		idxs := make([]int, n)
		for i := range idxs {
			idxs[i] = i
		}
		return idxs, nil
	}
	var out []int
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		k, err := strconv.Atoi(tok)
		if err != nil || k < 1 || k > n {
			return nil, fmt.Errorf("invalid --verified entry %q (want 1..%d or 'all')", tok, n)
		}
		out = append(out, k-1)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--verified selected no accounts")
	}
	return out, nil
}

// renderPwWorklist builds the SECRETS-FREE worklist: index, redacted identity, change
// link, and a status the human ticks off. New passwords NEVER appear here.
func renderPwWorklist(manager string, accts []pwstore.Account) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Password rotation worklist — %s\n\n", manager)
	fmt.Fprintf(&b, "%d account(s). Change each at its site (complete MFA), then commit by index.\n\n", len(accts))
	fmt.Fprintln(&b, "| # | account | change-password link | status |")
	fmt.Fprintln(&b, "|---|---------|----------------------|--------|")
	for i, a := range accts {
		fmt.Fprintf(&b, "| %d | %s | %s | [ ] pending |\n", i+1, pwstore.RedactIdentity(a), linkLabel(a))
	}
	return b.String()
}

func worklistDest() string {
	if flagWorklistOut == "" {
		return "(stdout)"
	}
	return flagWorklistOut
}

// defaultBundlePath returns a fresh timestamped path under ~/.incredigo/<sub>/.
func defaultBundlePath(sub string) (string, error) {
	dir := filepath.Join(os.Getenv("HOME"), ".incredigo", sub)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, time.Now().UTC().Format("2006-01-02T15-04-05Z")+".age"), nil
}

// ask prints a prompt and returns true on a y/yes answer.
func ask(in *bufio.Scanner, prompt string) bool {
	fmt.Print(prompt)
	if !in.Scan() {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(in.Text()))
	return a == "y" || a == "yes"
}

// promptSecret reads one secret line with no echo into the vault.
func promptSecret(v *vault.Vault, prompt string) (*vault.Handle, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return v.Store(b), nil
}
