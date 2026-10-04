# Adding a scanner

A scanner teaches incredigo to discover credentials from one location/format. Each
is a single self-contained file in `internal/discover/` that implements the
`Scanner` interface and registers itself in `init()`.

## The contract

```go
type Scanner interface {
    Name() string
    Available() bool
    Scan(ctx context.Context, v *vault.Vault) ([]Credential, error)
}
```

Rules:

1. **Read-only, always.** Open files with `os.Open` (O_RDONLY). Never write,
   rename, or truncate a source file.
2. **Never build plaintext into a long-lived value.** Read the secret into a
   `[]byte`, hand it to `v.Store(secret)`, and put the returned `*vault.Handle` in
   `Credential.Secret`. `Store` wipes your slice for you.
3. **Pre-redact identities.** `Identity` and any `Meta` values are printed and
   logged. Use `redactMiddle(...)` (see `aws.go`) for key ids etc. Never put the
   secret in `Identity`/`Meta`.
4. **Set `Modified`** from the file mtime — it feeds the expiry policy.
5. **`Available()` should be cheap** (a `stat`), and return false when the source
   is absent so the run skips it cleanly.

## Template

```go
package discover

import (
    "context"
    "os"
    "path/filepath"

    "incredigo/internal/vault"
)

func init() { Register(&fooScanner{}) }

type fooScanner struct{}

func (f *fooScanner) Name() string { return "foo" }

func (f *fooScanner) path() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".foo", "credentials")
}

func (f *fooScanner) Available() bool {
    _, err := os.Stat(f.path())
    return err == nil
}

func (f *fooScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
    p := f.path()
    b, err := os.ReadFile(p) // read-only
    if err != nil {
        return nil, err
    }
    fi, _ := os.Stat(p)

    secret := parseSecret(b) // your format logic
    return []Credential{{
        Source:   f.Name(),
        Kind:     KindToken,
        Identity: "foo / " + redactMiddle(/* a non-secret id */),
        Location: p,
        Modified: fi.ModTime(),
        Secret:   v.Store([]byte(secret)),
    }}, nil
}
```

That's it — the registry picks it up automatically, and `scan`/`migrate`/`status`
all gain the new source with no other changes.

## Tests

Add `foo_test.go` with a fixture file in a temp dir; assert that `Scan` returns
the expected metadata and that `Identity`/`Meta` contain no secret substrings.
