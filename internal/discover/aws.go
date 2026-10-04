package discover

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"incredigo/internal/vault"
)

func init() { Register(&awsScanner{}) }

// awsScanner reads ~/.aws/credentials (INI). Read-only: opens O_RDONLY and never
// writes back.
//
// The emitted secret is the driver-ready single-line blob
// "aws://<AccessKeyId>:<SecretAccessKey>@aws/?region=<region>" (see
// internal/rotate/aws.go), so a discovered key can be rotated directly in Mode B
// (scan → migrate → rotate). The AccessKeyId is non-secret and stays full in the
// blob (the rotation driver deletes the OLD key by id); Identity/Meta keep it
// redacted for display.
type awsScanner struct{}

func (a *awsScanner) Name() string { return "aws" }

func (a *awsScanner) path() string {
	if p := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aws", "credentials")
}

func (a *awsScanner) Available() bool {
	_, err := os.Stat(a.path())
	return err == nil
}

func (a *awsScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	p := a.path()
	f, err := os.Open(p) // read-only
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, _ := f.Stat()

	var creds []Credential
	var profile, keyID string

	flush := func(secret string) {
		if profile == "" || secret == "" || keyID == "" {
			return
		}
		// Driver-ready single-line blob; the secret lives only here (and the vault).
		blob := (&url.URL{
			Scheme:   "aws",
			Host:     "aws",
			User:     url.UserPassword(keyID, secret),
			Path:     "/",
			RawQuery: "region=" + url.QueryEscape(awsRegion(profile)),
		}).String()
		creds = append(creds, Credential{
			Source:   a.Name(),
			Kind:     KindAWSKey,
			Identity: profile + " / " + redactMiddle(keyID),
			Location: p,
			Modified: fi.ModTime(),
			Secret:   v.Store([]byte(blob)),
			Meta:     map[string]string{"access_key_id": redactMiddle(keyID)},
		})
		keyID = ""
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			profile = strings.TrimSpace(line[1 : len(line)-1])
			keyID = ""
			continue
		}
		k, val, ok := splitKV(line)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "aws_access_key_id":
			keyID = val
		case "aws_secret_access_key":
			flush(val)
		}
	}
	return creds, sc.Err()
}

// awsRegion resolves the signing region for a profile: AWS_REGION /
// AWS_DEFAULT_REGION env first, then the `region` key under the matching profile in
// ~/.aws/config (or AWS_CONFIG_FILE), defaulting to us-east-1. Read-only.
func awsRegion(profile string) string {
	if r := os.Getenv("AWS_REGION"); r != "" {
		return r
	}
	if r := os.Getenv("AWS_DEFAULT_REGION"); r != "" {
		return r
	}
	cfg := os.Getenv("AWS_CONFIG_FILE")
	if cfg == "" {
		home, _ := os.UserHomeDir()
		cfg = filepath.Join(home, ".aws", "config")
	}
	f, err := os.Open(cfg) // read-only
	if err != nil {
		return "us-east-1"
	}
	defer f.Close()

	// In ~/.aws/config non-default profiles are headed "[profile NAME]"; default is
	// "[default]".
	want := "profile " + profile
	if profile == "default" {
		want = "default"
	}
	inSection := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inSection = strings.TrimSpace(line[1:len(line)-1]) == want
			continue
		}
		if !inSection {
			continue
		}
		if k, val, ok := splitKV(line); ok && strings.ToLower(k) == "region" && val != "" {
			return val
		}
	}
	return "us-east-1"
}

func splitKV(line string) (k, v string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// redactMiddle keeps the first 4 and last 2 chars, masking the middle, so labels
// are human-recognizable without leaking the value.
func redactMiddle(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-6) + s[len(s)-2:]
}
