package rotate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// OpenWrt rotates an OpenWrt router's admin password over SSH — the in-place
// password pattern (the same family as Postgres/MySQL/Redis). On OpenWrt the root
// account password is the single admin secret: it gates SSH (dropbear) AND the LuCI
// web UI (LuCI shells out to `passwd`). The credential's secret is a single
// self-contained line (so it round-trips through the single-line gopass sink):
//
//	openwrt://<user>:<password>@<host>[:port]/
//
// Rotation dials the router with the OLD password, runs `passwd` (feeding the NEW
// password on the session's stdin so it never appears in argv), and returns a
// rebuilt blob with the new password. Setting the password IS the cutover — the old
// password stops authenticating immediately — so RevokeOld is a no-op and the §3
// sealed backup is the recovery path (lockout risk makes the backup gate essential).
//
// SECURITY (Hard Rule #3 — no plaintext secrets on disk/argv, ever): the new
// password travels only inside the SSH-encrypted stdin stream to the remote `passwd`;
// the command line is just "passwd". The new password is hex ([0-9a-f]) so it needs
// no quoting and cannot inject extra input lines. Captured stderr is scrubbed of the
// new password before any error surfaces.
type OpenWrt struct {
	// HostKey defaults to InsecureIgnoreHostKey: we rotate routers the operator owns
	// and reaches on the LAN; the trust boundary here is the admin password, not host
	// identity. Host-key pinning is a separate concern.
	HostKey ssh.HostKeyCallback
	// Dial is injectable so tests can point at an in-process SSH server. Defaults to
	// ssh.Dial.
	Dial func(network, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error)
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&OpenWrt{}) }

// Name identifies the driver in plans and audit records.
func (o *OpenWrt) Name() string { return "openwrt" }

// Detect claims credentials tagged Source == "openwrt".
func (o *OpenWrt) Detect(c discover.Credential) bool { return c.Source == "openwrt" }

func (o *OpenWrt) hostKey() ssh.HostKeyCallback {
	if o.HostKey != nil {
		return o.HostKey
	}
	return ssh.InsecureIgnoreHostKey()
}

func (o *OpenWrt) dialer() func(string, string, *ssh.ClientConfig) (*ssh.Client, error) {
	if o.Dial != nil {
		return o.Dial
	}
	return ssh.Dial
}

// owSecret is the parsed credential blob. None of its fields are ever logged.
type owSecret struct {
	user, password, host, port string
}

func parseOWSecret(v *vault.Vault, h *vault.Handle) (owSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return owSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return owSecret{}, fmt.Errorf("openwrt: parse secret url: %w", err)
	}
	if u.Scheme != "openwrt" && u.Scheme != "ssh" {
		return owSecret{}, fmt.Errorf("openwrt: unexpected scheme %q", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return owSecret{}, errors.New("openwrt: secret has no user")
	}
	pw, ok := u.User.Password()
	if !ok || pw == "" {
		return owSecret{}, errors.New("openwrt: secret has no password")
	}
	port := u.Port()
	if port == "" {
		port = "22"
	}
	return owSecret{user: u.User.Username(), password: pw, host: u.Hostname(), port: port}, nil
}

func (s owSecret) addr() string { return net.JoinHostPort(s.host, s.port) }

func (s owSecret) build() string {
	u := &url.URL{
		Scheme: "openwrt",
		Host:   net.JoinHostPort(s.host, s.port),
		User:   url.UserPassword(s.user, s.password),
		Path:   "/",
	}
	return u.String()
}

// Rotate sets a new admin password over the OLD SSH connection and returns a vault
// handle to the rebuilt blob. It does not revoke anything — the passwd change is the
// cutover.
func (o *OpenWrt) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseOWSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	newPw, err := genHex(18)
	if err != nil {
		return nil, err
	}
	if err := o.setPassword(ctx, s, newPw); err != nil {
		return nil, fmt.Errorf("openwrt: set password: %w", err)
	}

	ns := s
	ns.password = newPw
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the new password authenticates by opening an SSH session with it and
// running a trivial command.
func (o *OpenWrt) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseOWSecret(v, newSecret)
	if err != nil {
		return err
	}
	out, err := o.run(ctx, s, "echo incredigo-ok")
	if err != nil {
		return fmt.Errorf("openwrt verify: %w", err)
	}
	if !strings.Contains(out, "incredigo-ok") {
		return errors.New("openwrt verify: unexpected result")
	}
	return nil
}

// RevokeOld is a no-op for an in-place engine: setting the password in Rotate already
// invalidated the previous one. Defined to satisfy the safety-spine ordering.
func (o *OpenWrt) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}

// dialSSH opens an SSH client to the router authenticating with the secret's
// password.
func (o *OpenWrt) dialSSH(s owSecret) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            s.user,
		Auth:            []ssh.AuthMethod{ssh.Password(s.password)},
		HostKeyCallback: o.hostKey(),
		Timeout:         10 * time.Second,
	}
	return o.dialer()("tcp", s.addr(), cfg)
}

// run executes one command over a fresh SSH session and returns its stdout.
func (o *OpenWrt) run(ctx context.Context, s owSecret, cmd string) (string, error) {
	cli, err := o.dialSSH(s)
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", s.addr(), err)
	}
	defer cli.Close()
	sess, err := cli.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	if err := sess.Run(cmd); err != nil {
		return out.String(), fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// setPassword runs `passwd` for the connected (root) account, feeding the new
// password twice on stdin (BusyBox passwd reads new+retype from a non-tty stdin).
// The password reaches the router only inside the SSH-encrypted stdin stream.
func (o *OpenWrt) setPassword(ctx context.Context, s owSecret, newPw string) error {
	cli, err := o.dialSSH(s)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", s.addr(), err)
	}
	defer cli.Close()
	sess, err := cli.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(newPw + "\n" + newPw + "\n")
	var errb bytes.Buffer
	sess.Stderr = &errb
	if err := sess.Run("passwd"); err != nil {
		se := strings.ReplaceAll(errb.String(), newPw, "***")
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(se))
	}
	return nil
}
