package rotate

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// owServer is an in-process SSH server emulating an OpenWrt router: it authenticates
// password logins against a mutable current password, and handles a `passwd` exec by
// reading the new password (twice) from the session stdin and updating that current
// password — so a test can prove the cutover (old password stops authenticating).
type owServer struct {
	mu  sync.Mutex
	cur string
}

func (o *owServer) password() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cur
}

func (o *owServer) setPassword(p string) {
	o.mu.Lock()
	o.cur = p
	o.mu.Unlock()
}

func startOpenWrtServer(t *testing.T, srv *owServer) string {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(conn, hostSigner)
		}
	}()
	return ln.Addr().String()
}

func (o *owServer) serve(conn net.Conn, hostKey ssh.Signer) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == o.password() {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("auth denied")
		},
	}
	cfg.AddHostKey(hostKey)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		go o.handleSession(ch, requests)
	}
	_ = sshConn
}

func (o *owServer) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		ssh.Unmarshal(req.Payload, &payload)
		req.Reply(true, nil)
		if strings.HasPrefix(payload.Command, "passwd") {
			rd := bufio.NewReader(ch)
			line1, _ := rd.ReadString('\n')
			rd.ReadString('\n') // retype (ignored; equals line1)
			o.setPassword(strings.TrimSpace(line1))
		} else {
			io.WriteString(ch, "incredigo-ok\n")
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		ch.Close()
		return
	}
}

func TestOpenWrtDetect(t *testing.T) {
	o := &OpenWrt{}
	if !o.Detect(discover.Credential{Source: "openwrt"}) {
		t.Error("should detect Source=openwrt")
	}
	if o.Detect(discover.Credential{Source: "ssh"}) {
		t.Error("should not detect Source=ssh")
	}
}

func TestOpenWrtRotateRealCutover(t *testing.T) {
	srv := &owServer{cur: "oldpw"}
	addr := startOpenWrtServer(t, srv)

	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{
		Source:   "openwrt",
		Identity: "router",
		Secret:   v.Store([]byte("openwrt://root:oldpw@" + addr + "/")),
	}
	o := &OpenWrt{}
	ctx := context.Background()

	newH, err := o.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if srv.password() == "oldpw" {
		t.Fatal("admin password not changed by passwd")
	}

	if err := o.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}

	// Extract the new password to assert it never leaks into an error string.
	nb, _ := v.Open(newH)
	nu, _ := url.Parse(strings.TrimSpace(string(nb.Bytes())))
	newPw, _ := nu.User.Password()
	if newPw == "oldpw" || newPw == "" {
		t.Fatal("new credential carries no fresh password")
	}

	if err := o.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after rotation — old password should be revoked")
	} else if strings.Contains(err.Error(), newPw) {
		t.Error("error leaked the new password")
	}

	if err := o.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}
}

func TestOpenWrtRejectsBadSecret(t *testing.T) {
	o := &OpenWrt{}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "openwrt", Secret: v.Store([]byte("openwrt://root@192.168.1.1/"))} // no password
	if _, err := o.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no password")
	}
}
