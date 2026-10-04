package rotate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// awsEmu is a minimal IAM/STS Query-API emulator that ENFORCES access-key validity:
// every request must be SigV4-signed by a key that currently EXISTS (the emulator
// reads the AccessKeyId from the Authorization Credential= field), and
// DeleteAccessKey makes a key stop working. That lets the test prove a real cutover
// — old key rejected (403) after revoke, new key alive — which moto's default mode
// does not enforce. It does not verify the signature math (that is proven by the
// live moto POC); it proves the DRIVER'S create→verify→revoke ordering and that the
// old key is precisely targeted.
type awsEmu struct {
	mu    sync.Mutex
	valid map[string]string // AccessKeyId -> SecretAccessKey (existence == validity)
	user  string
	srv   *httptest.Server
}

func newAWSEmu(t *testing.T, user, seedID, seedSecret string) *awsEmu {
	e := &awsEmu{
		valid: map[string]string{seedID: seedSecret},
		user:  user,
	}
	e.srv = httptest.NewServer(http.HandlerFunc(e.handle))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *awsEmu) isValid(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.valid[id]
	return ok
}

// credKeyID pulls the AccessKeyId out of "Authorization: AWS4-HMAC-SHA256
// Credential=<keyID>/<date>/<region>/<service>/aws4_request, ...".
func credKeyID(r *http.Request) string {
	h := r.Header.Get("Authorization")
	i := strings.Index(h, "Credential=")
	if i < 0 {
		return ""
	}
	rest := h[i+len("Credential="):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return ""
}

func (e *awsEmu) handle(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.Form.Get("Action")

	// Auth gate: the signing key must currently exist. This is what enforces the
	// cutover — a deleted key fails here.
	if !e.isValid(credKeyID(r)) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>key revoked</Message></Error></ErrorResponse>`)
		return
	}

	w.Header().Set("Content-Type", "text/xml")
	switch action {
	case "CreateAccessKey":
		raw := make([]byte, 16)
		rand.Read(raw)
		newID := "AKIA" + strings.ToUpper(hex.EncodeToString(raw[:8]))
		raw2 := make([]byte, 30)
		rand.Read(raw2)
		newSecret := hex.EncodeToString(raw2)
		e.mu.Lock()
		e.valid[newID] = newSecret
		e.mu.Unlock()
		fmt.Fprintf(w, `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey>`+
			`<UserName>%s</UserName><AccessKeyId>%s</AccessKeyId><Status>Active</Status>`+
			`<SecretAccessKey>%s</SecretAccessKey></AccessKey></CreateAccessKeyResult>`+
			`</CreateAccessKeyResponse>`, e.user, newID, newSecret)
	case "DeleteAccessKey":
		id := r.Form.Get("AccessKeyId")
		e.mu.Lock()
		delete(e.valid, id)
		e.mu.Unlock()
		io.WriteString(w, `<DeleteAccessKeyResponse><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></DeleteAccessKeyResponse>`)
	case "GetCallerIdentity":
		fmt.Fprintf(w, `<GetCallerIdentityResponse><GetCallerIdentityResult>`+
			`<Arn>arn:aws:iam::123456789012:user/%s</Arn><UserId>AIDAEMULATED</UserId>`+
			`<Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`, e.user)
	default:
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `<ErrorResponse><Error><Code>InvalidAction</Code></Error></ErrorResponse>`)
	}
}

func TestAWSRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const user, oldID, oldSecret = "alice", "AKIAOLDKEYEXAMPLE000", "oldSecretAccessKey0123456789abcdef"
	emu := newAWSEmu(t, user, oldID, oldSecret)

	oldBlob := awsSecret{keyID: oldID, secret: oldSecret, region: "us-east-1", endpoint: emu.srv.URL}.build()
	cred := discover.Credential{
		Source:   "aws",
		Kind:     discover.KindAWSKey,
		Identity: user + " / AKIA***000",
		Location: "imported/aws/default",
		Secret:   v.Store([]byte(oldBlob)),
	}

	a := &AWS{}

	if !emu.isValid(oldID) {
		t.Fatal("seed key should be valid at start")
	}

	// 1. Rotate — create a new key (old still valid).
	newH, err := a.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseAWSSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.keyID == oldID || ns.secret == oldSecret {
		t.Fatal("new key equals old — rotation minted nothing")
	}
	if !emu.isValid(oldID) {
		t.Fatal("old key must remain valid before revoke")
	}
	if !emu.isValid(ns.keyID) {
		t.Fatal("new key must be valid after create")
	}

	// 2. Verify(new) via the driver (STS GetCallerIdentity with the new key).
	if err := a.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld — DeleteAccessKey targeting the OLD AccessKeyId.
	if err := a.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}

	// Cutover assertions: old dead, new alive.
	if emu.isValid(oldID) {
		t.Fatal("old key must be invalid after revoke")
	}
	if err := a.Verify(ctx, cred.Secret, v); err == nil {
		t.Fatal("old key must NOT authenticate after revoke")
	}
	if err := a.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new key must still authenticate after revoke: %v", err)
	}

	// Leak check: key material must not appear in non-secret credential fields.
	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, oldSecret) || strings.Contains(f, ns.secret) {
			t.Errorf("secret leaked into non-secret field %q", f)
		}
	}
}

func TestAWSSecretRoundTrip(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	// SecretAccessKey commonly contains '/' and '+'; ensure the blob round-trips.
	in := awsSecret{keyID: "AKIAEXAMPLE", secret: "ab/cd+ef==Ghi", region: "eu-west-2", endpoint: "http://127.0.0.1:5000"}
	h := v.Store([]byte(in.build()))
	out, err := parseAWSSecret(v, h)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch: %+v != %+v", out, in)
	}
}

func TestSigV4HeadersStable(t *testing.T) {
	// A fixed input must yield the canonical AWS SigV4 example-style header shape:
	// Credential/SignedHeaders/Signature present and the signing key chain applied.
	hdrs, err := sigV4Headers(http.MethodPost, "https://iam.amazonaws.com/", "us-east-1", "iam",
		[]byte("Action=CreateAccessKey&Version=2010-05-08"), "AKIDEXAMPLE", "secretkey",
		time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	auth := hdrs["Authorization"]
	for _, want := range []string{
		"AWS4-HMAC-SHA256 ",
		"Credential=AKIDEXAMPLE/",
		"/us-east-1/iam/aws4_request",
		"SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date",
		"Signature=",
	} {
		if !strings.Contains(auth, want) {
			t.Errorf("Authorization missing %q; got %q", want, auth)
		}
	}
	if hdrs["X-Amz-Date"] == "" || hdrs["X-Amz-Content-Sha256"] == "" {
		t.Error("missing x-amz-date / x-amz-content-sha256")
	}
}
