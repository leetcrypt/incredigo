package rotate

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// AWS rotates an AWS IAM access key via the IAM/STS Query APIs by CREATING a new
// access key, verifying it with STS GetCallerIdentity, then DELETING the old one —
// the provider-API rotation pattern (create-new → verify → revoke-old).
//
// This is the cleanest provider-API driver because the OLD credential is
// self-identifying: an access key's AccessKeyId is *non-secret* and travels in the
// secret blob, so RevokeOld deletes exactly the right key (DeleteAccessKey takes the
// AccessKeyId directly — no name-capture dance like Gitea needed).
//
// The credential's secret is a single self-contained line (so it round-trips
// through the existing single-line gopass sink unchanged):
//
//	aws://<AccessKeyId>:<SecretAccessKey>@aws/?region=<region>[&endpoint=<url>]
//
//   - AccessKeyId / SecretAccessKey are the userinfo user/password.
//   - region=   signing region (default us-east-1). IAM is global and always
//               signs us-east-1; region matters only for STS regional endpoints.
//   - endpoint= OPTIONAL override of the API base (for a self-hosted moto/LocalStack
//               in testing). Absent → real AWS (iam/sts .amazonaws.com).
//
// SECURITY: requests are signed with AWS SigV4 by HMAC chaining over the secret key
// (crypto/hmac); the secret never appears in argv, on disk, or in any header except
// as the derived signature. The new SecretAccessKey is returned by AWS only once, in
// the CreateAccessKey XML body — it is decoded straight into the vault and never
// logged. Error paths read only non-success bodies (AWS error XML, which carries no
// secret) and surface just the error Code, never a raw body.
type AWS struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout
	// client.
	HTTPClient *http.Client
	// now is injectable so tests can pin the SigV4 timestamp; defaults to time.Now.
	now func() time.Time
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&AWS{}) }

// Name identifies the driver in plans and audit records.
func (a *AWS) Name() string { return "aws" }

// Detect claims credentials tagged Source == "aws".
func (a *AWS) Detect(c discover.Credential) bool { return c.Source == "aws" }

func (a *AWS) client() *http.Client {
	if a.HTTPClient != nil {
		return a.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (a *AWS) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// awsSecret is the parsed credential blob. None of its fields are ever logged.
type awsSecret struct {
	keyID    string
	secret   string
	region   string
	endpoint string // "" = real AWS
}

// parseAWSSecret reads the single-line blob from the vault and decomposes it.
func parseAWSSecret(v *vault.Vault, h *vault.Handle) (awsSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return awsSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return awsSecret{}, fmt.Errorf("aws: parse secret url: %w", err)
	}
	if u.Scheme != "aws" {
		return awsSecret{}, fmt.Errorf("aws: unexpected scheme %q", u.Scheme)
	}
	if u.User == nil {
		return awsSecret{}, fmt.Errorf("aws: secret has no AccessKeyId:SecretAccessKey")
	}
	sec, _ := u.User.Password()
	if u.User.Username() == "" || sec == "" {
		return awsSecret{}, fmt.Errorf("aws: secret missing key id or secret")
	}
	q := u.Query()
	region := q.Get("region")
	if region == "" {
		region = "us-east-1"
	}
	return awsSecret{
		keyID:    u.User.Username(),
		secret:   sec,
		region:   region,
		endpoint: q.Get("endpoint"),
	}, nil
}

// build re-encodes an awsSecret into the single-line blob form.
func (s awsSecret) build() string {
	u := &url.URL{
		Scheme: "aws",
		Host:   "aws",
		User:   url.UserPassword(s.keyID, s.secret),
		Path:   "/",
	}
	q := url.Values{}
	q.Set("region", s.region)
	if s.endpoint != "" {
		q.Set("endpoint", s.endpoint)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// endpointFor resolves the API base for a service ("iam" or "sts"), honoring an
// explicit endpoint override (moto/LocalStack) when set.
func (a *AWS) endpointFor(s awsSecret, service string) string {
	if s.endpoint != "" {
		return strings.TrimRight(s.endpoint, "/")
	}
	return "https://" + service + ".amazonaws.com"
}

// Rotate creates a NEW access key for the calling identity (authenticated by the
// OLD key) and returns a vault handle to a rebuilt blob carrying the new key pair.
// It does not delete the old key.
func (a *AWS) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseAWSSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	body, err := a.call(ctx, s, "iam", "CreateAccessKey", "2010-05-08", nil)
	if err != nil {
		return nil, fmt.Errorf("aws: create access key: %w", err)
	}
	var r struct {
		KeyID  string `xml:"CreateAccessKeyResult>AccessKey>AccessKeyId"`
		Secret string `xml:"CreateAccessKeyResult>AccessKey>SecretAccessKey"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("aws: decode created key: %w", err)
	}
	if r.KeyID == "" || r.Secret == "" {
		return nil, fmt.Errorf("aws: create access key: empty key in response")
	}
	ns := s // carry region/endpoint forward
	ns.keyID = r.KeyID
	ns.secret = r.Secret
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the freshly minted key authenticates by calling STS
// GetCallerIdentity with it and checking a caller ARN comes back.
func (a *AWS) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseAWSSecret(v, newSecret)
	if err != nil {
		return err
	}
	body, err := a.call(ctx, s, "sts", "GetCallerIdentity", "2011-06-15", nil)
	if err != nil {
		return fmt.Errorf("aws verify: %w", err)
	}
	var r struct {
		Arn string `xml:"GetCallerIdentityResult>Arn"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("aws verify: decode caller identity: %w", err)
	}
	if r.Arn == "" {
		return fmt.Errorf("aws verify: GetCallerIdentity returned no ARN")
	}
	return nil
}

// RevokeOld deletes the OLD access key by its (non-secret) AccessKeyId. The old
// key is still valid at this point (revoke runs only after the new key is
// stored+verified), so it authenticates its own deletion.
func (a *AWS) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseAWSSecret(v, c.Secret)
	if err != nil {
		return err
	}
	extra := url.Values{}
	extra.Set("AccessKeyId", s.keyID)
	if _, err := a.call(ctx, s, "iam", "DeleteAccessKey", "2010-05-08", extra); err != nil {
		return fmt.Errorf("aws revoke: %w", err)
	}
	return nil
}

// call POSTs an AWS Query-protocol request (form-encoded Action/Version + extras),
// SigV4-signed with the blob's own key pair, and returns the response body. A
// non-2xx response yields an error carrying only the AWS error Code (never the
// raw body).
func (a *AWS) call(ctx context.Context, s awsSecret, service, action, version string, extra url.Values) ([]byte, error) {
	form := url.Values{}
	form.Set("Action", action)
	form.Set("Version", version)
	for k, vs := range extra {
		for _, val := range vs {
			form.Add(k, val)
		}
	}
	body := []byte(form.Encode())

	region := s.region
	if service == "iam" {
		region = "us-east-1" // IAM is a global service; SigV4 region is always us-east-1.
	}
	endpoint := a.endpointFor(s, service)

	hdrs, err := sigV4Headers(http.MethodPost, endpoint+"/", region, service, body, s.keyID, s.secret, a.clock())
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, val := range hdrs {
		req.Header.Set(k, val)
	}

	resp, err := a.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: status %s: %s", action, resp.Status, awsErrCode(rb))
	}
	return rb, nil
}

// awsErrCode extracts the <Error><Code> from an AWS error response so failures are
// legible without dumping the body. AWS error bodies never contain a secret.
func awsErrCode(b []byte) string {
	var e struct {
		Code string `xml:"Error>Code"`
	}
	if xml.Unmarshal(b, &e) == nil && e.Code != "" {
		return e.Code
	}
	return "unknown error"
}

// sigV4Headers computes the AWS Signature Version 4 headers for a POST request
// whose parameters are in the (already-encoded) body. Returns the headers the
// caller must set: Authorization, X-Amz-Date, X-Amz-Content-Sha256, Content-Type.
func sigV4Headers(method, rawURL, region, service string, body []byte, keyID, secret string, t time.Time) (map[string]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	t = t.UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	contentType := "application/x-www-form-urlencoded; charset=utf-8"
	payloadHash := sha256hex(body)

	canonicalURI := u.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalHeaders := "content-type:" + contentType + "\n" +
		"host:" + u.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"

	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		u.RawQuery, // empty: params are in the body
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := "AWS4-HMAC-SHA256 " +
		"Credential=" + keyID + "/" + scope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature

	return map[string]string{
		"Authorization":        auth,
		"X-Amz-Date":           amzDate,
		"X-Amz-Content-Sha256": payloadHash,
		"Content-Type":         contentType,
	}, nil
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
