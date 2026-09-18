package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// stapleFixture is a chain plus a signed OCSP response about its leaf.
type stapleFixture struct {
	Leaf   *x509.Certificate
	Issuer *x509.Certificate
	DER    []byte
}

// newStapleFixture mints a root and leaf, then has the root sign an OCSP
// response about the leaf, which is what a correctly configured server staples.
//
// It mints its own chain rather than reusing serverChain, which does not hand
// back the root key. Signing the response as the same issuer is the whole point
// here: a response signed by anyone else would not verify, and these tests are
// about what verification reports.
func newStapleFixture(t *testing.T, tmpl ocsp.Response) stapleFixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Staple Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x2a),
		Subject:      pkix.Name{CommonName: "staple.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"staple.test"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = leaf.SerialNumber
	}
	if tmpl.ThisUpdate.IsZero() {
		tmpl.ThisUpdate = time.Now().Add(-time.Hour)
	}
	respDER, err := ocsp.CreateResponse(root, root, tmpl, rootKey)
	if err != nil {
		t.Fatalf("creating the OCSP response: %v", err)
	}

	return stapleFixture{Leaf: leaf, Issuer: root, DER: respDER}
}

func TestParseStapleReadsAGoodResponse(t *testing.T) {
	next := time.Now().Add(24 * time.Hour)
	fx := newStapleFixture(t, ocsp.Response{Status: ocsp.Good, NextUpdate: next})

	staple, err := ParseStaple(fx.DER, fx.Leaf, fx.Issuer)
	if err != nil {
		t.Fatalf("ParseStaple: %v", err)
	}
	if staple.Status != "good" {
		t.Errorf("Status = %q, want %q", staple.Status, "good")
	}
	if !staple.Verified {
		t.Error("Verified is false even though the issuer was supplied")
	}
	if staple.SerialNumber != strings.ToLower(fx.Leaf.SerialNumber.Text(16)) {
		t.Errorf("SerialNumber = %q, want the leaf's %q",
			staple.SerialNumber, fx.Leaf.SerialNumber.Text(16))
	}
	if staple.Expired(time.Now()) {
		t.Error("a response with NextUpdate in the future reports as expired")
	}
	if !staple.RevokedAt.IsZero() {
		t.Error("a good response carries a revocation time")
	}
}

func TestParseStapleReadsARevokedResponse(t *testing.T) {
	revoked := time.Now().Add(-2 * time.Hour)
	fx := newStapleFixture(t, ocsp.Response{
		Status:           ocsp.Revoked,
		RevokedAt:        revoked,
		RevocationReason: ocsp.KeyCompromise,
		NextUpdate:       time.Now().Add(time.Hour),
	})

	staple, err := ParseStaple(fx.DER, fx.Leaf, fx.Issuer)
	if err != nil {
		t.Fatalf("ParseStaple: %v", err)
	}
	if staple.Status != "revoked" {
		t.Errorf("Status = %q, want %q", staple.Status, "revoked")
	}
	if staple.RevocationReason != "key compromise" {
		t.Errorf("RevocationReason = %q, want it named rather than numbered", staple.RevocationReason)
	}
	if staple.RevokedAt.IsZero() {
		t.Error("a revoked response carries no revocation time")
	}
}

// TestParseStapleWithoutTheIssuer covers the case this tool exists for: the
// server omitted the intermediate. The response is still read, and says so.
func TestParseStapleWithoutTheIssuer(t *testing.T) {
	fx := newStapleFixture(t, ocsp.Response{Status: ocsp.Good, NextUpdate: time.Now().Add(time.Hour)})

	staple, err := ParseStaple(fx.DER, fx.Leaf, nil)
	if err != nil {
		t.Fatalf("ParseStaple: %v", err)
	}
	if staple.Status != "good" {
		t.Errorf("Status = %q, want the response read anyway", staple.Status)
	}
	if staple.Verified {
		t.Error("Verified is true even though no issuer was available to check the signature against")
	}
}

// TestParseStapleWithABadSignature covers the case that must not be confused
// with a missing issuer: the issuer was there, and the response did not verify
// against it. Verified is false for both, so VerifyErr is what tells them apart.
func TestParseStapleWithABadSignature(t *testing.T) {
	fx := newStapleFixture(t, ocsp.Response{Status: ocsp.Good, NextUpdate: time.Now().Add(time.Hour)})

	// A second, unrelated CA signs a response about the same leaf. Handing the
	// real issuer to ParseStaple then fails verification rather than skipping it.
	imposter := newStapleFixture(t, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: fx.Leaf.SerialNumber,
		NextUpdate:   time.Now().Add(time.Hour),
	})

	staple, err := ParseStaple(imposter.DER, fx.Leaf, fx.Issuer)
	if err != nil {
		t.Fatalf("ParseStaple: %v, want the response read anyway", err)
	}
	if staple.Verified {
		t.Error("a response signed by an unrelated CA verified against the real issuer")
	}
	if staple.VerifyErr == nil {
		t.Fatal("VerifyErr is nil, so this is indistinguishable from having had no issuer at all")
	}
	if staple.Status != "good" {
		t.Errorf("Status = %q, want the response still read", staple.Status)
	}
}

// TestParseStapleWithoutTheIssuerLeavesVerifyErrNil is the other half of the
// pair: nothing failed, there was simply nothing to check against.
func TestParseStapleWithoutTheIssuerLeavesVerifyErrNil(t *testing.T) {
	fx := newStapleFixture(t, ocsp.Response{Status: ocsp.Good, NextUpdate: time.Now().Add(time.Hour)})

	staple, err := ParseStaple(fx.DER, fx.Leaf, nil)
	if err != nil {
		t.Fatalf("ParseStaple: %v", err)
	}
	if staple.VerifyErr != nil {
		t.Errorf("VerifyErr = %v, want nil: no issuer was supplied, so no check failed", staple.VerifyErr)
	}
}

// TestParseStapleExpiredResponse covers the freshness question a staple exists
// to answer.
func TestParseStapleExpiredResponse(t *testing.T) {
	fx := newStapleFixture(t, ocsp.Response{
		Status:     ocsp.Good,
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	})

	staple, err := ParseStaple(fx.DER, fx.Leaf, fx.Issuer)
	if err != nil {
		t.Fatalf("ParseStaple: %v", err)
	}
	if !staple.Expired(time.Now()) {
		t.Error("a response whose NextUpdate has passed does not report as expired")
	}
}

// TestParseStapleWithoutNextUpdateNeverExpires covers the difference between
// "no expiry" and "do not cache": a responder that gives no NextUpdate is
// saying the latter, and treating it as stale would be wrong.
func TestParseStapleWithoutNextUpdateNeverExpires(t *testing.T) {
	fx := newStapleFixture(t, ocsp.Response{Status: ocsp.Good})

	staple, err := ParseStaple(fx.DER, fx.Leaf, fx.Issuer)
	if err != nil {
		t.Fatalf("ParseStaple: %v", err)
	}
	if !staple.NextUpdate.IsZero() {
		t.Fatal("the fixture carries a NextUpdate, so the test cannot show its absence")
	}
	if staple.Expired(time.Now().Add(100 * 365 * 24 * time.Hour)) {
		t.Error("a response with no NextUpdate reports as expired")
	}
}

func TestParseStapleNoResponseIsNotAnError(t *testing.T) {
	staple, err := ParseStaple(nil, nil, nil)
	if err != nil {
		t.Errorf("ParseStaple(nil) error = %v, want none: the absence of a staple is not a problem", err)
	}
	if staple != nil {
		t.Errorf("ParseStaple(nil) = %+v, want nil", staple)
	}
}

func TestParseStapleRejectsGarbage(t *testing.T) {
	if _, err := ParseStaple([]byte("not an OCSP response"), nil, nil); err == nil {
		t.Error("bytes that are not an OCSP response parsed without complaint")
	}
}

func TestStapleExpiredOnNil(t *testing.T) {
	var staple *Staple
	if staple.Expired(time.Now()) {
		t.Error("a nil staple reports as expired")
	}
}

func TestRevocationReasonNames(t *testing.T) {
	for reason, want := range map[int]string{
		ocsp.Unspecified:          "unspecified",
		ocsp.KeyCompromise:        "key compromise",
		ocsp.CessationOfOperation: "cessation of operation",
		ocsp.PrivilegeWithdrawn:   "privilege withdrawn",
	} {
		if got := revocationReasonName(reason); got != want {
			t.Errorf("revocationReasonName(%d) = %q, want %q", reason, got, want)
		}
	}
	if got := revocationReasonName(42); !strings.Contains(got, "42") {
		t.Errorf("an unrecognised reason renders as %q, want it to carry the number", got)
	}
}

func TestOCSPStatusNames(t *testing.T) {
	for status, want := range map[int]string{
		ocsp.Good:    "good",
		ocsp.Revoked: "revoked",
		ocsp.Unknown: "unknown",
	} {
		if got := ocspStatusName(status); got != want {
			t.Errorf("ocspStatusName(%d) = %q, want %q", status, got, want)
		}
	}
	if got := ocspStatusName(99); !strings.Contains(got, "99") {
		t.Errorf("an unrecognised status renders as %q, want it to carry the number", got)
	}
}
