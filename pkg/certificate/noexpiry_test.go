package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// certNotAfter mints a real certificate, so NotAfter makes the round trip
// through GeneralizedTime the way a 9999-12-31 certificate's would.
func certNotAfter(t *testing.T, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "forever.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"forever.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestHasNoExpiry(t *testing.T) {
	if !HasNoExpiry(certNotAfter(t, noExpirySentinel)) {
		t.Error("the RFC 5280 sentinel was not recognised")
	}
	// A real date, however distant, is still a date.
	if HasNoExpiry(certNotAfter(t, noExpirySentinel.Add(-time.Second))) {
		t.Error("9999-12-31 23:59:58 is not the sentinel")
	}
	if HasNoExpiry(nil) {
		t.Error("nil has no NotAfter to read")
	}
}

// TestFormatValidityNoExpiry pins the overflow: time.Duration saturates near
// 292 years, which printed the sentinel as "Expires in: 2562047h47m16s".
func TestFormatValidityNoExpiry(t *testing.T) {
	got := FormatValidity(certNotAfter(t, noExpirySentinel))
	if !strings.Contains(got, "Expires in: never") || !strings.Contains(got, "no well-defined expiration") {
		t.Errorf("sentinel validity:\n%s", got)
	}
	if strings.Contains(got, "2562047h") {
		t.Errorf("saturated duration leaked into the output:\n%s", got)
	}
}

func TestJSONCertificateNoExpiry(t *testing.T) {
	out, err := json.Marshal(newJSONCertificate(0, certNotAfter(t, noExpirySentinel), time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		NoExpiry        bool `json:"noExpiry"`
		DaysUntilExpiry int  `json:"daysUntilExpiry"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !got.NoExpiry {
		t.Errorf("noExpiry = false for the sentinel: %s", out)
	}
	// The arithmetic is kept, so a threshold comparison still says "far away".
	if got.DaysUntilExpiry < 2_000_000 {
		t.Errorf("daysUntilExpiry = %d, want the real distance", got.DaysUntilExpiry)
	}

	out, err = json.Marshal(newJSONCertificate(0, certNotAfter(t, time.Now().Add(48*time.Hour)), time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"noExpiry":false`) {
		t.Errorf("an ordinary certificate must say noExpiry:false: %s", out)
	}
}
