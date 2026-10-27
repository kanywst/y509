package certificate

import (
	"crypto/dsa" //nolint:staticcheck // only to hand the rules a DSA key
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPolicyFindingsFIPS(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*x509.Certificate)
		want string
	}{
		{"rsa 2048 sha-256", nil, ""},
		{"rsa-pss sha-384", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA384WithRSAPSS }, ""},
		{"ecdsa p-256", func(c *x509.Certificate) {
			c.SignatureAlgorithm = x509.ECDSAWithSHA256
			c.PublicKey = &ecdsa.PublicKey{Curve: elliptic.P256()}
		}, ""},
		{"ecdsa p-224", func(c *x509.Certificate) { c.PublicKey = &ecdsa.PublicKey{Curve: elliptic.P224()} }, ProblemUnapprovedKey},
		{"ed25519", func(c *x509.Certificate) {
			c.SignatureAlgorithm = x509.PureEd25519
			c.PublicKey = ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
		}, ""},
		{"ml-dsa-65 signature", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.MLDSA65 }, ""},
		{"sha-1", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA1WithRSA }, ProblemUnapprovedSignature},
		{"ecdsa sha-1", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA1 }, ProblemUnapprovedSignature},
		{"md5", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.MD5WithRSA }, ProblemUnapprovedSignature},
		// Setting the issuer to the subject is not self-signing.
		{"sha-1 with a forged self-issued name", func(c *x509.Certificate) {
			c.SignatureAlgorithm = x509.SHA1WithRSA
			c.Issuer = c.Subject
			c.IsCA = true
		}, ProblemUnapprovedSignature},
		{"rsa 1024", func(c *x509.Certificate) { c.PublicKey = rsaKey(1024) }, ProblemUnapprovedKey},
		{"rsa 3071, odd size", func(c *x509.Certificate) { c.PublicKey = rsaKey(3071) }, ProblemUnapprovedKey},
		{"rsa exponent 3", func(c *x509.Certificate) { c.PublicKey.(*rsa.PublicKey).E = 3 }, ProblemUnapprovedKey},
		{"rsa exponent 65536", func(c *x509.Certificate) { c.PublicKey.(*rsa.PublicKey).E = 1 << 16 }, ProblemUnapprovedKey},
		{"rsa even exponent", func(c *x509.Certificate) { c.PublicKey.(*rsa.PublicKey).E = 1<<16 + 2 }, ProblemUnapprovedKey},
		{"dsa key", func(c *x509.Certificate) { c.PublicKey = &dsa.PublicKey{} }, ProblemUnapprovedKey},
		// Both at once are both reported: the fix differs.
		{"sha-1 and rsa 1024", func(c *x509.Certificate) {
			c.SignatureAlgorithm = x509.SHA1WithRSA
			c.PublicKey = rsaKey(1024)
		}, ProblemUnapprovedSignature + "," + ProblemUnapprovedKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := conformanceCert(tt.mod)
			got := conformanceProblems(PolicyFindings(PolicyFIPS, []*x509.Certificate{cert}))
			if got != tt.want {
				t.Errorf("problems = %q, want %q", got, tt.want)
			}
		})
	}
}

// A SHA-1 self-signature on a root is never checked, in FIPS mode or out, but
// the root's key still verifies the certificate below it.
func TestPolicyFindingsFIPSSelfSignedRoot(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := selfSign(t, selfSignTemplate("SHA-1 Root", x509.SHA1WithRSA), &key.PublicKey, key)
	if got := conformanceProblems(PolicyFindings(PolicyFIPS, []*x509.Certificate{root})); got != "" {
		t.Errorf("a genuine SHA-1 self-signature was reported: %q", got)
	}

	weak := conformanceCert(func(c *x509.Certificate) {
		c.PublicKey = rsaKey(1024)
		c.Issuer = c.Subject
		c.IsCA = true
	})
	if got := conformanceProblems(PolicyFindings(PolicyFIPS, []*x509.Certificate{weak})); got != ProblemUnapprovedKey {
		t.Errorf("a 1024-bit root key gave %q, want %q", got, ProblemUnapprovedKey)
	}
}

// Go does not decode SLH-DSA, so its approval rests on the name read from
// the OID. An algorithm nobody can name cannot be shown to be approved.
func TestPolicyFindingsFIPSUndecodedAlgorithms(t *testing.T) {
	slh := conformanceCert(func(c *x509.Certificate) {
		c.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
		c.RawSignatureAlgorithm = algorithmIdentifier(t, "2.16.840.1.101.3.4.3.24")
	})
	if got := conformanceProblems(PolicyFindings(PolicyFIPS, []*x509.Certificate{slh})); got != "" {
		t.Errorf("SLH-DSA-SHA2-256s was reported: %q", got)
	}

	unknown := conformanceCert(func(c *x509.Certificate) {
		c.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
		c.RawSignatureAlgorithm = algorithmIdentifier(t, "1.2.3.4")
	})
	findings := PolicyFindings(PolicyFIPS, []*x509.Certificate{unknown})
	if got := conformanceProblems(findings); got != ProblemUnapprovedSignature {
		t.Fatalf("an unknown algorithm gave %q, want %q", got, ProblemUnapprovedSignature)
	}
	if !strings.Contains(findings[0].Detail, "OID 1.2.3.4") {
		t.Errorf("detail does not name the OID: %q", findings[0].Detail)
	}
}

// A real ML-DSA certificate, so the key is the type crypto/x509 hands back.
func TestPolicyFindingsFIPSMLDSA(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSign(t, selfSignTemplate("ML-DSA Root", 0), key.PublicKey(), key)
	if got := conformanceProblems(PolicyFindings(PolicyFIPS, []*x509.Certificate{cert})); got != "" {
		t.Errorf("an ML-DSA-44 certificate was reported: %q", got)
	}
}

func TestParsePolicy(t *testing.T) {
	for _, name := range []string{"fips", "FIPS"} {
		if p, err := ParsePolicy(name); err != nil || p != PolicyFIPS {
			t.Errorf("ParsePolicy(%q) = %q, %v", name, p, err)
		}
	}
	if _, err := ParsePolicy("fips-level-3"); err == nil || !strings.Contains(err.Error(), "fips") {
		t.Errorf("an unknown policy gave %v, want an error listing the known ones", err)
	}
}

func TestFormatPolicyFindings(t *testing.T) {
	if got := FormatPolicyFindings(PolicyFIPS, nil); got != "FIPS 140-3: met" {
		t.Errorf("a pass is silent: %q", got)
	}

	findings := PolicyFindings(PolicyFIPS, []*x509.Certificate{
		conformanceCert(func(c *x509.Certificate) { c.PublicKey = rsaKey(1024) }),
	})
	got := FormatPolicyFindings(PolicyFIPS, findings)
	for _, want := range []string{"FIPS 140-3:", ProblemUnapprovedKey, "leaf.test", "1024 bits"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestNewJSONPolicy(t *testing.T) {
	raw, err := json.Marshal(NewJSONPolicy(PolicyFIPS, nil))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"name":"fips","ok":true,"findings":[]}`; string(raw) != want {
		t.Errorf("got %s, want %s", raw, want)
	}
}

// selfSign signs tmpl with itself for real and parses the result.
func selfSign(t *testing.T, tmpl *x509.Certificate, pub, priv any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func selfSignTemplate(name string, alg x509.SignatureAlgorithm) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    alg,
	}
}

// algorithmIdentifier is the DER AlgorithmIdentifier for oid.
func algorithmIdentifier(t *testing.T, oid string) []byte {
	t.Helper()
	var parsed asn1.ObjectIdentifier
	for _, part := range strings.Split(oid, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, n)
	}
	der, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: parsed})
	if err != nil {
		t.Fatal(err)
	}
	return der
}
