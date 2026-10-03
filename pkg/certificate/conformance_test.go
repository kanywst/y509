package certificate

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rsaKey is a public key whose modulus has exactly bits bits. Nothing is
// signed with it; the rules only read the size.
func rsaKey(bits int) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}
}

func conformanceCert(mod func(*x509.Certificate)) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber:       big.NewInt(7),
		Subject:            pkix.Name{CommonName: "leaf.test"},
		Issuer:             pkix.Name{CommonName: "Test Intermediate"},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          rsaKey(2048),
		DNSNames:           []string{"leaf.test"},
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if mod != nil {
		mod(cert)
	}
	return cert
}

func conformanceProblems(findings []ConformanceFinding) string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Problem)
	}
	return strings.Join(out, ",")
}

func TestConformanceFindings(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*x509.Certificate)
		want string
	}{
		{"clean", nil, ""},
		{"sha-1 leaf", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA1WithRSA }, ProblemWeakSignature},
		{"ecdsa sha-1", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA1 }, ProblemWeakSignature},
		{"md5", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.MD5WithRSA }, ProblemWeakSignature},
		// Setting the issuer to the subject is not self-signing: with no valid
		// signature behind it, the exemption must not apply.
		{"sha-1 with a forged self-issued name", func(c *x509.Certificate) {
			c.SignatureAlgorithm = x509.SHA1WithRSA
			c.Issuer = c.Subject
			c.IsCA = true
		}, ProblemWeakSignature},
		{"rsa 1024", func(c *x509.Certificate) { c.PublicKey = rsaKey(1024) }, ProblemWeakKey},
		{"rsa 2047", func(c *x509.Certificate) { c.PublicKey = rsaKey(2047) }, ProblemWeakKey},
		// A weak root key still fails: the key is what a forger attacks.
		{"rsa 1024 root", func(c *x509.Certificate) { c.PublicKey = rsaKey(1024); c.Issuer = c.Subject; c.IsCA = true }, ProblemWeakKey},
		{"ecdsa key", func(c *x509.Certificate) { c.PublicKey = &ecdsa.PublicKey{} }, ""},
		{"cn only", func(c *x509.Certificate) { c.DNSNames = nil }, ProblemNoSAN},
		{"cn only, no eku", func(c *x509.Certificate) { c.DNSNames = nil; c.ExtKeyUsage = nil }, ProblemNoSAN},
		{"ip san", func(c *x509.Certificate) { c.DNSNames = nil; c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} }, ""},
		// Hostname verification never reads these, so they do not exempt it.
		{"cn plus email san", func(c *x509.Certificate) { c.DNSNames = nil; c.EmailAddresses = []string{"ops@leaf.test"} }, ProblemNoSAN},
		// A SPIFFE workload certificate is matched on its URI, not a host.
		{"spiffe uri san", func(c *x509.Certificate) {
			c.DNSNames = nil
			c.URIs = []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/ns/default/sa/web"}}
		}, ""},
		{"code signing", func(c *x509.Certificate) {
			c.DNSNames = nil
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}, ""},
		{"ca without san", func(c *x509.Certificate) { c.DNSNames = nil; c.IsCA = true }, ""},
		{"no cn, no san", func(c *x509.Certificate) { c.DNSNames = nil; c.Subject = pkix.Name{} }, ""},
		{"everything wrong", func(c *x509.Certificate) {
			c.SignatureAlgorithm = x509.SHA1WithRSA
			c.PublicKey = rsaKey(1024)
			c.DNSNames = nil
		}, ProblemWeakSignature + "," + ProblemWeakKey + "," + ProblemNoSAN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConformanceFindings([]*x509.Certificate{conformanceCert(tt.mod)})
			if conformanceProblems(got) != tt.want {
				t.Fatalf("problems = %q, want %q", conformanceProblems(got), tt.want)
			}
			for _, f := range got {
				if f.Subject == "" || f.Detail == "" {
					t.Errorf("%s is missing its subject or detail: %+v", f.Problem, f)
				}
			}
		})
	}
}

// TestConformanceExemptsAGenuineSHA1Root signs a root with SHA-1 for real. Its
// own signature is never checked by a client, so it is not a finding.
func TestConformanceExemptsAGenuineSHA1Root(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SHA-1 Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA1WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if root.SignatureAlgorithm != x509.SHA1WithRSA {
		t.Fatalf("fixture is signed with %s, not SHA-1", root.SignatureAlgorithm)
	}
	if got := ConformanceFindings([]*x509.Certificate{root}); len(got) != 0 {
		t.Fatalf("a genuine SHA-1 root was reported: %+v", got)
	}
}

func TestConformanceFindingsSkipsNil(t *testing.T) {
	if got := ConformanceFindings([]*x509.Certificate{nil}); len(got) != 0 {
		t.Fatalf("nil certificate produced %+v", got)
	}
}

// TestJSONConformanceShape pins the contract: always present, ok with an empty
// array when nothing is wrong, in both the report and the inspection.
func TestJSONConformanceShape(t *testing.T) {
	clean := NewJSONReport("", &ChainReport{Sent: []*x509.Certificate{conformanceCert(nil)}}, nil)
	out, err := json.Marshal(clean.Conformance)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"ok":true,"findings":[]}` {
		t.Errorf("clean chain = %s", out)
	}

	weak := &ChainReport{Sent: []*x509.Certificate{conformanceCert(func(c *x509.Certificate) { c.PublicKey = rsaKey(1024) })}}
	for name, got := range map[string]JSONConformance{
		"report":     NewJSONReport("", weak, nil).Conformance,
		"inspection": NewJSONInspection("", weak).Conformance,
	} {
		if got.OK || len(got.Findings) != 1 || got.Findings[0].Problem != ProblemWeakKey || got.Findings[0].Subject != "leaf.test" {
			t.Errorf("%s: conformance = %+v", name, got)
		}
	}

	// No report at all still marshals an array, never null.
	out, err = json.Marshal(NewJSONReport("", nil, nil).Conformance)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"findings":[]`) {
		t.Errorf("nil report = %s", out)
	}
}

func TestFormatConformanceFindings(t *testing.T) {
	if FormatConformanceFindings(nil) != "" {
		t.Error("no findings should print nothing")
	}
	got := FormatConformanceFindings([]ConformanceFinding{{Problem: ProblemNoSAN, Subject: "leaf.test", Detail: "why"}})
	if !strings.HasPrefix(got, "Conformance:\n") || !strings.Contains(got, "• no SAN: leaf.test") {
		t.Errorf("unexpected text:\n%s", got)
	}
}
