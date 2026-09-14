package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// writeP12 builds a real PKCS#12 file and returns its path.
func writeP12(t *testing.T, password string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "p12.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}

	data, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatalf("encoding the PKCS#12 file: %v", err)
	}

	path := filepath.Join(t.TempDir(), "bundle.p12")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	return path
}

// TestPKCS12WithoutAPasswordNeedsNoPrompt is the reason the empty password is
// tried first: a bundle exported to move certificates around often has none,
// and asking for one that is not needed trains people to type a password
// anywhere they are asked.
func TestPKCS12WithoutAPasswordNeedsNoPrompt(t *testing.T) {
	path := writeP12(t, "")

	out, err := runRoot(t, path, "--json")
	if err != nil {
		t.Fatalf("reading an unprotected PKCS#12 file: %v", err)
	}
	if !strings.Contains(out, "p12.example.com") {
		t.Errorf("the certificate is not in the output:\n%s", out)
	}
}

func TestPKCS12ReadsThePasswordFromTheEnvironment(t *testing.T) {
	path := writeP12(t, "hunter2")
	t.Setenv("Y509_PKCS12_PASSWORD", "hunter2")

	out, err := runRoot(t, path, "--json")
	if err != nil {
		t.Fatalf("reading a protected PKCS#12 file: %v", err)
	}
	if !strings.Contains(out, "p12.example.com") {
		t.Errorf("the certificate is not in the output:\n%s", out)
	}
}

func TestPKCS12ReadsThePasswordFromAFile(t *testing.T) {
	path := writeP12(t, "hunter2")

	// A trailing newline is what an editor leaves behind and is almost never
	// part of the password.
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatalf("writing the password file: %v", err)
	}

	if _, err := runRoot(t, path, "--password-file", passwordFile, "--json"); err != nil {
		t.Fatalf("reading with a password file: %v", err)
	}
}

func TestPKCS12ReportsAWrongPassword(t *testing.T) {
	path := writeP12(t, "hunter2")
	t.Setenv("Y509_PKCS12_PASSWORD", "wrong")

	_, err := runRoot(t, path, "--json")
	if err == nil {
		t.Fatal("a wrong password was accepted")
	}
	// The message has to be about the password, not about the file not being
	// a certificate, or the reader looks in the wrong place.
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error = %q, want it to name the password", err)
	}
}

func TestPKCS12DoesNotProvokeAPromptForOtherInput(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	// A PEM file parses before the PKCS#12 path is reached, so nothing here
	// can ask for a password.
	if _, err := runRoot(t, path, "--json"); err != nil {
		t.Fatalf("reading a PEM file: %v", err)
	}
}

// TestPKCS12ShapedFileReportsAPKCS12Error keeps the message pointing at the
// right thing: a file that is a PKCS#12 file and cannot be decoded should not
// be reported as not being a certificate.
func TestPKCS12ShapedFileReportsAPKCS12Error(t *testing.T) {
	path := writeP12(t, "hunter2")
	t.Setenv("Y509_PKCS12_PASSWORD", "wrong")

	_, err := runRoot(t, path, "--json")
	if err == nil {
		t.Fatal("a wrong password was accepted")
	}
	if strings.Contains(err.Error(), "not a certificate") {
		t.Errorf("error = %q, want it to be about the PKCS#12 file", err)
	}
}

// TestPKCS12TrustStoreWorksAsRoots is why the input path is shared: a PKCS#12
// truststore is a normal way to ship trust anchors, and reading it only for the
// chain under inspection would be an arbitrary line to draw.
func TestPKCS12TrustStoreWorksAsRoots(t *testing.T) {
	chain := newTestChain(t)
	chainPath := write(t, "chain.pem", chain.ChainPEM)

	// The chain's own CA, packed as a PKCS#12 truststore.
	caBlock := caCertificateOf(t, chain.ChainPEM)

	store, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{caBlock}, "")
	if err != nil {
		t.Fatalf("encoding the trust store: %v", err)
	}
	storePath := filepath.Join(t.TempDir(), "roots.p12")
	if err := os.WriteFile(storePath, store, 0o600); err != nil {
		t.Fatalf("writing the trust store: %v", err)
	}

	if _, err := runRoot(t, "validate", chainPath, "--roots", storePath, "--no-system-roots"); err != nil {
		t.Fatalf("a chain was not trusted against its own CA in a PKCS#12 truststore: %v", err)
	}
}

// caCertificateOf returns the last certificate in a PEM bundle, which for the
// test chain is the CA.
func caCertificateOf(t *testing.T, bundle []byte) *x509.Certificate {
	t.Helper()

	var last *x509.Certificate
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing a certificate from the bundle: %v", err)
		}
		last = cert
	}
	if last == nil {
		t.Fatal("the bundle holds no certificates")
	}
	return last
}
