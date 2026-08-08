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
	"testing"
	"time"
)

// testChain is a two-certificate chain generated per test run. Committing
// fixtures would mean fixtures that expire, and validate's whole job is to
// notice expiry.
type testChain struct {
	// LeafPEM is the leaf on its own.
	LeafPEM []byte
	// ChainPEM is leaf then CA, the order a server should present.
	ChainPEM []byte
	// CAPEM is the root, usable as a --roots file.
	CAPEM []byte
	// Leaf and CA are the parsed forms, for building a tls.Certificate.
	Leaf, CA *x509.Certificate
	// LeafKey signs for the leaf.
	LeafKey *ecdsa.PrivateKey
}

func newTestChain(t *testing.T, dnsNames ...string) *testChain {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "y509 test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("signing the CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing the CA: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "y509 test leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("signing the leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}

	encode := func(ders ...[]byte) []byte {
		var out []byte
		for _, der := range ders {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		return out
	}

	return &testChain{
		LeafPEM:  encode(leafDER),
		ChainPEM: encode(leafDER, caDER),
		CAPEM:    encode(caDER),
		Leaf:     leaf,
		CA:       ca,
		LeafKey:  leafKey,
	}
}

// write puts the given PEM in a fresh temp file and returns its path.
func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}
