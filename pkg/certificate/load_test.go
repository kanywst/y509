package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadCertificates_WithPrivateKey(t *testing.T) {
	// Create a temporary file with a certificate AND a private key
	tmpfile, err := os.CreateTemp("", "cert_with_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	// Generate a key and cert
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	// Write Cert
	if err := pem.Encode(tmpfile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		t.Fatal(err)
	}

	// Write Key
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	if err := pem.Encode(tmpfile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatal(err)
	}

	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Try to load
	certs, err := LoadCertificates(tmpfile.Name())
	if err != nil {
		t.Errorf("LoadCertificates failed when private key is present: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}
}

// TestParseCertificates_NumbersCertificatesNotBlocks pins the invariant that
// Info.Index equals the slice position and the label counts from 1, even when
// the bundle carries non-certificate PEM blocks. A key concatenated ahead of
// the chain used to consume number 1, so the first certificate came out as
// "2." and every Index was shifted by one.
func TestParseCertificates_NumbersCertificatesNotBlocks(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	newCert := func(serial int64, cn string) []byte {
		template := x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	// A private key ahead of the chain, and a second one wedged between the
	// certificates for good measure.
	var bundle []byte
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert(1, "leaf.example.com")})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: []byte("ignored")})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert(2, "intermediate.example.com")})...)

	certs, err := ParseCertificates(bundle)
	if err != nil {
		t.Fatalf("ParseCertificates failed: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(certs))
	}

	for i, info := range certs {
		if info.Index != i {
			t.Errorf("certificate %d: Index = %d, want %d", i, info.Index, i)
		}
		wantPrefix := fmt.Sprintf("%d. ", i+1)
		if !strings.HasPrefix(info.Label, wantPrefix) {
			t.Errorf("certificate %d: Label = %q, want it to start with %q", i, info.Label, wantPrefix)
		}
	}
}
