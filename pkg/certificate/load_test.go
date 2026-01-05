package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestLoadCertificates_WithPrivateKey(t *testing.T) {
	// Create a temporary file with a certificate AND a private key
	tmpfile, err := os.CreateTemp("", "cert_with_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

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
	pem.Encode(tmpfile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// Write Key
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(tmpfile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	tmpfile.Close()

	// Try to load
	certs, err := LoadCertificates(tmpfile.Name())
	if err != nil {
		t.Errorf("LoadCertificates failed when private key is present: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}
}
