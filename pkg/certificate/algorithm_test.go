package certificate

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestMLDSACertificateIsNamedByGo signs a real ML-DSA-65 certificate. From Go
// 1.27 crypto/x509 decodes it, so the names come from the standard library and
// the key is described rather than labelled unrecognized.
func TestMLDSACertificateIsNamedByGo(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(65),
		Subject:      pkix.Name{CommonName: "mldsa.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"mldsa.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	if got := SignatureAlgorithmName(cert); got != "ML-DSA-65" {
		t.Errorf("SignatureAlgorithmName = %q, want ML-DSA-65", got)
	}
	if got := PublicKeyAlgorithmName(cert); got != "ML-DSA" {
		t.Errorf("PublicKeyAlgorithmName = %q, want ML-DSA", got)
	}
	got := FormatPublicKey(cert)
	for _, want := range []string{"ML-DSA-65 (post-quantum)", "Key Size: 1952 bytes"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatPublicKey is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Unrecognized") {
		t.Errorf("an ML-DSA key went down the unrecognized path:\n%s", got)
	}
	if conformance := ConformanceFindings([]*x509.Certificate{cert}); len(conformance) != 0 {
		t.Errorf("an ML-DSA certificate breaks no client rule: %+v", conformance)
	}
}

func algorithmIdentifierDER(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	der, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oid})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestSignatureAlgorithmNameReadsTheOID covers what crypto/x509 prints as "0".
func TestSignatureAlgorithmNameReadsTheOID(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{"known to Go", &x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA256}, "ECDSA-SHA256"},
		{"SLH-DSA", &x509.Certificate{RawSignatureAlgorithm: algorithmIdentifierDER(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24})}, "SLH-DSA-SHA2-256s"},
		{"unknown OID", &x509.Certificate{RawSignatureAlgorithm: algorithmIdentifierDER(t, asn1.ObjectIdentifier{1, 2, 3, 4})}, "unknown (OID 1.2.3.4)"},
		{"garbage", &x509.Certificate{RawSignatureAlgorithm: []byte{0xff}}, "unknown"},
		{"nil", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SignatureAlgorithmName(tt.cert); got != tt.want {
				t.Errorf("SignatureAlgorithmName = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPublicKeyAlgorithmNameReadsTheSPKI(t *testing.T) {
	spki, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}},
		PublicKey: asn1.BitString{Bytes: []byte{1}, BitLength: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := PublicKeyAlgorithmName(&x509.Certificate{RawSubjectPublicKeyInfo: spki}); got != "SLH-DSA-SHAKE-128s" {
		t.Errorf("PublicKeyAlgorithmName = %q, want SLH-DSA-SHAKE-128s", got)
	}
	if got := PublicKeyAlgorithmName(&x509.Certificate{PublicKeyAlgorithm: x509.RSA}); got != "RSA" {
		t.Errorf("PublicKeyAlgorithmName = %q, want RSA", got)
	}
}
