package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// p12Fixture builds a real PKCS#12 file, so the test exercises the library the
// way a Windows export would arrive rather than a hand-made structure.
func p12Fixture(t *testing.T, password string) (data []byte, leafCN string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "p12 test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the CA: %v", err)
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
		Subject:      pkix.Name{CommonName: "leaf.p12.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"leaf.p12.example"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}

	out, err := pkcs12.Modern.Encode(leafKey, leaf, []*x509.Certificate{ca}, password)
	if err != nil {
		t.Fatalf("encoding the PKCS#12 file: %v", err)
	}
	return out, "leaf.p12.example"
}

func TestParsePKCS12ReadsTheChain(t *testing.T) {
	data, leafCN := p12Fixture(t, "hunter2")

	certs, err := ParsePKCS12(data, "hunter2")
	if err != nil {
		t.Fatalf("ParsePKCS12: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("parsed %d certificates, want the leaf and its CA", len(certs))
	}
	// Leaf first, which is the order everything downstream expects.
	if cn := certs[0].Certificate.Subject.CommonName; cn != leafCN {
		t.Errorf("first certificate is %q, want the leaf", cn)
	}
	if !certs[1].Certificate.IsCA {
		t.Error("the second certificate is not the CA")
	}
}

// TestParsePKCS12DistinguishesAPasswordFromAFormat is what lets the command
// decide whether asking the user for anything is worthwhile.
func TestParsePKCS12DistinguishesAPasswordFromAFormat(t *testing.T) {
	data, _ := p12Fixture(t, "hunter2")

	if _, err := ParsePKCS12(data, "wrong"); err != ErrPKCS12Password {
		t.Errorf("a wrong password gave %v, want ErrPKCS12Password", err)
	}
	if _, err := ParsePKCS12([]byte("not a container"), ""); err == ErrPKCS12Password {
		t.Error("a file that is not PKCS#12 was reported as a password problem")
	}
}

func TestParsePKCS12ReadsATrustStore(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trusted root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the root: %v", err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the root: %v", err)
	}

	// A truststore holds certificates and no key, which is what a CA bundle in
	// this format looks like and what DecodeChain refuses.
	store, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{root}, "")
	if err != nil {
		t.Fatalf("encoding the trust store: %v", err)
	}

	certs, err := ParsePKCS12(store, "")
	if err != nil {
		t.Fatalf("ParsePKCS12 on a trust store: %v", err)
	}
	if len(certs) != 1 || certs[0].Certificate.Subject.CommonName != "trusted root" {
		t.Errorf("trust store parsed to %d certificates", len(certs))
	}
}

func TestParsePKCS12RejectsSomethingElse(t *testing.T) {
	_, err := ParsePKCS12([]byte{0x30, 0x03, 0x02, 0x01, 0x00}, "")
	if err == nil {
		t.Fatal("a non-PKCS#12 DER structure parsed as a container")
	}
	if !strings.Contains(err.Error(), "not a PKCS#12 container") {
		t.Errorf("error = %q", err)
	}
}

func TestLooksLikePKCS12(t *testing.T) {
	data, _ := p12Fixture(t, "")
	if !LooksLikePKCS12(data) {
		t.Error("a real PKCS#12 file was not recognised by shape")
	}

	// A certificate is a SEQUENCE whose first element is the tbsCertificate
	// SEQUENCE, not an INTEGER, so it must not be mistaken for one.
	cert := containerCert(t, "leaf.example.com")
	if LooksLikePKCS12(cert.Raw) {
		t.Error("a certificate was mistaken for a PKCS#12 file")
	}

	for _, input := range [][]byte{nil, []byte("hello"), {0x30, 0x00}} {
		if LooksLikePKCS12(input) {
			t.Errorf("%q was mistaken for a PKCS#12 file", input)
		}
	}
}

// TestPKCS12ShapedButUndecodable is the case the shape check exists for: the
// file is a PKCS#12 file and cannot be read, and saying "not a certificate"
// would send the reader looking at the wrong thing.
func TestPKCS12ShapedButUndecodable(t *testing.T) {
	data, _ := p12Fixture(t, "")

	_ = data

	// A well-formed SEQUENCE opening with the version INTEGER, and nothing
	// usable after it: the shape of a PKCS#12 file this cannot decode.
	var body []byte
	body = append(body, mustMarshalASN1(t, 3)...)
	body = append(body, mustMarshalASN1(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
	})...)
	shaped := mustMarshalASN1(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body,
	})

	if !LooksLikePKCS12(shaped) {
		t.Fatal("the fixture is not PKCS#12-shaped, so it tests nothing")
	}
	if _, err := ParsePKCS12(shaped, ""); err == nil {
		t.Error("an undecodable PKCS#12-shaped file parsed")
	}
}

func mustMarshalASN1(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return b
}
