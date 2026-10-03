package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

var (
	oidUnknownTest = asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	oidPoison      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidFeature     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
)

// certWithExtensions mints a real self-signed leaf carrying extra, so the
// extensions go through the parser the way a served certificate's would.
func certWithExtensions(t *testing.T, extra ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: "ext.test"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		DNSNames:        []string{"ext.test"},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: extra,
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

func findExtension(exts []Extension, oid string) (Extension, bool) {
	for _, ext := range exts {
		if ext.OID == oid {
			return ext, true
		}
	}
	return Extension{}, false
}

func TestExtensionsNamesWhatItKnows(t *testing.T) {
	exts := Extensions(certWithExtensions(t))
	for oid, name := range map[string]string{
		"2.5.29.15": "Key Usage",
		"2.5.29.37": "Extended Key Usage",
		"2.5.29.17": "Subject Alternative Name",
	} {
		ext, ok := findExtension(exts, oid)
		if !ok {
			t.Errorf("%s (%s) is missing", name, oid)
			continue
		}
		if ext.Name != name {
			t.Errorf("%s named %q, want %q", oid, ext.Name, name)
		}
	}
	if ku, _ := findExtension(exts, "2.5.29.15"); !ku.Critical || ku.Unhandled {
		t.Errorf("Key Usage = %+v, want critical and handled", ku)
	}
}

func TestExtensionsLabelsWhatItDoesNotKnow(t *testing.T) {
	exts := Extensions(certWithExtensions(t, pkix.Extension{Id: oidUnknownTest, Value: []byte{0x05, 0x00}}))
	ext, ok := findExtension(exts, "1.2.3.4.5")
	if !ok {
		t.Fatal("an unknown extension was dropped")
	}
	if ext.Name != "" || ext.Unhandled {
		t.Errorf("unknown non-critical extension = %+v", ext)
	}
	if got, want := ext.Label(), "unrecognized extension (OID 1.2.3.4.5, 2 bytes)"; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}

func TestExtensionsFlagsAnUnhandledCriticalExtension(t *testing.T) {
	cert := certWithExtensions(t, pkix.Extension{Id: oidUnknownTest, Critical: true, Value: []byte{0x05, 0x00}})
	ext, _ := findExtension(Extensions(cert), "1.2.3.4.5")
	if !ext.Critical || !ext.Unhandled {
		t.Fatalf("critical unknown extension = %+v, want unhandled", ext)
	}

	got := ConformanceFindings([]*x509.Certificate{cert})
	if len(got) != 1 || got[0].Problem != ProblemUnhandledExt || !strings.Contains(got[0].Detail, "OID 1.2.3.4.5") {
		t.Fatalf("findings = %+v, want one unhandled critical extension naming the OID", got)
	}
}

func TestExtensionsNamesMustStaple(t *testing.T) {
	mustStaple, _ := asn1.Marshal([]int{5})
	other, _ := asn1.Marshal([]int{17})

	ext, _ := findExtension(Extensions(certWithExtensions(t, pkix.Extension{Id: oidFeature, Value: mustStaple})), oidTLSFeature)
	if ext.Name != "TLS Feature (OCSP Must-Staple)" {
		t.Errorf("status_request feature named %q", ext.Name)
	}
	ext, _ = findExtension(Extensions(certWithExtensions(t, pkix.Extension{Id: oidFeature, Value: other})), oidTLSFeature)
	if ext.Name != "TLS Feature" {
		t.Errorf("a feature other than status_request named %q", ext.Name)
	}
}

// TestPrecertificateIsOneFinding covers the poison extension: it is critical
// and Go does not process it, but the finding is that a precertificate was
// served, not a generic unhandled extension, and it is reported once.
func TestPrecertificateIsOneFinding(t *testing.T) {
	cert := certWithExtensions(t, pkix.Extension{Id: oidPoison, Critical: true, Value: []byte{0x05, 0x00}})
	got := ConformanceFindings([]*x509.Certificate{cert})
	if conformanceProblems(got) != ProblemPrecert {
		t.Fatalf("problems = %q, want only %q", conformanceProblems(got), ProblemPrecert)
	}
}

func TestJSONCertificateCarriesExtensions(t *testing.T) {
	cert := certWithExtensions(t, pkix.Extension{Id: oidUnknownTest, Critical: true, Value: []byte{0x05, 0x00}})
	out, err := json.Marshal(newJSONCertificate(0, cert, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		`{"oid":"2.5.29.15","name":"Key Usage","critical":true}`,
		// No name for what y509 does not know, rather than a guess.
		`{"oid":"1.2.3.4.5","critical":true}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("certificate JSON is missing %s:\n%s", want, got)
		}
	}
}
