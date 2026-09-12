package certificate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// partialCert signs a throwaway self-signed certificate with the given common
// name, so a bundle can be assembled from real DER.
func partialCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}

// corruptBlock is a CERTIFICATE block holding bytes that are not a certificate.
// The armour is valid, so pem.Decode hands it over and x509 is what refuses --
// which is the shape of the real case: a well-formed block carrying something
// this version of Go cannot read.
func corruptBlock() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00},
	})
}

// TestParseKeepsGoingPastAnUnreadableBlock is the bug: one certificate Go
// declines used to abort the whole input, so a bundle of good/bad/good showed
// nothing at all.
func TestParseKeepsGoingPastAnUnreadableBlock(t *testing.T) {
	first := partialCert(t, "first")
	second := partialCert(t, "second")

	var bundle bytes.Buffer
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Raw}))
	bundle.Write(corruptBlock())
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Raw}))

	certs, failures, err := ParseCertificatesReport(bundle.Bytes())
	if err != nil {
		t.Fatalf("ParseCertificatesReport: %v", err)
	}

	if len(certs) != 2 {
		t.Fatalf("parsed %d certificates, want the two that are readable", len(certs))
	}
	if cn := certs[0].Certificate.Subject.CommonName; cn != "first" {
		t.Errorf("first certificate is %q, want %q", cn, "first")
	}
	if cn := certs[1].Certificate.Subject.CommonName; cn != "second" {
		t.Errorf("second certificate is %q, want %q", cn, "second")
	}

	if len(failures) != 1 {
		t.Fatalf("reported %d failures, want 1", len(failures))
	}
	if failures[0].Block != 1 {
		t.Errorf("failure is at block %d, want 1", failures[0].Block)
	}
	if len(failures[0].Raw) == 0 {
		t.Error("failure carries no raw DER, so a caller cannot report its size")
	}
	if failures[0].Err == nil {
		t.Error("failure carries no error")
	}
}

// TestParseIndexesStayAlignedWithTheInput pins the numbering: a skipped block
// still consumes a position, so "certificate 2" means the third one in the file
// whether or not the second could be read.
func TestParseIndexesStayAlignedWithTheInput(t *testing.T) {
	first := partialCert(t, "first")
	second := partialCert(t, "second")

	var bundle bytes.Buffer
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Raw}))
	bundle.Write(corruptBlock())
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Raw}))

	certs, failures, err := ParseCertificatesReport(bundle.Bytes())
	if err != nil {
		t.Fatalf("ParseCertificatesReport: %v", err)
	}

	if certs[0].Index != 0 {
		t.Errorf("first certificate has Index %d, want 0", certs[0].Index)
	}
	if certs[1].Index != 2 {
		t.Errorf("second readable certificate has Index %d, want 2: the skipped block keeps its place", certs[1].Index)
	}
	if failures[0].Block != certs[1].Index-1 {
		t.Errorf("failure block %d does not sit between the two certificates", failures[0].Block)
	}
}

// TestParseStillFailsWhenNothingIsReadable keeps the useful error: skipping is
// for a bundle that holds something, not for an input that holds nothing.
func TestParseStillFailsWhenNothingIsReadable(t *testing.T) {
	certs, failures, err := ParseCertificatesReport(corruptBlock())

	if err == nil {
		t.Fatal("parsing succeeded for an input with no readable certificate")
	}
	if len(certs) != 0 {
		t.Errorf("parsed %d certificates from an unreadable input", len(certs))
	}
	if len(failures) != 1 {
		t.Errorf("reported %d failures, want 1", len(failures))
	}
	// The message has to name the block, or the only clue is "it failed".
	if !strings.Contains(err.Error(), "certificate 0") {
		t.Errorf("error = %q, want it to name the block that failed", err)
	}
}

func TestLoadCertificatesSkipsUnreadableBlocks(t *testing.T) {
	cert := partialCert(t, "only")

	var bundle bytes.Buffer
	bundle.Write(corruptBlock())
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	path := t.TempDir() + "/bundle.pem"
	if err := os.WriteFile(path, bundle.Bytes(), 0o600); err != nil {
		t.Fatalf("writing the bundle: %v", err)
	}

	certs, failures, err := LoadCertificatesReport(path)
	if err != nil {
		t.Fatalf("LoadCertificatesReport: %v", err)
	}
	if len(certs) != 1 || len(failures) != 1 {
		t.Fatalf("got %d certificates and %d failures, want 1 and 1", len(certs), len(failures))
	}

	// The compatibility wrapper must behave the same, minus the report.
	plain, err := LoadCertificates(path)
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}
	if len(plain) != 1 {
		t.Errorf("LoadCertificates returned %d certificates, want 1", len(plain))
	}
}

func TestNewJSONUnparsedIsAbsentWhenEverythingParsed(t *testing.T) {
	if got := NewJSONUnparsed(nil); got != nil {
		t.Errorf("NewJSONUnparsed(nil) = %v, want nil so the key is omitted", got)
	}

	got := NewJSONUnparsed([]ParseFailure{{Block: 3, Raw: []byte{1, 2, 3}, Err: errForTest("bad")}})
	if len(got) != 1 {
		t.Fatalf("NewJSONUnparsed returned %d entries, want 1", len(got))
	}
	if got[0].Index != 3 || got[0].Bytes != 3 || got[0].Error != "bad" {
		t.Errorf("NewJSONUnparsed()[0] = %+v, want index 3, 3 bytes and the error text", got[0])
	}
}

type errForTest string

func (e errForTest) Error() string { return string(e) }
