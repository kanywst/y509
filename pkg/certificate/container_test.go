package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// containerCert signs a throwaway certificate for packing into a container.
func containerCert(t *testing.T, cn string) *x509.Certificate {
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

// buildPKCS7 packs certificates into a signedData container, the shape Windows
// and several CAs hand out as a .p7b.
func buildPKCS7(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()

	var raw []byte
	for _, cert := range certs {
		raw = append(raw, cert.Raw...)
	}

	// SignedData, assembled field by field: version, an empty set of digest
	// algorithms, the encapsulated content, then the certificates in [0].
	var body []byte
	body = append(body, mustMarshal(t, 1)...)
	body = append(body, mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
	})...)
	body = append(body, mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: mustMarshal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}),
	})...)
	if len(raw) > 0 {
		body = append(body, mustMarshal(t, asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw,
		})...)
	}

	signed := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body,
	})

	// ContentInfo: the signedData OID, then the SignedData inside an explicit
	// [0]. Built from raw values rather than a tagged struct, because
	// asn1.Marshal writes a RawValue's FullBytes verbatim and would leave the
	// wrapper off -- which is not what a real .p7b looks like.
	inner := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signed,
	})

	return mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(mustMarshal(t, oidSignedData), inner...),
	})
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return b
}

// TestParsePKCS7ReadsABundle covers the format a Windows CA hands out, which
// previously reached the DER path and failed with nothing useful to say.
func TestParsePKCS7ReadsABundle(t *testing.T) {
	leaf := containerCert(t, "leaf.example.com")
	ca := containerCert(t, "Example CA")

	certs, failures, err := ParseCertificatesReport(buildPKCS7(t, leaf, ca))
	if err != nil {
		t.Fatalf("ParseCertificatesReport: %v", err)
	}
	if len(failures) != 0 {
		t.Errorf("reported %d failures for a clean bundle", len(failures))
	}
	if len(certs) != 2 {
		t.Fatalf("parsed %d certificates, want 2", len(certs))
	}
	// Order is the evidence, and PKCS#7 carries no promise about it, so it has
	// to come back as it was stored rather than sorted.
	if cn := certs[0].Certificate.Subject.CommonName; cn != "leaf.example.com" {
		t.Errorf("first certificate is %q, want the one stored first", cn)
	}
	if certs[1].Index != 1 {
		t.Errorf("second certificate has Index %d, want 1", certs[1].Index)
	}
}

func TestParsePKCS7RejectsAContainerWithNoCertificates(t *testing.T) {
	if _, err := parsePKCS7(buildPKCS7(t)); err == nil {
		t.Error("an empty PKCS#7 container parsed as a chain")
	}
}

// kubeSecret builds what `kubectl get secret -o json` prints.
func kubeSecret(t *testing.T, data map[string][]byte) []byte {
	t.Helper()

	encoded := map[string]string{}
	for k, v := range data {
		encoded[k] = base64.StdEncoding.EncodeToString(v)
	}
	out, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/tls",
		"data":       encoded,
	})
	if err != nil {
		t.Fatalf("encoding the secret: %v", err)
	}
	return out
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// TestParseKubernetesSecret covers the shape people actually have: a chain
// inside a base64 field inside JSON, which otherwise needs a jq and a base64
// before y509 can see it at all.
func TestParseKubernetesSecret(t *testing.T) {
	leaf := containerCert(t, "leaf.example.com")
	ca := containerCert(t, "Example CA")

	secret := kubeSecret(t, map[string][]byte{
		"tls.crt": certPEM(leaf),
		"ca.crt":  certPEM(ca),
		// A real TLS secret also carries the key. It must be ignored rather
		// than parsed, and the fixture does not need to look like a real one
		// to prove that.
		"tls.key": []byte("this is not a certificate"),
	})

	certs, _, err := ParseCertificatesReport(secret)
	if err != nil {
		t.Fatalf("ParseCertificatesReport: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("parsed %d certificates, want the served chain and the CA", len(certs))
	}
	// tls.crt before ca.crt, so the leaf is first and the chain reads the way
	// it was served.
	if cn := certs[0].Certificate.Subject.CommonName; cn != "leaf.example.com" {
		t.Errorf("first certificate is %q, want the leaf from tls.crt", cn)
	}
	if cn := certs[1].Certificate.Subject.CommonName; cn != "Example CA" {
		t.Errorf("second certificate is %q, want the CA from ca.crt", cn)
	}
}

func TestParseKubernetesSecretErrors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "a secret with no certificate keys",
			input: kubeSecret(t, map[string][]byte{"tls.key": []byte("key")}),
			want:  "tls.crt",
		},
		{
			name:  "some other kind of object",
			input: []byte(`{"kind":"ConfigMap","data":{"tls.crt":"aGk="}}`),
			want:  "not a Secret",
		},
		{
			name:  "a secret whose certificate is not base64",
			input: []byte(`{"kind":"Secret","data":{"tls.crt":"not base64!"}}`),
			want:  "not base64",
		},
		{
			name:  "a secret whose certificate is not a certificate",
			input: kubeSecret(t, map[string][]byte{"tls.crt": []byte("hello")}),
			want:  "no certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseCertificatesReport(tt.input)
			if err == nil {
				t.Fatalf("input parsed as a chain: %s", tt.input)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestJSONInputDoesNotFallThroughToDER keeps the error useful: JSON that is not
// a usable secret should say so, rather than being retried as DER and failing
// with a message about ASN.1.
func TestJSONInputDoesNotFallThroughToDER(t *testing.T) {
	_, _, err := ParseCertificatesReport([]byte(`{"hello":"world"}`))
	if err == nil {
		t.Fatal("arbitrary JSON parsed as a chain")
	}
	if strings.Contains(err.Error(), "asn1") {
		t.Errorf("error = %q, want it to be about the secret rather than DER", err)
	}
}
