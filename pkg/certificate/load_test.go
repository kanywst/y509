package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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

// TestParseCertificates_DER covers raw DER input. y509's own export form offers
// DER, so before this the tool could write a file it could not read back.
func TestParseCertificates_DER(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(serial int64, cn string) []byte {
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

	t.Run("single certificate", func(t *testing.T) {
		certs, err := ParseCertificates(mint(1, "der-leaf"))
		if err != nil {
			t.Fatalf("ParseCertificates on DER failed: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(certs))
		}
		if got := certs[0].Certificate.Subject.CommonName; got != "der-leaf" {
			t.Errorf("CommonName = %q, want %q", got, "der-leaf")
		}
	})

	t.Run("concatenated chain", func(t *testing.T) {
		var chain []byte
		chain = append(chain, mint(1, "der-leaf")...)
		chain = append(chain, mint(2, "der-intermediate")...)

		certs, err := ParseCertificates(chain)
		if err != nil {
			t.Fatalf("ParseCertificates on a concatenated DER chain failed: %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(certs))
		}
		for i, info := range certs {
			if info.Index != i {
				t.Errorf("certificate %d: Index = %d, want %d", i, info.Index, i)
			}
		}
	})

	t.Run("round trip through ExportCertificate", func(t *testing.T) {
		cert, err := x509.ParseCertificate(mint(3, "round-trip"))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "cert.der")
		if err := ExportCertificate(cert, "der", target); err != nil {
			t.Fatalf("ExportCertificate: %v", err)
		}

		certs, err := LoadCertificates(target)
		if err != nil {
			t.Fatalf("could not read back a DER file y509 wrote itself: %v", err)
		}
		if len(certs) != 1 || certs[0].Certificate.Subject.CommonName != "round-trip" {
			t.Errorf("round trip lost the certificate: %+v", certs)
		}
	})
}

// TestParseCertificates_Errors checks that unreadable input says what is wrong
// rather than the blanket "no certificates found".
func TestParseCertificates_Errors(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "PEM with no certificate blocks",
			input: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}),
			want:  "no CERTIFICATE blocks",
		},
		{
			name: "a complete DER SEQUENCE that is not a certificate",
			// A real, well-formed ASN.1 SEQUENCE that x509 rejects -- standing
			// in for a PKCS#7 / PKCS#12 container.
			input: func() []byte {
				der, err := asn1.Marshal([]int{1, 2, 3})
				if err != nil {
					t.Fatal(err)
				}
				return der
			}(),
			want: "PKCS#7 and PKCS#12",
		},
		{
			name: "text that merely starts with 0x30",
			// '0' is 0x30, the SEQUENCE tag. The old first-byte test called this
			// a PKCS container; it is just text.
			input: []byte("0000 this is plain text, not a certificate at all"),
			want:  "could not be parsed as a certificate",
		},
		{
			name:  "plain garbage",
			input: []byte("hello, this is not a certificate"),
			want:  "not PEM, and not valid DER",
		},
		{
			name: "a truncated certificate",
			// A real certificate cut in half is still a DER SEQUENCE, so the
			// message must not assert it is a PKCS container.
			input: func() []byte {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				template := x509.Certificate{
					SerialNumber: big.NewInt(7),
					Subject:      pkix.Name{CommonName: "truncated"},
					NotBefore:    time.Now(),
					NotAfter:     time.Now().Add(time.Hour),
				}
				der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
				if err != nil {
					t.Fatal(err)
				}
				return der[:len(der)/2]
			}(),
			want: "could not be parsed as a certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCertificates(tt.input)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
			// Only a genuine complete SEQUENCE may be called a PKCS container.
			if tt.want != "PKCS#7 and PKCS#12" && strings.Contains(err.Error(), "PKCS") {
				t.Errorf("error = %q wrongly claims a PKCS container", err)
			}
		})
	}
}
