package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// describeCert signs template so the fields under test come back through a real
// parse rather than being read off the struct that was written. An extension
// that does not survive encoding would otherwise pass.
func describeCert(t *testing.T, template *x509.Certificate) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(1)
	}
	if template.NotAfter.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
		template.NotAfter = time.Now().Add(time.Hour)
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

func mustOID(t *testing.T, s string) x509.OID {
	t.Helper()
	oid, err := x509.ParseOID(s)
	if err != nil {
		t.Fatalf("parsing the OID %q: %v", s, err)
	}
	return oid
}

func TestKeyUsageNames(t *testing.T) {
	cert := describeCert(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "usage"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	})

	got := KeyUsageNames(cert)
	want := []string{"digitalSignature", "keyCertSign"}
	if !slices.Equal(got, want) {
		t.Errorf("KeyUsageNames() = %v, want %v", got, want)
	}

	// Order follows the extension's bit order, not the order they were set.
	if got[0] != "digitalSignature" {
		t.Errorf("usages are out of RFC 5280 order: %v", got)
	}
}

func TestKeyUsageNamesWithoutTheExtension(t *testing.T) {
	cert := describeCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "none"}})

	if got := KeyUsageNames(cert); got != nil {
		t.Errorf("KeyUsageNames() = %v, want nil when the extension is absent", got)
	}
	if got := KeyUsageNames(nil); got != nil {
		t.Errorf("KeyUsageNames(nil) = %v, want nil", got)
	}
}

// TestExtKeyUsageNamesKeepsUnknownOIDs is the point of the helper: Go parses an
// EKU it does not recognise into UnknownExtKeyUsage, and dropping those would
// hide the reason a client refused the certificate.
func TestExtKeyUsageNamesKeepsUnknownOIDs(t *testing.T) {
	exotic := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	cert := describeCert(t, &x509.Certificate{
		Subject:            pkix.Name{CommonName: "eku"},
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{exotic},
	})

	got := ExtKeyUsageNames(cert)
	if !slices.Contains(got, "serverAuth") {
		t.Errorf("ExtKeyUsageNames() = %v, want it to name serverAuth", got)
	}
	if !slices.Contains(got, exotic.String()) {
		t.Errorf("ExtKeyUsageNames() = %v, want it to carry the unknown OID %s", got, exotic)
	}
}

func TestBasicConstraints(t *testing.T) {
	tests := []struct {
		name     string
		template *x509.Certificate
		want     string
	}{
		{
			name:     "absent extension says nothing",
			template: &x509.Certificate{Subject: pkix.Name{CommonName: "no constraints"}},
			want:     "",
		},
		{
			name: "an end-entity certificate",
			template: &x509.Certificate{
				Subject:               pkix.Name{CommonName: "leaf"},
				BasicConstraintsValid: true,
			},
			want: "CA: no",
		},
		{
			name: "a CA with no path length limit",
			template: &x509.Certificate{
				Subject:               pkix.Name{CommonName: "ca"},
				BasicConstraintsValid: true,
				IsCA:                  true,
			},
			want: "CA: yes, no pathLen limit",
		},
		{
			name: "a CA that may not issue further CAs",
			template: &x509.Certificate{
				Subject:               pkix.Name{CommonName: "constrained ca"},
				BasicConstraintsValid: true,
				IsCA:                  true,
				MaxPathLenZero:        true,
			},
			want: "CA: yes, pathLen 0 (may not issue further CAs)",
		},
		{
			name: "a CA with a path length of one",
			template: &x509.Certificate{
				Subject:               pkix.Name{CommonName: "ca1"},
				BasicConstraintsValid: true,
				IsCA:                  true,
				MaxPathLen:            1,
			},
			want: "CA: yes, pathLen 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BasicConstraints(describeCert(t, tt.template)); got != tt.want {
				t.Errorf("BasicConstraints() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPolicyOIDsNamesTheValidationLevel builds the fixture through Policies,
// not PolicyIdentifiers: current Go ignores the deprecated field when creating
// a certificate, so a fixture written the old way asserts no policy at all.
func TestPolicyOIDsNamesTheValidationLevel(t *testing.T) {
	dv := mustOID(t, "2.23.140.1.2.1")
	other := mustOID(t, "1.3.6.1.4.1.44947.1.1.1")
	cert := describeCert(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "policies"},
		Policies: []x509.OID{dv, other},
	})

	got := PolicyOIDs(cert)
	if len(got) != 2 {
		t.Fatalf("PolicyOIDs() = %v, want two entries", got)
	}
	if !strings.Contains(got[0], "domain validated") || !strings.Contains(got[0], dv.String()) {
		t.Errorf("PolicyOIDs()[0] = %q, want the CABF name and the OID", got[0])
	}
	// An OID with no well-known name stays an OID rather than being dropped.
	if got[1] != other.String() {
		t.Errorf("PolicyOIDs()[1] = %q, want the bare OID %s", got[1], other)
	}
}

// TestExtraDNAttributes covers what pkix.Name has no field for. These are
// already parsed into Names, so a renderer reading only the named fields drops
// them without saying anything.
func TestExtraDNAttributes(t *testing.T) {
	cert := describeCert(t, &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "extras.example.com",
			Organization: []string{"Example Ltd"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 15}, Value: "Private Organization"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: "NTRGB-12345"},
				{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}, Value: "custom"},
			},
		},
	})

	got := ExtraDNAttributes(cert.Subject)
	joined := strings.Join(got, "\n")

	for _, want := range []string{
		"businessCategory: Private Organization",
		"organizationIdentifier: NTRGB-12345",
		"1.3.6.1.4.1.99999.7: custom",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("ExtraDNAttributes() = %v, want it to include %q", got, want)
		}
	}

	// The attributes pkix.Name already exposes must not be repeated here, or
	// every DN would list its CN twice.
	if strings.Contains(joined, "extras.example.com") || strings.Contains(joined, "Example Ltd") {
		t.Errorf("ExtraDNAttributes() repeated a named field: %v", got)
	}
}

// TestDescribeURISANsSurviveAParse guards the field the SANs tab was missing:
// a URI-only certificate has to come back with URIs populated, or the tab has
// nothing to render.
func TestDescribeURISANsSurviveAParse(t *testing.T) {
	cert := describeCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "workload"},
		URIs:    []*url.URL{{Scheme: "spiffe", Host: "example", Path: "/workload"}},
	})

	if len(cert.URIs) != 1 {
		t.Fatalf("parsed certificate carries %d URI SANs, want 1", len(cert.URIs))
	}
	if got := cert.URIs[0].String(); got != "spiffe://example/workload" {
		t.Errorf("URI SAN = %q, want the SPIFFE ID", got)
	}
	// And nothing else claims it: this is exactly the certificate that used to
	// report "No SANs present".
	if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses) != 0 {
		t.Error("fixture is not URI-only, so it does not test the gap")
	}
}
