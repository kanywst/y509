package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/y509/pkg/certificate"
)

// richCert carries the fields the detail tabs used to drop on the floor, all of
// them named fields on x509.Certificate that were parsed and then never shown.
func richCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	policy, err := x509.ParseOID("2.23.140.1.2.1")
	if err != nil {
		t.Fatalf("parsing the policy OID: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:         "rich.example.com",
			Organization:       []string{"Example Ltd"},
			OrganizationalUnit: []string{"Platform"},
			Country:            []string{"JP"},
			Province:           []string{"Tokyo"},
			Locality:           []string{"Chiyoda"},
			StreetAddress:      []string{"1-1 Nowhere"},
			PostalCode:         []string{"100-0001"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: "NTRJP-99999"},
			},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{0xde, 0xad, 0xbe, 0xef},
		AuthorityKeyId:        []byte{0xfe, 0xed, 0xfa, 0xce},
		IssuingCertificateURL: []string{"http://ca.example.com/issuer.crt"},
		OCSPServer:            []string{"http://ocsp.example.com"},
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
		Policies:              []x509.OID{policy},
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: "example", Path: "/workload"}},
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

// tabContent renders one named tab for the given certificate.
func tabContent(t *testing.T, cert *x509.Certificate, tab string) string {
	t.Helper()

	m := *NewModel([]*certificate.Info{{Certificate: cert}}, loadTestConfig(t))
	idx := -1
	for i, name := range m.tabs {
		if name == tab {
			idx = i
			break
		}
	}
	if idx == -1 {
		t.Fatalf("no %q tab in %v", tab, m.tabs)
	}
	m.activeTab = idx
	return m.renderTabContent(100)
}

func TestMiscTabShowsTheFieldsAlreadyParsed(t *testing.T) {
	got := tabContent(t, richCert(t), "Misc")

	// Every one of these was parsed by crypto/x509 and then not rendered.
	for _, want := range []string{
		"Version", "v3",
		"SKI", "de:ad:be:ef",
		"AKI", "fe:ed:fa:ce",
		"Key Usage", "digitalSignature", "keyEncipherment",
		"Ext Key Usage", "serverAuth", "clientAuth",
		"Constraints", "CA: no",
		"CA Issuers", "http://ca.example.com/issuer.crt",
		"OCSP", "http://ocsp.example.com",
		"CRL", "http://crl.example.com/ca.crl",
		"domain validated",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Misc tab does not show %q:\n%s", want, got)
		}
	}
}

func TestSANsTabShowsURIs(t *testing.T) {
	got := tabContent(t, richCert(t), "SANs")

	if !strings.Contains(got, "spiffe://example/workload") {
		t.Errorf("SANs tab drops URI SANs:\n%s", got)
	}
	// The fallback line has to go when there is something to show.
	if strings.Contains(got, "No SANs present") {
		t.Errorf("SANs tab claims there are no SANs while rendering one:\n%s", got)
	}
}

func TestSubjectTabShowsUnnamedDNAttributes(t *testing.T) {
	got := tabContent(t, richCert(t), "Subject")

	for _, want := range []string{"Street", "Postal Code", "organizationIdentifier", "NTRJP-99999"} {
		if !strings.Contains(got, want) {
			t.Errorf("Subject tab does not show %q:\n%s", want, got)
		}
	}
}

// TestIssuerTabMatchesSubject pins the asymmetry that used to exist: Issuer
// rendered CN, Organization and Country only, so a self-signed certificate
// showed different DNs on two tabs that hold the same attributes.
func TestIssuerTabMatchesSubject(t *testing.T) {
	cert := richCert(t) // self-signed, so issuer and subject are identical
	subject := tabContent(t, cert, "Subject")
	issuer := tabContent(t, cert, "Issuer")

	if subject != issuer {
		t.Errorf("Subject and Issuer render the same DN differently:\n--- subject ---\n%s\n--- issuer ---\n%s", subject, issuer)
	}
}
