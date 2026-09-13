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
)

// sanCert signs a certificate carrying the given raw subject alternative name
// extension, so the test exercises a real parse rather than a struct literal.
func sanCert(t *testing.T, names []asn1.RawValue) *x509.Certificate {
	t.Helper()

	encoded, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatRaw(t, names),
	})
	if err != nil {
		t.Fatalf("encoding the SAN sequence: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "san"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidSubjectAltName, Value: encoded},
		},
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

func concatRaw(t *testing.T, values []asn1.RawValue) []byte {
	t.Helper()
	var out []byte
	for _, v := range values {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatalf("encoding a GeneralName: %v", err)
		}
		out = append(out, der...)
	}
	return out
}

// otherNameValue builds an otherName: the type OID, then the value inside an
// explicit [0].
func otherNameValue(t *testing.T, oid asn1.ObjectIdentifier, value asn1.RawValue) asn1.RawValue {
	t.Helper()

	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("encoding the otherName OID: %v", err)
	}
	valueDER, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("encoding the otherName value: %v", err)
	}
	wrapper, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      valueDER,
	})
	if err != nil {
		t.Fatalf("wrapping the otherName value: %v", err)
	}

	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        sanOtherName,
		IsCompound: true,
		Bytes:      append(oidDER, wrapper...),
	}
}

// TestOtherSANsFindsAUPNOnlyCertificate is the case that motivated this: a
// smartcard certificate whose only identity is a Microsoft UPN parses cleanly
// and comes back with every name field empty.
func TestOtherSANsFindsAUPNOnlyCertificate(t *testing.T) {
	upn := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	cert := sanCert(t, []asn1.RawValue{
		otherNameValue(t, upn, asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagUTF8String,
			Bytes: []byte("alice@example.com"),
		}),
	})

	// The premise: Go itself reports no names at all.
	if n := len(cert.DNSNames) + len(cert.EmailAddresses) + len(cert.IPAddresses) + len(cert.URIs); n != 0 {
		t.Fatalf("fixture is not otherName-only: Go exposed %d names", n)
	}

	got := OtherSANs(cert)
	if len(got) != 1 {
		t.Fatalf("OtherSANs returned %d names, want 1", len(got))
	}
	if got[0].Kind != "otherName" {
		t.Errorf("Kind = %q, want otherName", got[0].Kind)
	}
	if got[0].Type != "UPN" {
		t.Errorf("Type = %q, want UPN", got[0].Type)
	}
	if got[0].Value != "alice@example.com" {
		t.Errorf("Value = %q, want the principal name", got[0].Value)
	}
	if s := got[0].String(); s != "UPN: alice@example.com" {
		t.Errorf("String() = %q", s)
	}
}

func TestOtherSANsNamesTheFormsItKnows(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		wantType string
	}{
		{"SRVName", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 7}, "SRVName"},
		{"XmppAddr", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 5}, "XmppAddr"},
		{"SmtpUTF8Mailbox", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 9}, "SmtpUTF8Mailbox"},
		{"Kerberos", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}, "KerberosPrincipal"},
		// An OID with no well-known name is reported as an OID rather than
		// dropped: an unrecognised identity is still an identity.
		{"unknown", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 3}, "1.3.6.1.4.1.99999.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := sanCert(t, []asn1.RawValue{
				otherNameValue(t, tt.oid, asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagUTF8String,
					Bytes: []byte("value"),
				}),
			})

			got := OtherSANs(cert)
			if len(got) != 1 {
				t.Fatalf("OtherSANs returned %d names, want 1", len(got))
			}
			if got[0].Type != tt.wantType {
				t.Errorf("Type = %q, want %q", got[0].Type, tt.wantType)
			}
		})
	}
}

func TestOtherSANsReadsRegisteredIDAndDirectoryName(t *testing.T) {
	registered := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42}
	registeredDER, err := asn1.Marshal(registered)
	if err != nil {
		t.Fatalf("encoding the registeredID: %v", err)
	}

	dn, err := asn1.Marshal(pkix.Name{CommonName: "directory.example.com"}.ToRDNSequence())
	if err != nil {
		t.Fatalf("encoding the directoryName: %v", err)
	}

	cert := sanCert(t, []asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: sanRegisteredID, Bytes: registeredDER[2:]},
		{Class: asn1.ClassContextSpecific, Tag: sanDirectoryName, IsCompound: true, Bytes: dn},
	})

	got := OtherSANs(cert)
	if len(got) != 2 {
		t.Fatalf("OtherSANs returned %d names, want 2: %v", len(got), got)
	}

	var kinds []string
	var joined string
	for _, name := range got {
		kinds = append(kinds, name.Kind)
		joined += name.Value + "\n"
	}
	if !strings.Contains(strings.Join(kinds, ","), "registeredID") {
		t.Errorf("kinds = %v, want a registeredID", kinds)
	}
	if !strings.Contains(joined, "directory.example.com") {
		t.Errorf("values = %q, want the directoryName rendered", joined)
	}
}

// TestOtherSANsStripsControlCharacters keeps an attacker-controlled name from
// carrying a terminal escape sequence onto the screen.
func TestOtherSANsStripsControlCharacters(t *testing.T) {
	upn := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	cert := sanCert(t, []asn1.RawValue{
		otherNameValue(t, upn, asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagUTF8String,
			Bytes: []byte("alice\x1b[31m@example.com"),
		}),
	})

	got := OtherSANs(cert)
	if len(got) != 1 {
		t.Fatalf("OtherSANs returned %d names, want 1", len(got))
	}
	if strings.ContainsRune(got[0].Value, 0x1b) {
		t.Errorf("Value = %q, want the escape stripped", got[0].Value)
	}
	if got[0].Value != "alice[31m@example.com" {
		t.Errorf("Value = %q", got[0].Value)
	}
}

func TestOtherSANsIsEmptyForOrdinaryCertificates(t *testing.T) {
	cert := sanCert(t, []asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("example.com")},
	})

	if got := OtherSANs(cert); len(got) != 0 {
		t.Errorf("OtherSANs() = %v, want nothing for a DNS-only certificate", got)
	}
	if got := OtherSANs(nil); got != nil {
		t.Errorf("OtherSANs(nil) = %v, want nil", got)
	}
}

// TestJSONCertificateCarriesEverySANForm closes the gap between what the TUI
// renders and what the report publishes: a consumer gating CI on identity
// should not have to know which SAN forms happened to be included.
func TestJSONCertificateCarriesEverySANForm(t *testing.T) {
	upn := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	cert := sanCert(t, []asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("example.com")},
		{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("ops@example.com")},
		{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte("spiffe://example/workload")},
		otherNameValue(t, upn, asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagUTF8String,
			Bytes: []byte("alice@example.com"),
		}),
	})

	report := NewJSONReport("", AnalyzeChain([]*x509.Certificate{cert}), nil)
	if len(report.Chain) != 1 {
		t.Fatalf("report holds %d certificates, want 1", len(report.Chain))
	}
	entry := report.Chain[0]

	if len(entry.DNSNames) != 1 || entry.DNSNames[0] != "example.com" {
		t.Errorf("dnsNames = %v", entry.DNSNames)
	}
	if len(entry.EmailAddresses) != 1 || entry.EmailAddresses[0] != "ops@example.com" {
		t.Errorf("emailAddresses = %v, want the address the SANs tab shows", entry.EmailAddresses)
	}
	if len(entry.URIs) != 1 || entry.URIs[0] != "spiffe://example/workload" {
		t.Errorf("uris = %v, want the workload identity", entry.URIs)
	}
	if len(entry.OtherNames) != 1 || entry.OtherNames[0] != "UPN: alice@example.com" {
		t.Errorf("otherNames = %v, want the UPN", entry.OtherNames)
	}
}
