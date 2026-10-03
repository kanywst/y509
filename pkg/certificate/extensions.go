package certificate

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
)

// Extension is one X.509v3 extension as the certificate carries it.
type Extension struct {
	// OID is the dotted extension identifier.
	OID string
	// Name is the extension's name, empty when it is not one this package
	// knows. An unknown extension is labelled by OID and size, never dropped.
	Name string
	// Critical is the critical bit: a client that does not understand a
	// critical extension must reject the certificate.
	Critical bool
	// Unhandled reports a critical extension crypto/x509 does not process,
	// which makes Go refuse the certificate outright.
	Unhandled bool
	// Bytes is the size of the extension value.
	Bytes int
}

// Label is the extension's name, or a description of what could not be
// named.
func (e Extension) Label() string {
	if e.Name != "" {
		return e.Name
	}
	return fmt.Sprintf("unrecognized extension (OID %s, %d bytes)", e.OID, e.Bytes)
}

const (
	oidCTPoison   = "1.3.6.1.4.1.11129.2.4.3"
	oidTLSFeature = "1.3.6.1.5.5.7.1.24"
)

// extensionNames covers the extensions a web PKI, enterprise or ACME
// certificate is likely to carry. Anything else is shown by OID.
var extensionNames = map[string]string{
	"2.5.29.9":                "Subject Directory Attributes",
	"2.5.29.14":               "Subject Key Identifier",
	"2.5.29.15":               "Key Usage",
	"2.5.29.17":               "Subject Alternative Name",
	"2.5.29.18":               "Issuer Alternative Name",
	"2.5.29.19":               "Basic Constraints",
	"2.5.29.30":               "Name Constraints",
	"2.5.29.31":               "CRL Distribution Points",
	"2.5.29.32":               "Certificate Policies",
	"2.5.29.33":               "Policy Mappings",
	"2.5.29.35":               "Authority Key Identifier",
	"2.5.29.36":               "Policy Constraints",
	"2.5.29.37":               "Extended Key Usage",
	"2.5.29.46":               "Freshest CRL",
	"2.5.29.54":               "Inhibit anyPolicy",
	"1.3.6.1.5.5.7.1.1":       "Authority Information Access",
	"1.3.6.1.5.5.7.1.11":      "Subject Information Access",
	oidTLSFeature:             "TLS Feature",
	"1.3.6.1.5.5.7.1.31":      "ACME Identifier",
	"1.3.6.1.5.5.7.48.1.5":    "OCSP No Check",
	"1.3.6.1.4.1.11129.2.4.2": "CT Signed Certificate Timestamps",
	oidCTPoison:               "CT Precertificate Poison",
	"2.16.840.1.113730.1.1":   "Netscape Certificate Type",
	"2.16.840.1.113730.1.13":  "Netscape Comment",
	"1.3.6.1.4.1.311.20.2":    "Microsoft Certificate Template Name",
	"1.3.6.1.4.1.311.21.1":    "Microsoft CA Version",
	"1.3.6.1.4.1.311.21.2":    "Microsoft Previous CA Certificate Hash",
	"1.3.6.1.4.1.311.21.7":    "Microsoft Certificate Template",
	"1.3.6.1.4.1.311.21.10":   "Microsoft Application Policies",
}

// tlsFeatureStatusRequest is the TLS Feature value for OCSP Must-Staple
// (RFC 7633): the status_request extension number.
const tlsFeatureStatusRequest = 5

// Extensions lists every extension the certificate carries, in the order it
// carries them.
func Extensions(cert *x509.Certificate) []Extension {
	if cert == nil {
		return nil
	}

	out := make([]Extension, 0, len(cert.Extensions))
	for _, ext := range cert.Extensions {
		oid := ext.Id.String()
		entry := Extension{
			OID:      oid,
			Name:     extensionNames[oid],
			Critical: ext.Critical,
			Bytes:    len(ext.Value),
		}
		if oid == oidTLSFeature && isMustStaple(ext.Value) {
			entry.Name = "TLS Feature (OCSP Must-Staple)"
		}
		if ext.Critical {
			entry.Unhandled = slices.ContainsFunc(cert.UnhandledCriticalExtensions, ext.Id.Equal)
		}
		out = append(out, entry)
	}
	return out
}

// isMustStaple reports a TLS Feature extension that requires status_request.
func isMustStaple(value []byte) bool {
	var features []int
	if _, err := asn1.Unmarshal(value, &features); err != nil {
		return false
	}
	return slices.Contains(features, tlsFeatureStatusRequest)
}
