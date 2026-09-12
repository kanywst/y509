package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
)

// This file turns the parts of an x509.Certificate that are bitmasks, OIDs or
// unnamed DN attributes into something a view can print. It lives here rather
// than in the renderer so the model never has to reason about X.509 encodings.

// keyUsageNames pairs each KeyUsage bit with the name RFC 5280 gives it.
// contentCommitment is listed under its modern name, since "nonRepudiation" was
// renamed precisely because it promised more than the bit delivers.
var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

// KeyUsageNames lists the key usages the certificate asserts, in the order the
// extension defines them. Empty when the extension is absent.
func KeyUsageNames(cert *x509.Certificate) []string {
	if cert == nil || cert.KeyUsage == 0 {
		return nil
	}

	names := make([]string, 0, len(keyUsageNames))
	for _, ku := range keyUsageNames {
		if cert.KeyUsage&ku.bit != 0 {
			names = append(names, ku.name)
		}
	}
	return names
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoftKernelCodeSigning",
}

// ExtKeyUsageNames lists the extended key usages, including the ones Go does
// not recognise: those come back as bare OIDs rather than being dropped, since
// an unknown EKU can be the reason a client refuses the certificate.
func ExtKeyUsageNames(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}

	names := make([]string, 0, len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage))
	for _, eku := range cert.ExtKeyUsage {
		if name, ok := extKeyUsageNames[eku]; ok {
			names = append(names, name)
		} else {
			names = append(names, fmt.Sprintf("unrecognized (%d)", eku))
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		names = append(names, oid.String())
	}

	if len(names) == 0 {
		return nil
	}
	return names
}

// BasicConstraints describes the CA bit and any path length limit, or an empty
// string when the extension is absent.
//
// The distinction between "no limit" and "zero" matters: pathLen 0 means this CA
// may issue end-entity certificates but no further CAs, which is what a
// technically constrained subordinate looks like.
func BasicConstraints(cert *x509.Certificate) string {
	if cert == nil || !cert.BasicConstraintsValid {
		return ""
	}

	if !cert.IsCA {
		return "CA: no"
	}
	switch {
	case cert.MaxPathLenZero:
		return "CA: yes, pathLen 0 (may not issue further CAs)"
	case cert.MaxPathLen > 0:
		return fmt.Sprintf("CA: yes, pathLen %d", cert.MaxPathLen)
	default:
		return "CA: yes, no pathLen limit"
	}
}

// cabfPolicyNames names the CA/Browser Forum validation-level policy OIDs,
// which say how the subject was vetted -- the one policy OID a reader is likely
// to want in words.
var cabfPolicyNames = map[string]string{
	"2.23.140.1.1":   "CABF extended validation",
	"2.23.140.1.2.1": "CABF domain validated",
	"2.23.140.1.2.2": "CABF organization validated",
	"2.23.140.1.2.3": "CABF individual validated",
	"2.5.29.32.0":    "anyPolicy",
}

// PolicyOIDs lists the certificate policies, naming the CA/Browser Forum
// validation levels and leaving everything else as an OID.
//
// Policies is read in preference to PolicyIdentifiers. Both are populated when
// a certificate is parsed, but Policies is the field that is not deprecated,
// and it is the only one CreateCertificate still writes -- so a certificate
// minted by current Go and read back through the older field alone would look
// as though it asserted no policy at all.
func PolicyOIDs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}

	oids := make([]string, 0, len(cert.Policies))
	for _, policy := range cert.Policies {
		oids = append(oids, policy.String())
	}
	if len(oids) == 0 {
		for _, oid := range cert.PolicyIdentifiers { //nolint:staticcheck // the fallback is the point
			oids = append(oids, oid.String())
		}
	}

	names := make([]string, 0, len(oids))
	for _, oid := range oids {
		if name, ok := cabfPolicyNames[oid]; ok {
			names = append(names, fmt.Sprintf("%s (%s)", name, oid))
		} else {
			names = append(names, oid)
		}
	}

	if len(names) == 0 {
		return nil
	}
	return names
}

// namedDNAttributes are the attribute OIDs pkix.Name already exposes as fields,
// so ExtraDNAttributes can report everything else.
var namedDNAttributes = map[string]bool{
	"2.5.4.3":  true, // commonName
	"2.5.4.5":  true, // serialNumber
	"2.5.4.6":  true, // countryName
	"2.5.4.7":  true, // localityName
	"2.5.4.8":  true, // stateOrProvinceName
	"2.5.4.9":  true, // streetAddress
	"2.5.4.10": true, // organizationName
	"2.5.4.11": true, // organizationalUnitName
	"2.5.4.17": true, // postalCode
}

// extraDNAttributeNames names the attributes seen often enough in the WebPKI to
// be worth words rather than an arc.
var extraDNAttributeNames = map[string]string{
	"2.5.4.4":                     "surname",
	"2.5.4.12":                    "title",
	"2.5.4.42":                    "givenName",
	"2.5.4.15":                    "businessCategory",
	"2.5.4.97":                    "organizationIdentifier",
	"1.2.840.113549.1.9.1":        "emailAddress",
	"0.9.2342.19200300.100.1.25":  "domainComponent",
	"1.3.6.1.4.1.311.60.2.1.1":    "jurisdictionLocality",
	"1.3.6.1.4.1.311.60.2.1.2":    "jurisdictionStateOrProvince",
	"1.3.6.1.4.1.311.60.2.1.3":    "jurisdictionCountry",
	"1.3.6.1.4.1.311.60.2.1.3.10": "jurisdictionCountry",
}

// ExtraDNAttributes lists the distinguished name attributes that pkix.Name has
// no field for, as "name: value" pairs.
//
// pkix.Name.Names carries every attribute that was parsed, including these, so
// they are already in hand -- a renderer that reads only the named fields drops
// a subject's businessCategory or organizationIdentifier without saying so.
func ExtraDNAttributes(name pkix.Name) []string {
	var out []string
	for _, atv := range name.Names {
		oid := atv.Type.String()
		if namedDNAttributes[oid] {
			continue
		}

		label := oid
		if named, ok := extraDNAttributeNames[oid]; ok {
			label = named
		}

		// A non-string value (an ASN.1 type Go did not decode into a string)
		// is reported as present rather than guessed at.
		value, ok := atv.Value.(string)
		if !ok {
			value = fmt.Sprintf("(%T, not decoded)", atv.Value)
		}
		out = append(out, fmt.Sprintf("%s: %s", label, value))
	}
	return out
}
