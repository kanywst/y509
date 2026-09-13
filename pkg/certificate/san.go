package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"unicode/utf16"
)

// oidSubjectAltName is the subject alternative name extension.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// GeneralName tag numbers from RFC 5280 section 4.2.1.6. Go's parser handles
// rfc822Name, dNSName, uniformResourceIdentifier and iPAddress and drops the
// other five on the floor, so those are what this file is for.
const (
	sanOtherName     = 0
	sanX400Address   = 3
	sanDirectoryName = 4
	sanEDIPartyName  = 5
	sanRegisteredID  = 8
)

// otherNameTypes are the otherName forms common enough to name. Everything else
// is reported by OID, which is still better than silence.
var otherNameTypes = map[string]string{
	"1.3.6.1.4.1.311.20.2.3": "UPN",             // Microsoft user principal name
	"1.3.6.1.5.5.7.8.7":      "SRVName",         // RFC 4985
	"1.3.6.1.5.5.7.8.5":      "XmppAddr",        // RFC 6120
	"1.3.6.1.5.5.7.8.9":      "SmtpUTF8Mailbox", // RFC 8398
	"1.3.6.1.5.2.2":          "KerberosPrincipal",
	"1.3.6.1.4.1.311.25.1":   "ADGUID", // Active Directory object GUID
}

// OtherSAN is a subject alternative name that crypto/x509 parsed past without
// exposing.
type OtherSAN struct {
	// Kind is the GeneralName form: "otherName", "directoryName",
	// "registeredID", "x400Address" or "ediPartyName".
	Kind string
	// Type names the otherName form where it is known -- "UPN", "SRVName" --
	// and is the bare OID where it is not. Empty for the other kinds.
	Type string
	// Value is the name itself, rendered as text where that is meaningful and
	// as a byte count where it is not.
	Value string
}

// String renders the name for display.
func (o OtherSAN) String() string {
	if o.Type == "" {
		return o.Value
	}
	return o.Type + ": " + o.Value
}

// OtherSANs returns the subject alternative names Go's parser does not expose.
//
// crypto/x509 handles four of RFC 5280's nine GeneralName forms and silently
// drops the rest, so a certificate whose only identity is an otherName -- a
// Microsoft UPN on a smartcard certificate, a SPIFFE-adjacent SRVName, a
// Kerberos principal -- comes back looking as though it has no names at all.
// Reporting them by OID is the difference between "no SANs present" and an
// identity the reader can act on.
//
// This reads the SAN extension and nothing else. Where a value is not text,
// it is reported by kind and size rather than guessed at.
func OtherSANs(cert *x509.Certificate) []OtherSAN {
	if cert == nil {
		return nil
	}

	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			raw = ext.Value
			break
		}
	}
	if len(raw) == 0 {
		return nil
	}

	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		logger.Debug("Subject alternative name extension did not parse as a sequence")
		return nil
	}
	if !seq.IsCompound || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil
	}

	var out []OtherSAN
	rest := seq.Bytes
	for len(rest) > 0 {
		var name asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &name)
		if err != nil {
			logger.Debug("Stopped reading subject alternative names at a malformed entry")
			break
		}
		if name.Class != asn1.ClassContextSpecific {
			continue
		}

		switch name.Tag {
		case sanOtherName:
			if parsed, ok := parseOtherName(name.Bytes); ok {
				out = append(out, parsed)
			}
		case sanDirectoryName:
			out = append(out, OtherSAN{Kind: "directoryName", Value: directoryNameString(name.Bytes)})
		case sanRegisteredID:
			out = append(out, OtherSAN{Kind: "registeredID", Value: registeredIDString(name)})
		case sanX400Address:
			out = append(out, OtherSAN{Kind: "x400Address", Value: notDecoded(len(name.Bytes))})
		case sanEDIPartyName:
			out = append(out, OtherSAN{Kind: "ediPartyName", Value: notDecoded(len(name.Bytes))})
		}
	}

	// Sanitize once, here, rather than in each decoder: every one of these
	// values is attacker-controlled, and a terminal will act on an escape
	// sequence wherever it arrives from. Doing it per-branch is how the
	// directoryName path came to be missed.
	for i := range out {
		out[i].Type = sanitizeSANText(out[i].Type)
		out[i].Value = sanitizeSANText(out[i].Value)
	}

	return out
}

// parseOtherName reads an otherName: an OID naming the form, then the value
// wrapped in an explicit [0].
func parseOtherName(der []byte) (OtherSAN, bool) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &oid)
	if err != nil {
		return OtherSAN{}, false
	}

	name := OtherSAN{Kind: "otherName", Type: oid.String()}
	if known, ok := otherNameTypes[name.Type]; ok {
		name.Type = known
	}

	var wrapper asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &wrapper); err != nil {
		name.Value = notDecoded(len(rest))
		return name, true
	}

	// The value sits inside the explicit [0]; unwrap it before reading.
	inner := wrapper.Bytes
	var value asn1.RawValue
	if _, err := asn1.Unmarshal(inner, &value); err != nil {
		name.Value = notDecoded(len(inner))
		return name, true
	}

	name.Value = stringOrSize(value)
	return name, true
}

// stringOrSize renders an ASN.1 value as text when its tag says it is text, and
// as a size when it does not. Guessing at bytes would put control characters on
// a terminal.
func stringOrSize(value asn1.RawValue) string {
	switch value.Tag {
	case asn1.TagBMPString:
		// BMPString is UCS-2, big-endian 16-bit code units. Reading its bytes
		// as UTF-8 would produce mojibake with embedded NULs, and Microsoft
		// has historically encoded UPNs this way.
		return decodeBMPString(value.Bytes)
	case asn1.TagUTF8String, asn1.TagIA5String, asn1.TagPrintableString,
		asn1.TagT61String, asn1.TagGeneralString:
		return string(value.Bytes)
	case asn1.TagOID:
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(value.FullBytes, &oid); err == nil {
			return oid.String()
		}
	}
	return notDecoded(len(value.Bytes))
}

// decodeBMPString reads a UCS-2 big-endian string. An odd length is not a
// BMPString, so it is reported by size rather than guessed at.
func decodeBMPString(b []byte) string {
	if len(b)%2 != 0 {
		return notDecoded(len(b))
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		units = append(units, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return string(utf16.Decode(units))
}

// sanitizeSANText strips the characters that let a name lie about itself.
//
// Subject alternative names are attacker-controlled and reach both a terminal
// and the JSON report. Three classes have to go, and the last two are the ones
// worth spelling out:
//
//   - C0 and C1 controls and DEL, because a terminal acts on an escape
//     sequence that arrives inside a name.
//   - Bidirectional controls, because U+202E and the directional isolates
//     reorder what follows them: a UPN can be made to read as a different name
//     than the one the certificate asserts, which is the whole point of
//     printing it.
//   - Zero-width characters, because two names that render identically but
//     compare unequal are worse than one that looks wrong.
func sanitizeSANText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return -1
		case r == 0x200e, r == 0x200f, // LRM, RLM
			r >= 0x202a && r <= 0x202e, // embeddings and overrides, incl. RLO
			r >= 0x2066 && r <= 0x2069: // isolates
			return -1
		case r == 0x200b, r == 0x200c, r == 0x200d, r == 0xfeff:
			return -1
		}
		return r
	}, s)
}

func notDecoded(n int) string {
	return fmt.Sprintf("(%d bytes, not decoded)", n)
}

// directoryNameString renders a directoryName by its RFC 2253 form.
func directoryNameString(der []byte) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdns); err != nil {
		return notDecoded(len(der))
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	return name.String()
}

// registeredIDString renders a registeredID, which is a bare OID.
func registeredIDString(name asn1.RawValue) string {
	// The tag is context-specific [8]; re-tag it as an OID so asn1 will read it.
	der := make([]byte, len(name.FullBytes))
	copy(der, name.FullBytes)
	der[0] = byte(asn1.TagOID)

	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &oid); err != nil {
		return notDecoded(len(name.Bytes))
	}
	return oid.String()
}
