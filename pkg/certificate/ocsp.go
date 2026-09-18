package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Staple is what a stapled OCSP response said.
//
// Reading one is not revocation checking: the bytes arrived in the handshake
// and nothing here goes to the network to fetch them. That distinction is the
// whole reason this is in scope while AIA chasing is not.
//
// The absence of a staple is never recorded here, and never a finding.
// id-ad-ocsp is optional for every subscriber certificate now, a growing share
// of servers will never staple one, and reporting the absence would be
// reporting the norm.
type Staple struct {
	// Status is "good", "revoked" or "unknown", the three an OCSP responder
	// can give about a certificate it recognises.
	Status string
	// SerialNumber is the certificate the response is about, in the same
	// lower-case hex the rest of this package uses for serials. It is worth
	// showing because a response for the wrong certificate is a real
	// misconfiguration, and one that is invisible otherwise.
	SerialNumber string
	// ProducedAt, ThisUpdate and NextUpdate are the response's own freshness.
	// NextUpdate is zero when the responder gave none, which is legal and
	// means the response should not be cached.
	ProducedAt time.Time
	ThisUpdate time.Time
	NextUpdate time.Time
	// RevokedAt and RevocationReason are set only for a revoked certificate.
	// The reason is the RFC 5280 CRLReason, named rather than numbered.
	RevokedAt        time.Time
	RevocationReason string
	// Responder names who signed the response, when the response says so by
	// name rather than by key hash.
	Responder string
	// Verified reports whether the response's signature was checked against the
	// issuer, and passed.
	Verified bool
	// VerifyErr is why the check failed, set only when an issuer was available
	// and the signature did not verify against it. It stays nil when there was
	// no issuer to check against.
	//
	// The two are very different claims and must not collapse into one bool. A
	// missing issuer means the server omitted the intermediate, which is a
	// common misconfiguration. A response that fails against the issuer the
	// server itself presented is a much louder signal, and an operator told the
	// first when it was the second would go and fix the wrong thing.
	VerifyErr error
}

// Expired reports whether the response is past the point the responder said it
// would be refreshed by. A response with no NextUpdate never expires, by the
// responder's own instruction not to cache it.
func (s *Staple) Expired(now time.Time) bool {
	if s == nil || s.NextUpdate.IsZero() {
		return false
	}
	return now.After(s.NextUpdate)
}

// ParseStaple reads the OCSP response a server stapled.
//
// leaf and issuer come from the chain as presented. When the issuer is there
// the signature is checked against it; when it is not -- a server that omitted
// the intermediate, which is the misconfiguration this tool exists to find --
// the response is still parsed, and Verified says the signature was not
// checked. Refusing to read it at all would hide two problems behind one.
//
// Every read goes through ParseResponseForCert, including the unverified ones.
// ParseResponse is that function with a nil certificate, and a nil certificate
// makes it reject any response carrying more than one status instead of picking
// the one whose serial matches.
func ParseStaple(der []byte, leaf, issuer *x509.Certificate) (*Staple, error) {
	if len(der) == 0 {
		return nil, nil
	}

	var (
		resp      *ocsp.Response
		err       error
		verified  bool
		verifyErr error
	)
	if issuer != nil {
		resp, err = ocsp.ParseResponseForCert(der, leaf, issuer)
		if err == nil {
			verified = true
		} else {
			// Fall back to an unverified read rather than reporting nothing. A
			// response that fails against the presented issuer is exactly what
			// the caller needs to see, and verifyErr keeps that apart from the
			// case where there was no issuer to check against at all.
			verifyErr = err
			resp, err = ocsp.ParseResponseForCert(der, leaf, nil)
		}
	} else {
		resp, err = ocsp.ParseResponseForCert(der, leaf, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("stapled OCSP response could not be read: %w", err)
	}

	staple := &Staple{
		Status:     ocspStatusName(resp.Status),
		ProducedAt: resp.ProducedAt,
		ThisUpdate: resp.ThisUpdate,
		NextUpdate: resp.NextUpdate,
		Verified:   verified,
		VerifyErr:  verifyErr,
		Responder:  responderName(resp.RawResponderName),
	}
	if resp.SerialNumber != nil {
		staple.SerialNumber = fmt.Sprintf("%x", resp.SerialNumber)
	}
	if resp.Status == ocsp.Revoked {
		staple.RevokedAt = resp.RevokedAt
		staple.RevocationReason = revocationReasonName(resp.RevocationReason)
	}
	return staple, nil
}

// ocspStatusName names the three statuses a responder can return about a
// certificate. Anything else is a response this package did not expect rather
// than a status, so it is labelled as such rather than rendered as a number.
func ocspStatusName(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	default:
		return fmt.Sprintf("unrecognised status (%d)", status)
	}
}

// revocationReasonName names the RFC 5280 CRLReason. The reason is optional, and
// zero means "unspecified" rather than "absent", so it is always named.
func revocationReasonName(reason int) string {
	switch reason {
	case ocsp.Unspecified:
		return "unspecified"
	case ocsp.KeyCompromise:
		return "key compromise"
	case ocsp.CACompromise:
		return "CA compromise"
	case ocsp.AffiliationChanged:
		return "affiliation changed"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessation of operation"
	case ocsp.CertificateHold:
		return "certificate hold"
	case ocsp.RemoveFromCRL:
		return "remove from CRL"
	case ocsp.PrivilegeWithdrawn:
		return "privilege withdrawn"
	case ocsp.AACompromise:
		return "AA compromise"
	default:
		return fmt.Sprintf("unrecognised reason (%d)", reason)
	}
}

// responderName renders the DER-encoded responder subject, when the response
// identified its signer by name. A response that identifies it by key hash
// instead returns empty: a hash is not a name, and printing one here would
// suggest it could be looked up.
func responderName(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdn); err != nil {
		return ""
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)
	return name.String()
}
