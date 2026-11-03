package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Advisory is a certificate that verifies today but leaves a client less to
// work with when something goes wrong: a chain sent incomplete, or a key that
// has to be revoked.
//
// Advisories are the "verifies but fragile" severity. They have no ok and no
// fail-on gate, so adding one never changes what an existing gate means.
type Advisory struct {
	// Problem is the short name, from a fixed vocabulary.
	Problem string
	// Subject is the certificate concerned.
	Subject string
	// Detail is one clause of why it matters and what to do about it.
	Detail string
}

// The fixed vocabulary for Advisory.Problem.
const (
	ProblemNoAIA = "no AIA"
	ProblemNoCRL = "no CRL pointer"
)

// shortLivedSchedule is the CA/Browser Forum's short-lived subscriber
// certificate limit (Ballot SC-063), newest first, evaluated against NotBefore
// like the lifetime maximum. A certificate at or under it may carry neither a
// CRL nor an OCSP pointer: it expires before a revocation would reach anyone.
var shortLivedSchedule = []struct {
	from time.Time
	secs int64
}{
	{time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC), 7 * 24 * 60 * 60},
	{time.Time{}, 10 * 24 * 60 * 60},
}

// isShortLived reports a subscriber certificate within the short-lived limit
// that applied when it was issued. The validity period is inclusive of both
// ends, as RFC 5280 and the Baseline Requirements count it. Unix seconds, so a
// far-future NotAfter cannot overflow.
func isShortLived(cert *x509.Certificate) bool {
	if cert.IsCA {
		return false
	}
	period := cert.NotAfter.Unix() - cert.NotBefore.Unix() + 1
	for _, step := range shortLivedSchedule {
		if !cert.NotBefore.Before(step.from) {
			return period <= step.secs
		}
	}
	return false
}

// RevocationPointerAdvisories reports each certificate, as presented, that has
// no AIA CA Issuers URL, or no CRL distribution point while it is neither
// short-lived nor has an OCSP URL.
//
// A missing OCSP URL on its own is never reported: the CA/Browser Forum made
// OCSP optional in 2023 and the public CAs are dropping it, so a CRL pointer is
// what a revocation check needs. A self-issued certificate is skipped, since it
// has no issuer to point at and nothing above it to revoke it.
//
// Nothing is fetched. The AIA is reported because it is what a browser follows
// when a server forgets the intermediate, not because y509 follows it.
func RevocationPointerAdvisories(certs []*x509.Certificate) []Advisory {
	var out []Advisory
	for _, cert := range certs {
		if cert == nil || cert.Issuer.String() == cert.Subject.String() {
			continue
		}
		name := displayName(cert)

		if len(cert.IssuingCertificateURL) == 0 {
			out = append(out, Advisory{
				Problem: ProblemNoAIA,
				Subject: name,
				Detail:  "it carries no AIA CA Issuers URL, so if a server ever sends it without its issuer, not even a browser can fetch the missing certificate; reissue it with one, and always serve the full chain",
			})
		}

		if len(cert.CRLDistributionPoints) == 0 && len(cert.OCSPServer) == 0 && !isShortLived(cert) {
			out = append(out, Advisory{
				Problem: ProblemNoCRL,
				Subject: name,
				Detail:  "it carries neither a CRL distribution point nor an OCSP URL and is not short-lived, so no client can learn that it was revoked; reissue it with a CRL distribution point",
			})
		}
	}
	return out
}

// FormatAdvisories renders the advisories for the terminal, or an empty string
// when there are none.
func FormatAdvisories(advisories []Advisory) string {
	if len(advisories) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Advisories (the chain still works):\n")
	for _, a := range advisories {
		fmt.Fprintf(&sb, "  • %s: %s\n", a.Problem, a.Subject)
		fmt.Fprintf(&sb, "    %s\n", a.Detail)
	}
	return strings.TrimRight(sb.String(), "\n")
}
