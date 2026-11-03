package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Advisory is a non-gating note about a certificate, judged without verifying
// anything. Advisories have no ok and no fail-on keyword.
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

// shortLivedSchedule is the CA/Browser Forum short-lived subscriber limit
// (Ballot SC-063), newest first, evaluated against NotBefore.
var shortLivedSchedule = []struct {
	from time.Time
	secs int64
}{
	{time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC), 7 * 24 * 60 * 60},
	{time.Time{}, 10 * 24 * 60 * 60},
}

// isShortLived counts the validity period inclusive of both ends, as RFC 5280
// does, in Unix seconds so a far-future NotAfter cannot overflow.
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

// RevocationPointerAdvisories reports each certificate with no AIA CA Issuers
// URL, and each with no CRL distribution point that is neither short-lived nor
// has an OCSP URL. A missing OCSP URL alone is never reported: SC-063 made OCSP
// optional. A self-signed certificate has no issuer to point at and is skipped;
// a self-issued one from a key rollover does have one.
func RevocationPointerAdvisories(certs []*x509.Certificate) []Advisory {
	var out []Advisory
	for _, cert := range certs {
		if cert == nil || isGenuinelySelfSigned(cert) {
			continue
		}
		name := displayName(cert)

		if !hasURL(cert.IssuingCertificateURL) {
			out = append(out, Advisory{
				Problem: ProblemNoAIA,
				Subject: name,
				Detail:  "no CA Issuers URL, so a client missing its issuer has nowhere to fetch it from; reissue it with one",
			})
		}

		if !hasURL(cert.CRLDistributionPoints) && !hasURL(cert.OCSPServer) && !isShortLived(cert) {
			out = append(out, Advisory{
				Problem: ProblemNoCRL,
				Subject: name,
				Detail:  "neither a CRL distribution point nor an OCSP URL, so no client can learn it was revoked; reissue it with a CRL distribution point",
			})
		}
	}
	return out
}

// hasURL reports whether any of the locations is non-empty.
func hasURL(urls []string) bool {
	for _, u := range urls {
		if strings.TrimSpace(u) != "" {
			return true
		}
	}
	return false
}

// FormatAdvisories renders the advisories for the terminal, or an empty string
// when there are none.
func FormatAdvisories(advisories []Advisory) string {
	if len(advisories) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Advisories:\n")
	for _, a := range advisories {
		fmt.Fprintf(&sb, "  • %s: %s\n", a.Problem, a.Subject)
		fmt.Fprintf(&sb, "    %s\n", a.Detail)
	}
	return strings.TrimRight(sb.String(), "\n")
}
