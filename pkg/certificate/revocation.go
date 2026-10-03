package certificate

import (
	"fmt"
	"strings"
	"time"
)

// RevocationFinding is a problem with what the server stapled.
//
// These are kept apart from the presentation Findings on purpose. A chain can
// be served perfectly and still carry a revoked or stale staple, and a gate
// written against presentation.ok must not start failing because a new kind
// of finding was added to the list it reads.
type RevocationFinding struct {
	// Problem is the short name, from a fixed vocabulary.
	Problem string
	// Subject is the certificate the staple is about: always the leaf.
	Subject string
	// Detail is one clause of why it matters and what to do about it.
	Detail string
}

// The fixed vocabulary for RevocationFinding.Problem. They are strings rather
// than iota constants because they cross the JSON boundary as-is.
const (
	ProblemRevoked          = "revoked"
	ProblemStaleStaple      = "stale staple"
	ProblemUnknownStatus    = "unknown status"
	ProblemBadStapleSig     = "staple signature invalid"
	ProblemUnreadableStaple = "unreadable staple"
)

// StapleFindings judges what the server stapled, as of now.
//
// Only what was stapled is judged. No staple is not a finding, and neither is a
// signature left unchecked because the server omitted the issuer: that is the
// missing-issuer presentation finding, and reporting it twice would point the
// operator at the staple when the fix is the chain.
//
// It returns nil for a result with no handshake or no staple.
func StapleFindings(result *ConnectResult, now time.Time) []RevocationFinding {
	if result == nil || !result.OCSPStapled {
		return nil
	}

	subject := "(unknown leaf)"
	if len(result.Certificates) > 0 && result.Certificates[0] != nil && result.Certificates[0].Certificate != nil {
		subject = displayName(result.Certificates[0].Certificate)
	}
	finding := func(problem, detail string) RevocationFinding {
		return RevocationFinding{Problem: problem, Subject: subject, Detail: detail}
	}

	if result.StapleErr != nil {
		return []RevocationFinding{finding(ProblemUnreadableStaple,
			"the server stapled an OCSP response that does not parse for this certificate ("+
				result.StapleErr.Error()+"); a client that requires stapling rejects it, so check the server's OCSP cache")}
	}

	staple := result.Staple
	if staple == nil {
		return nil
	}

	var out []RevocationFinding
	switch staple.Status {
	case "good":
	case "revoked":
		detail := "the responder says this certificate is revoked"
		if !staple.RevokedAt.IsZero() {
			detail += fmt.Sprintf(" (since %s, %s)", staple.RevokedAt.UTC().Format(time.RFC3339), staple.RevocationReason)
		}
		out = append(out, finding(ProblemRevoked, detail+"; every client that reads the staple refuses the connection, so replace the certificate"))
	default:
		out = append(out, finding(ProblemUnknownStatus,
			fmt.Sprintf("the responder answered %q rather than good or revoked; it does not recognise this certificate, so check the server staples the response for the certificate it serves", staple.Status)))
	}

	if staple.VerifyErr != nil {
		out = append(out, finding(ProblemBadStapleSig,
			"the stapled response does not verify against the issuer the server presented ("+
				staple.VerifyErr.Error()+"); clients discard it, so check the server is stapling for this chain"))
	}

	if staple.Expired(now) {
		out = append(out, finding(ProblemStaleStaple,
			fmt.Sprintf("the response passed its nextUpdate at %s; the server has stopped refreshing it, and clients that require stapling reject it, so restart or fix its OCSP fetch",
				staple.NextUpdate.UTC().Format(time.RFC3339))))
	}

	return out
}

// FormatStapleFindings renders the findings for the terminal, or an empty
// string when there are none.
func FormatStapleFindings(findings []RevocationFinding) string {
	if len(findings) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Stapled OCSP response:\n")
	for _, f := range findings {
		fmt.Fprintf(&sb, "  • %s: %s\n", f.Problem, f.Subject)
		fmt.Fprintf(&sb, "    %s\n", f.Detail)
	}
	return strings.TrimRight(sb.String(), "\n")
}
