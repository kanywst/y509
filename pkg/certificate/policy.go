package certificate

import (
	"crypto/dsa" //nolint:staticcheck // only to recognise a DSA key, never to use one
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

// Policy is a set of algorithm rules a certificate is judged against on
// request, beyond the ones every client enforces.
//
// A policy is opt-in because its clients are: a FIPS-mode client rejects a
// certificate that every other client accepts, so reporting it unasked would
// be noise for everyone else.
type Policy string

// PolicyFIPS is the FIPS 140-3 approved-algorithm rules, as a client running
// in FIPS-only mode enforces them when it verifies a chain: Go with
// GODEBUG=fips140=only, OpenSSL with the FIPS provider, a RHEL host in FIPS
// mode. The rules are the verifying side of NIST SP 800-131A Rev. 2 and FIPS
// 186-5, which is what Go's crypto/rsa checks in checkFIPS140OnlyPublicKey.
//
// FIPS 140 "levels" are not here: Level 1 to 4 grade a cryptographic module's
// physical security, which no certificate can show.
const PolicyFIPS Policy = "fips"

// Policies lists the policies ParsePolicy accepts, for flag help and errors.
var Policies = []Policy{PolicyFIPS}

// ParsePolicy reads a policy name.
func ParsePolicy(name string) (Policy, error) {
	for _, p := range Policies {
		if strings.EqualFold(name, string(p)) {
			return p, nil
		}
	}
	names := make([]string, len(Policies))
	for i, p := range Policies {
		names[i] = string(p)
	}
	return "", fmt.Errorf("unknown policy %q (expected %s)", name, strings.Join(names, ", "))
}

// Title names the policy for the text report.
func (p Policy) Title() string {
	switch p {
	case PolicyFIPS:
		return "FIPS 140-3"
	}
	return string(p)
}

// The fixed vocabulary for a policy finding's Problem.
const (
	ProblemUnapprovedSignature = "unapproved signature"
	ProblemUnapprovedKey       = "unapproved key"
)

// fipsMinRSABits is the smallest modulus SP 800-131A allows for verifying,
// the 112-bit security floor.
const fipsMinRSABits = 2048

// approvedSLHDSA is the SLH-DSA parameter sets, all approved by FIPS 205. Go
// does not decode them, so they are matched by name from pqcAlgorithmNames.
var approvedSLHDSA = func() map[string]bool {
	out := make(map[string]bool, len(pqcAlgorithmNames))
	for _, name := range pqcAlgorithmNames {
		if strings.HasPrefix(name, "SLH-DSA-") {
			out[name] = true
		}
	}
	return out
}()

// PolicyFindings checks each certificate as presented against the policy.
// The findings share ConformanceFinding's shape, but are kept out of
// conformance: a gate on conformance.ok must not start failing a chain because
// someone asked about FIPS.
func PolicyFindings(policy Policy, certs []*x509.Certificate) []ConformanceFinding {
	if policy != PolicyFIPS {
		return nil
	}

	var out []ConformanceFinding
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		name := displayName(cert)

		// A root's self-signature is never checked, in FIPS mode or out of
		// it, so a SHA-1 one fails nothing. As in conformance, the exemption
		// needs the signature to verify, not just matching names.
		if !fipsApprovedSignature(cert) && !isGenuinelySelfSigned(cert) {
			out = append(out, ConformanceFinding{
				Problem: ProblemUnapprovedSignature,
				Subject: name,
				Detail: fmt.Sprintf("signed with %s, which FIPS 140-3 does not approve, so a client in FIPS mode rejects the chain; reissue it signed with RSA or ECDSA over SHA-256 or stronger, Ed25519 or ML-DSA",
					SignatureAlgorithmName(cert)),
			})
		}

		// The key is checked on every certificate, a root included: it is
		// what verifies the certificate below it.
		if why := fipsKeyProblem(cert); why != "" {
			out = append(out, ConformanceFinding{
				Problem: ProblemUnapprovedKey,
				Subject: name,
				Detail:  why + ", which a client in FIPS mode refuses to verify with; reissue it with a new key",
			})
		}
	}
	return out
}

// fipsApprovedSignature reports a signature algorithm a FIPS-mode verifier
// accepts: SHA-2 for RSA and ECDSA, plus the FIPS 186-5, 204 and 205
// schemes.
func fipsApprovedSignature(cert *x509.Certificate) bool {
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.PureEd25519,
		x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		return true
	case x509.UnknownSignatureAlgorithm:
		return approvedSLHDSA[SignatureAlgorithmName(cert)]
	}
	return false
}

// fipsKeyProblem says what is wrong with the subject public key, or "".
func fipsKeyProblem(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		switch {
		case bits < fipsMinRSABits:
			return fmt.Sprintf("an RSA key of %d bits, below the %d bits FIPS requires", bits, fipsMinRSABits)
		case bits%2 == 1:
			return fmt.Sprintf("an RSA key of %d bits, an odd size FIPS 186-5 does not allow", bits)
		case pub.E <= 1<<16:
			return fmt.Sprintf("an RSA public exponent of %d, at or below the 65537 floor of FIPS 186-5", pub.E)
		case pub.E%2 == 0:
			return fmt.Sprintf("an even RSA public exponent of %d, which FIPS 186-5 does not allow", pub.E)
		}
		return ""
	case *ecdsa.PublicKey:
		// crypto/x509 only parses the NIST curves, all of them approved, so a
		// curve here never needs judging.
		return ""
	case ed25519.PublicKey, *mldsa.PublicKey:
		return ""
	case *dsa.PublicKey:
		return "a DSA key, which FIPS 186-5 no longer approves for signatures"
	}
	if approvedSLHDSA[PublicKeyAlgorithmName(cert)] {
		return ""
	}
	return fmt.Sprintf("a %s key, which FIPS 140-3 does not approve", PublicKeyAlgorithmName(cert))
}

// FormatPolicyFindings renders the verdict for the terminal. Unlike the other
// sections it says so when there is nothing to report: the policy was asked
// for, and silence would read the same as a check that never ran.
func FormatPolicyFindings(policy Policy, findings []ConformanceFinding) string {
	if len(findings) == 0 {
		return fmt.Sprintf("%s: every certificate sent uses approved algorithms", policy.Title())
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s:\n", policy.Title())
	for _, f := range findings {
		fmt.Fprintf(&sb, "  • %s: %s\n", f.Problem, f.Subject)
		fmt.Fprintf(&sb, "    %s\n", f.Detail)
	}
	return strings.TrimRight(sb.String(), "\n")
}
