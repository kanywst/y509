package certificate

import (
	"crypto/dsa" //nolint:staticcheck // only to recognise a DSA key, never to use one
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

// Policy is an opt-in set of algorithm rules. Only some clients enforce one,
// so it is never judged unasked.
type Policy string

// PolicyFIPS is the FIPS 140-3 approved algorithms, as Go's fips140=only mode
// enforces them when verifying (checkFIPS140OnlyPublicKey in crypto/rsa).
const PolicyFIPS Policy = "fips"

var policies = []Policy{PolicyFIPS}

// ParsePolicy reads a policy name.
func ParsePolicy(name string) (Policy, error) {
	for _, p := range policies {
		if strings.EqualFold(name, string(p)) {
			return p, nil
		}
	}
	names := make([]string, len(policies))
	for i, p := range policies {
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

// fipsMinRSABits is the SP 800-131A floor.
const fipsMinRSABits = 2048

// approvedSLHDSA is the SLH-DSA parameter sets (FIPS 205), matched by name
// since Go does not decode them.
var approvedSLHDSA = func() map[string]bool {
	out := make(map[string]bool, len(pqcAlgorithmNames))
	for _, name := range pqcAlgorithmNames {
		if strings.HasPrefix(name, "SLH-DSA-") {
			out[name] = true
		}
	}
	return out
}()

// PolicyFindings checks each certificate against the policy, and returns nil
// for a policy ParsePolicy does not accept. The findings are kept out of
// conformance, so conformance.ok keeps its meaning.
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

		// As in conformance: a root's own signature is never checked.
		if !fipsApprovedSignature(cert) && !isGenuinelySelfSigned(cert) {
			out = append(out, ConformanceFinding{
				Problem: ProblemUnapprovedSignature,
				Subject: name,
				Detail: fmt.Sprintf("signed with %s, which FIPS 140-3 does not approve, so a client in FIPS mode rejects the chain; reissue it signed with RSA or ECDSA over SHA-256 or stronger, Ed25519 or ML-DSA",
					SignatureAlgorithmName(cert)),
			})
		}

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
			return fmt.Sprintf("an RSA public exponent of %d, below the 65537 FIPS 186-5 requires", pub.E)
		case pub.E%2 == 0:
			return fmt.Sprintf("an even RSA public exponent of %d, which FIPS 186-5 does not allow", pub.E)
		}
		return ""
	case *ecdsa.PublicKey:
		// As crypto/tls allows in FIPS mode: not P-224.
		switch pub.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return ""
		}
		return fmt.Sprintf("an ECDSA key on %s, a curve FIPS-mode TLS does not allow", curveName(pub))
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

func curveName(pub *ecdsa.PublicKey) string {
	if pub.Curve == nil {
		return "an unknown curve"
	}
	return pub.Curve.Params().Name
}

// FormatPolicyFindings renders the verdict for the terminal. A pass is printed
// too, since the policy was asked for.
func FormatPolicyFindings(policy Policy, findings []ConformanceFinding) string {
	if len(findings) == 0 {
		return fmt.Sprintf("%s: met", policy.Title())
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s:\n", policy.Title())
	for _, f := range findings {
		fmt.Fprintf(&sb, "  • %s: %s\n", f.Problem, f.Subject)
		fmt.Fprintf(&sb, "    %s\n", f.Detail)
	}
	return strings.TrimRight(sb.String(), "\n")
}
