package certificate

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

// ConformanceFinding is a certificate that breaks a rule clients enforce,
// independent of how the chain was served or whether it verifies here.
//
// These are kept apart from presentation and revocation for the same reason
// those two are apart: each has its own ok, so a gate written against one
// does not change meaning when another grows.
//
// The rules are hand-rolled rather than imported from zlint. zlint checks
// hundreds of Baseline Requirements clauses, most of which are a CA's problem
// and predict no client failure; y509 only reports what a client rejects.
type ConformanceFinding struct {
	// Problem is the short name, from a fixed vocabulary.
	Problem string
	// Subject is the certificate concerned.
	Subject string
	// Detail is one clause of why it matters and what to do about it.
	Detail string
}

// The fixed vocabulary for ConformanceFinding.Problem.
const (
	ProblemWeakSignature = "weak signature"
	ProblemWeakKey       = "weak key"
	ProblemNoSAN         = "no SAN"
)

// minRSABits is the smallest RSA modulus browsers and the CA/Browser Forum
// still accept.
const minRSABits = 2048

// ConformanceFindings checks each certificate as presented.
func ConformanceFindings(certs []*x509.Certificate) []ConformanceFinding {
	var out []ConformanceFinding
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		name := displayName(cert)

		// A self-signed certificate's own signature is never checked by a
		// client: it is trusted because it is in the store, not because of how
		// it was signed. A SHA-1 self-signature on a root is harmless.
		if weakSignatureAlgorithm(cert.SignatureAlgorithm) && !isSelfSigned(cert) {
			out = append(out, ConformanceFinding{
				Problem: ProblemWeakSignature,
				Subject: name,
				Detail: fmt.Sprintf("signed with %s, which browsers and Go have rejected since 2017 and 2022; reissue it from the CA with SHA-256",
					cert.SignatureAlgorithm),
			})
		}

		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok && pub.N.BitLen() < minRSABits {
			out = append(out, ConformanceFinding{
				Problem: ProblemWeakKey,
				Subject: name,
				Detail: fmt.Sprintf("an RSA key of %d bits, below the %d bits clients require; reissue it with a new key of at least %d bits",
					pub.N.BitLen(), minRSABits, minRSABits),
			})
		}

		if lacksSAN(cert) {
			out = append(out, ConformanceFinding{
				Problem: ProblemNoSAN,
				Subject: name,
				Detail: fmt.Sprintf("the name %q is only in the common name, with no subject alternative names; Chrome and Go ignore the common name, so reissue it with the name as a DNS SAN",
					cert.Subject.CommonName),
			})
		}
	}
	return out
}

// weakSignatureAlgorithm reports the signature algorithms clients no longer
// accept on a certificate they have to check.
func weakSignatureAlgorithm(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// isSelfSigned is a name match, like JSONCertificate.SelfSigned. Checking the
// signature would also catch a certificate that merely claims to be self-issued,
// but that one fails to verify anyway, and trust already says so.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// lacksSAN reports a server certificate that names its host only in the common
// name.
//
// It is limited to certificates a TLS server could present: a CA, or an
// end-entity certificate for code signing or S/MIME, has no reason to carry a
// DNS name, and flagging it would be noise.
func lacksSAN(cert *x509.Certificate) bool {
	if cert.IsCA || cert.Subject.CommonName == "" {
		return false
	}
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 ||
		len(cert.URIs) > 0 || len(OtherSANs(cert)) > 0 {
		return false
	}
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// FormatConformanceFindings renders the findings for the terminal, or an empty
// string when there are none.
func FormatConformanceFindings(findings []ConformanceFinding) string {
	if len(findings) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Conformance:\n")
	for _, f := range findings {
		fmt.Fprintf(&sb, "  • %s: %s\n", f.Problem, f.Subject)
		fmt.Fprintf(&sb, "    %s\n", f.Detail)
	}
	return strings.TrimRight(sb.String(), "\n")
}
