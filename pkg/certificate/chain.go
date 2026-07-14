package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// ChainProblem is something wrong with how a chain was presented, as opposed to
// something wrong with the certificates themselves.
type ChainProblem int

const (
	// ProblemMissingIssuer means a certificate's issuer was not supplied and the
	// certificate is not self-signed. A TLS client that does not chase the AIA
	// URL -- which is to say Go, curl and Java, though not the browsers -- will
	// fail to build a chain. This is the classic "works in Chrome, breaks in
	// curl" bug.
	ProblemMissingIssuer ChainProblem = iota
	// ProblemRedundantRoot means the sender included a self-signed root. Clients
	// ignore it: they trust their own copy or none at all. It is harmless but
	// wastes a round trip's worth of bytes on every handshake.
	ProblemRedundantRoot
	// ProblemOutOfOrder means the certificates were not sent leaf-first, which
	// RFC 8446 asks for. Most clients cope; some embedded stacks do not.
	ProblemOutOfOrder
	// ProblemDuplicate means the same certificate was sent more than once.
	ProblemDuplicate
	// ProblemUnrelated means a certificate belongs to no chain in the bundle.
	ProblemUnrelated
)

// String names the problem.
func (p ChainProblem) String() string {
	switch p {
	case ProblemMissingIssuer:
		return "missing issuer"
	case ProblemRedundantRoot:
		return "redundant root"
	case ProblemOutOfOrder:
		return "out of order"
	case ProblemDuplicate:
		return "duplicate"
	case ProblemUnrelated:
		return "unrelated"
	default:
		return "unknown"
	}
}

// ChainFinding is one problem, tied to the certificate it concerns.
type ChainFinding struct {
	// Problem is what is wrong.
	Problem ChainProblem
	// Subject is the common name of the certificate concerned.
	Subject string
	// Detail explains the finding in a sentence.
	Detail string
	// FetchURLs are the AIA CA-Issuers URLs that would supply a missing issuer.
	// Only set for ProblemMissingIssuer.
	FetchURLs []string
}

// ChainReport compares the chain as it was presented against the chain as it
// should have been.
//
// This is the question openssl explicitly declines to answer: its own docs note
// that s_client -showcerts "displays the server certificate list as sent by the
// server ... it is not a verified chain".
type ChainReport struct {
	// Sent is the chain in the order it was presented.
	Sent []*x509.Certificate
	// Sorted is the chain rebuilt leaf-first.
	Sorted []*x509.Certificate
	// SortErr is whatever SortChain made of the input. It is carried here so a
	// caller that needs the sorted chain does not have to sort it a second time.
	SortErr error
	// Findings are the problems with how it was presented, in the order they
	// were discovered.
	Findings []ChainFinding
}

// OK reports whether the chain was presented correctly.
func (r *ChainReport) OK() bool { return len(r.Findings) == 0 }

// AnalyzeChain compares the chain as presented against the chain as it should
// have been sent, and reports the difference.
//
// certs must be in the order they were presented -- the order a server sent
// them, or the order they appear in a file. Sorting them first destroys the
// very information this looks at.
//
// The analysis is deliberately structural: it looks only at the certificates
// that were sent, and never asks a verifier whether the chain builds.
//
// That is not squeamishness. On macOS, Go's verification delegates to the
// platform, which chases the AIA URL and fetches a missing intermediate off the
// network -- so the very bug this is meant to catch verifies clean. Asking
// "did it verify?" would make the check quietly useless on the platform most
// people run it from. Asking "what did you send me?" cannot be fooled.
func AnalyzeChain(certs []*x509.Certificate) *ChainReport {
	report := &ChainReport{Sent: certs}
	if len(certs) == 0 {
		return report
	}

	sorted, sortErr := SortChain(certs)
	report.Sorted = sorted
	report.SortErr = sortErr

	seen := make(map[string]bool, len(certs))
	for _, cert := range certs {
		fingerprint := FormatFingerprint(cert)
		if seen[fingerprint] {
			report.Findings = append(report.Findings, ChainFinding{
				Problem: ProblemDuplicate,
				Subject: displayName(cert),
				Detail:  "sent more than once",
			})
			continue
		}
		seen[fingerprint] = true

		if cert.Issuer.String() == cert.Subject.String() {
			report.Findings = append(report.Findings, ChainFinding{
				Problem: ProblemRedundantRoot,
				Subject: displayName(cert),
				Detail: "a self-signed root was included; clients ignore it and " +
					"trust their own copy, so it only adds bytes to every handshake",
			})
		}
	}

	// A chain has to terminate at a CA. Whoever is at the top is the last
	// certificate the sender supplied, and the client is expected to take over
	// from there using its own trust store.
	//
	// If that terminus is not a CA, the sender stopped too early: it never sent
	// the intermediate that signed the leaf. This is the "works in Chrome,
	// breaks in curl" bug -- browsers chase the AIA URL and paper over it, but
	// curl, Go and Java do not.
	//
	// If the terminus *is* a CA whose issuer was not sent, that is the normal,
	// correct shape: the client supplies the root. A cross-signed root like
	// GTS Root R1 lands here, and must not be flagged.
	if terminus := chainTerminus(sorted); terminus != nil && !terminus.IsCA {
		finding := ChainFinding{
			Problem:   ProblemMissingIssuer,
			Subject:   displayName(terminus),
			FetchURLs: terminus.IssuingCertificateURL,
			Detail: fmt.Sprintf("the chain stops at a certificate that is not a CA; "+
				"its issuer %q was never sent, so a client that does not chase AIA "+
				"(curl, Go, Java) cannot build a chain",
				nameOrUnknown(terminus.Issuer.CommonName)),
		}
		if len(finding.FetchURLs) == 0 {
			finding.Detail += ", and it carries no AIA URL to fetch it from"
		}
		report.Findings = append(report.Findings, finding)
	}

	// A certificate nobody issued and which issued nobody is just baggage.
	for _, cert := range unrelatedIn(certs) {
		report.Findings = append(report.Findings, ChainFinding{
			Problem: ProblemUnrelated,
			Subject: displayName(cert),
			Detail:  "belongs to no chain in this bundle",
		})
	}

	// Only meaningful when the chain sorted cleanly. Otherwise `sorted` may not
	// hold the same certificates, and the comparison would report an ordering
	// problem that is really a sorting failure.
	if sortErr == nil && !sameOrder(certs, sorted) {
		report.Findings = append(report.Findings, ChainFinding{
			Problem: ProblemOutOfOrder,
			Subject: displayName(certs[0]),
			Detail: "the certificates were not sent leaf-first; RFC 8446 asks for " +
				"leaf-first order and some embedded TLS stacks require it",
		})
	}

	return report
}

// chainTerminus walks up from the leaf and returns the last certificate the
// sender supplied for that chain -- the one whose issuer is absent. It returns
// nil when the chain is empty or loops.
func chainTerminus(sorted []*x509.Certificate) *x509.Certificate {
	if len(sorted) == 0 {
		return nil
	}

	subjects := make(map[string]*x509.Certificate, len(sorted))
	for _, cert := range sorted {
		subjects[cert.Subject.String()] = cert
	}

	current := sorted[0]
	visited := make(map[string]bool, len(sorted))
	for {
		if visited[current.Subject.String()] {
			// Cyclic; there is no terminus to speak of.
			return nil
		}
		visited[current.Subject.String()] = true

		if current.Issuer.String() == current.Subject.String() {
			// Self-signed: the chain ends here, and it is already reported as a
			// redundant root.
			return nil
		}

		parent, ok := subjects[current.Issuer.String()]
		if !ok {
			return current
		}
		current = parent
	}
}

// unrelatedIn returns the certificates that neither issued nor were issued by
// anything else in the bundle. A single self-signed certificate on its own is
// not unrelated -- it is the whole chain.
func unrelatedIn(certs []*x509.Certificate) []*x509.Certificate {
	if len(certs) < 2 {
		return nil
	}

	var unrelated []*x509.Certificate
	for i, cert := range certs {
		connected := false
		for j, other := range certs {
			if i == j {
				continue
			}
			if cert.Issuer.String() == other.Subject.String() ||
				other.Issuer.String() == cert.Subject.String() {
				connected = true
				break
			}
		}
		if !connected {
			unrelated = append(unrelated, cert)
		}
	}
	return unrelated
}

// sameOrder reports whether two chains hold the same certificates in the same
// order.
func sameOrder(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// displayName is the certificate's common name, or its serial if it has none.
func displayName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return "serial " + cert.SerialNumber.String()
}

// nameOrUnknown guards against a blank common name in a message.
func nameOrUnknown(name string) string {
	if name == "" {
		return "(no common name)"
	}
	return name
}

// FormatChainReport renders the report for the terminal. It returns an empty
// string when the chain was presented correctly, so a caller can print it
// unconditionally.
func FormatChainReport(report *ChainReport) string {
	if report == nil || report.OK() {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Chain as presented:\n")

	for _, finding := range report.Findings {
		fmt.Fprintf(&sb, "  • %s: %s\n", finding.Problem, finding.Subject)
		fmt.Fprintf(&sb, "    %s\n", finding.Detail)
		for _, url := range finding.FetchURLs {
			fmt.Fprintf(&sb, "    fetch from: %s\n", url)
		}
	}

	return strings.TrimRight(sb.String(), "\n")
}
