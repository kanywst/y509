package certificate

import (
	"crypto/x509"
	"strings"
	"testing"
)

// hasProblem reports whether the report contains a finding of the given kind.
func hasProblem(report *ChainReport, problem ChainProblem) bool {
	for _, finding := range report.Findings {
		if finding.Problem == problem {
			return true
		}
	}
	return false
}

func problemNames(report *ChainReport) []string {
	names := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		names = append(names, finding.Problem.String())
	}
	return names
}

// TestAnalyzeChain_WellFormed is the case that must stay silent: leaf then
// intermediate, with the root left to the client. This is what a correctly
// configured server sends.
func TestAnalyzeChain_WellFormed(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	report := AnalyzeChain([]*x509.Certificate{leaf, intermediate})
	if !report.OK() {
		t.Errorf("a correctly served chain was flagged: %v", problemNames(report))
	}
}

// TestAnalyzeChain_MissingIntermediate is the bug worth catching: the server
// sends only the leaf, so a client that does not chase AIA cannot build a
// chain. This is the "works in Chrome, breaks in curl" case.
func TestAnalyzeChain_MissingIntermediate(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	report := AnalyzeChain([]*x509.Certificate{leaf})
	if !hasProblem(report, ProblemMissingIssuer) {
		t.Fatalf("a missing intermediate was not reported; findings: %v", problemNames(report))
	}

	for _, finding := range report.Findings {
		if finding.Problem == ProblemMissingIssuer {
			if !strings.Contains(finding.Detail, "Issuing CA") {
				t.Errorf("the finding does not name the missing issuer: %q", finding.Detail)
			}
		}
	}
}

// TestAnalyzeChain_CrossSignedRootIsNotMissingItsIssuer is the false positive to
// avoid. A cross-signed root sits at the top of the chain with its own issuer
// absent -- and always will, because the client trusts the root itself. This is
// what google.com sends (GTS Root R1, issued by GlobalSign Root CA).
func TestAnalyzeChain_CrossSignedRootIsNotMissingItsIssuer(t *testing.T) {
	oldRoot, oldRootKey := issue(t, "Legacy Root CA", true, nil, nil)
	// A CA certificate whose issuer is the legacy root: this is the shape of a
	// cross-signed root, and its own issuer is never sent.
	crossSigned, crossSignedKey := issue(t, "Modern Root CA", true, oldRoot, oldRootKey)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, crossSigned, crossSignedKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	report := AnalyzeChain([]*x509.Certificate{leaf, intermediate, crossSigned})
	if hasProblem(report, ProblemMissingIssuer) {
		t.Errorf("a cross-signed root at the top was wrongly reported as a missing issuer; findings: %v",
			problemNames(report))
	}
}

// TestAnalyzeChain_RedundantRoot covers a server shipping its own root.
func TestAnalyzeChain_RedundantRoot(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	report := AnalyzeChain([]*x509.Certificate{leaf, intermediate, root})
	if !hasProblem(report, ProblemRedundantRoot) {
		t.Errorf("a self-signed root in the bundle was not reported; findings: %v", problemNames(report))
	}
	// It is redundant, not missing.
	if hasProblem(report, ProblemMissingIssuer) {
		t.Errorf("shipping the root must not also report a missing issuer; findings: %v",
			problemNames(report))
	}
}

// TestAnalyzeChain_OutOfOrder covers a server sending the intermediate first.
func TestAnalyzeChain_OutOfOrder(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	report := AnalyzeChain([]*x509.Certificate{intermediate, leaf})
	if !hasProblem(report, ProblemOutOfOrder) {
		t.Errorf("a chain sent intermediate-first was not reported; findings: %v", problemNames(report))
	}
}

// TestAnalyzeChain_Duplicate covers the same certificate sent twice.
func TestAnalyzeChain_Duplicate(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	report := AnalyzeChain([]*x509.Certificate{leaf, intermediate, intermediate})
	if !hasProblem(report, ProblemDuplicate) {
		t.Errorf("a duplicated certificate was not reported; findings: %v", problemNames(report))
	}
}

// TestAnalyzeChain_Unrelated covers a certificate that belongs to no chain in
// the bundle.
func TestAnalyzeChain_Unrelated(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	otherRoot, otherRootKey := issue(t, "Unrelated Root", true, nil, nil)
	stranger, _ := issue(t, "stranger.example.net", false, otherRoot, otherRootKey)

	report := AnalyzeChain([]*x509.Certificate{leaf, intermediate, stranger})
	if !hasProblem(report, ProblemUnrelated) {
		t.Errorf("a stranger in the bundle was not reported; findings: %v", problemNames(report))
	}
}

// TestAnalyzeChain_SelfSignedAlone covers a single self-signed certificate: it
// is a redundant root, but nothing is missing and nothing is unrelated.
func TestAnalyzeChain_SelfSignedAlone(t *testing.T) {
	selfSigned, _ := issue(t, "self-signed.example.com", true, nil, nil)

	report := AnalyzeChain([]*x509.Certificate{selfSigned})
	if hasProblem(report, ProblemMissingIssuer) {
		t.Errorf("a self-signed certificate has no missing issuer; findings: %v", problemNames(report))
	}
	if hasProblem(report, ProblemUnrelated) {
		t.Errorf("a lone self-signed certificate is not unrelated to itself; findings: %v",
			problemNames(report))
	}
}

// TestAnalyzeChain_Empty covers the degenerate input.
func TestAnalyzeChain_Empty(t *testing.T) {
	report := AnalyzeChain(nil)
	if !report.OK() {
		t.Errorf("an empty chain should produce no findings, got %v", problemNames(report))
	}
	if FormatChainReport(report) != "" {
		t.Error("an empty chain should format to nothing")
	}
}

// TestFormatChainReport_SilentWhenClean checks that a clean chain formats to the
// empty string, so callers can print it unconditionally.
func TestFormatChainReport_SilentWhenClean(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	report := AnalyzeChain([]*x509.Certificate{leaf, intermediate})
	if got := FormatChainReport(report); got != "" {
		t.Errorf("a clean chain should format to nothing, got:\n%s", got)
	}
}

// TestAnalyzeChain_CarriesSortedChain checks the report hands back the sorted
// chain, so a caller does not have to sort a second time.
func TestAnalyzeChain_CarriesSortedChain(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	// Presented backwards.
	report := AnalyzeChain([]*x509.Certificate{intermediate, leaf})

	if report.SortErr != nil {
		t.Fatalf("SortErr = %v, want nil", report.SortErr)
	}
	if len(report.Sorted) != 2 {
		t.Fatalf("Sorted holds %d certificates, want 2", len(report.Sorted))
	}
	if !report.Sorted[0].Equal(leaf) {
		t.Errorf("Sorted[0] = %q, want the leaf", report.Sorted[0].Subject.CommonName)
	}
	// The sent order is preserved untouched alongside it.
	if !report.Sent[0].Equal(intermediate) {
		t.Errorf("Sent[0] = %q, want the intermediate that was actually sent first",
			report.Sent[0].Subject.CommonName)
	}
}

// TestAnalyzeChain_DuplicateIsNotUnrelated is a regression: two copies of the
// same certificate are not each other's issuer, so unrelatedIn used to flag a
// duplicated leaf as unrelated -- twice -- on top of the duplicate finding.
func TestAnalyzeChain_DuplicateIsNotUnrelated(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	report := AnalyzeChain([]*x509.Certificate{leaf, leaf})

	if !hasProblem(report, ProblemDuplicate) {
		t.Errorf("a duplicated leaf should be reported as a duplicate; findings: %v", problemNames(report))
	}
	if hasProblem(report, ProblemUnrelated) {
		t.Errorf("a duplicated leaf must not also be reported as unrelated; findings: %v", problemNames(report))
	}
}

// TestAnalyzeChain_NilEntries checks the exported entry point survives nil
// certificates in the slice rather than panicking on the first dereference.
func TestAnalyzeChain_NilEntries(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	t.Run("nil among real certs", func(t *testing.T) {
		// Dropping the nil leaves a well-formed leaf+intermediate pair, so the
		// point is simply that it is analyzed without panicking and the nil is
		// not itself mistaken for a certificate.
		report := AnalyzeChain([]*x509.Certificate{leaf, nil, intermediate})
		if !report.OK() {
			t.Errorf("the leaf+intermediate pair should analyze clean, got %v", problemNames(report))
		}
	})

	t.Run("all nil", func(t *testing.T) {
		report := AnalyzeChain([]*x509.Certificate{nil, nil})
		if !report.OK() {
			t.Errorf("a slice of only nils should produce no findings, got %v", problemNames(report))
		}
	})
}

// TestAnalyzeChain_LeafNotFlaggedUnrelated is a regression: when the
// intermediate is missing, the leaf has no neighbour in the bundle, so the old
// pairwise check reported the validation target itself as "unrelated" on top of
// the missing-issuer finding.
func TestAnalyzeChain_LeafNotFlaggedUnrelated(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	otherRoot, otherRootKey := issue(t, "Other Root", true, nil, nil)
	stranger, _ := issue(t, "stranger.net", false, otherRoot, otherRootKey)

	// The intermediate is absent, so the leaf connects to nothing.
	report := AnalyzeChain([]*x509.Certificate{leaf, stranger})

	if !hasProblem(report, ProblemMissingIssuer) {
		t.Errorf("the missing intermediate should be reported; findings: %v", problemNames(report))
	}
	for _, finding := range report.Findings {
		if finding.Problem == ProblemUnrelated && finding.Subject == "leaf.example.com" {
			t.Error("the primary leaf must never be reported as unrelated")
		}
	}
	// The stranger, on the other hand, is genuinely unrelated.
	if !hasProblem(report, ProblemUnrelated) {
		t.Errorf("the stranger should be reported as unrelated; findings: %v", problemNames(report))
	}
}

// TestAnalyzeChain_DisjointSecondChainIsUnrelated checks that a whole second
// chain -- whose members are connected to each other but not to the primary
// leaf -- is reported as unrelated. A pairwise "has any neighbour" test misses
// this, because each member has a neighbour within its own chain.
func TestAnalyzeChain_DisjointSecondChainIsUnrelated(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	otherRoot, otherRootKey := issue(t, "Other Root", true, nil, nil)
	otherIntermediate, otherIntermediateKey := issue(t, "Other CA", true, otherRoot, otherRootKey)
	otherLeaf, _ := issue(t, "other.example.net", false, otherIntermediate, otherIntermediateKey)

	report := AnalyzeChain([]*x509.Certificate{leaf, intermediate, otherIntermediate, otherLeaf})

	unrelated := map[string]bool{}
	for _, finding := range report.Findings {
		if finding.Problem == ProblemUnrelated {
			unrelated[finding.Subject] = true
		}
	}
	for _, want := range []string{"Other CA", "other.example.net"} {
		if !unrelated[want] {
			t.Errorf("%q should be reported as unrelated; findings: %v", want, problemNames(report))
		}
	}
	if unrelated["leaf.example.com"] || unrelated["Issuing CA"] {
		t.Error("the primary chain must not be reported as unrelated")
	}
}
