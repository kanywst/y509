package certificate

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// marshal renders a report the way the command does, and returns both the raw
// bytes and the generic decoding, so a test can assert on the wire form rather
// than on the Go structs it was built from. Asserting on the structs would pass
// even if every json tag were wrong.
func marshal(t *testing.T, report *JSONReport) (string, map[string]any) {
	t.Helper()

	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		t.Fatalf("the report does not marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &decoded); err != nil {
		t.Fatalf("the report does not round-trip: %v", err)
	}
	return sb.String(), decoded
}

// TestJSONReport_LevelsAreStrings is the contract this whole type exists to
// protect. TrustLevel and ChainProblem are iota constants, and marshalling them
// directly would publish their numeric values as an API -- which then breaks
// the moment a constant is inserted in the middle.
func TestJSONReport_LevelsAreStrings(t *testing.T) {
	for _, tc := range []struct {
		level TrustLevel
		want  string
	}{
		{TrustAnchored, "trusted"},
		{TrustSelfAnchored, "self-anchored"},
		{TrustBroken, "broken"},
	} {
		report := NewJSONReport("", nil, &VerifyResult{Level: tc.level})
		_, decoded := marshal(t, report)

		trust, ok := decoded["trust"].(map[string]any)
		if !ok {
			t.Fatalf("trust is not an object: %#v", decoded["trust"])
		}
		if got := trust["level"]; got != tc.want {
			t.Errorf("level = %#v, want %q", got, tc.want)
		}
	}
}

// TestJSONReport_TrustedMirrorsTheExitCode: the boolean is the convenience
// field, and it must agree with the level rather than drift from it.
func TestJSONReport_TrustedMirrorsTheExitCode(t *testing.T) {
	for _, level := range []TrustLevel{TrustAnchored, TrustSelfAnchored, TrustBroken} {
		report := NewJSONReport("", nil, &VerifyResult{Level: level})
		want := level == TrustAnchored
		if report.Trust.Trusted != want {
			t.Errorf("level %s: trusted = %v, want %v", level, report.Trust.Trusted, want)
		}
	}
}

// TestJSONReport_SelfAnchoredCarriesItsReason is the distinction the exit code
// cannot make: self-anchored and broken both exit 1, so a consumer needs the
// level and the error to tell an internal PKI apart from a real failure.
func TestJSONReport_SelfAnchoredCarriesItsReason(t *testing.T) {
	report := NewJSONReport("", nil, &VerifyResult{
		Level:  TrustSelfAnchored,
		Anchor: "Internal Root CA",
		Err:    errors.New("x509: certificate signed by unknown authority"),
	})

	if report.Trust.Level != "self-anchored" {
		t.Errorf("level = %q", report.Trust.Level)
	}
	if report.Trust.Anchor != "Internal Root CA" {
		t.Errorf("anchor = %q", report.Trust.Anchor)
	}
	if !strings.Contains(report.Trust.Error, "unknown authority") {
		t.Errorf("error = %q, want the trust store's reason", report.Trust.Error)
	}
}

// TestJSONReport_EmptyFindingsMarshalAsArray guards the null-vs-[] trap: "no
// findings" is the common case, and a consumer ranging over a null gets an
// unhelpful surprise in most languages.
func TestJSONReport_EmptyFindingsMarshalAsArray(t *testing.T) {
	report := NewJSONReport("", nil, &VerifyResult{Level: TrustAnchored})
	raw, decoded := marshal(t, report)

	if strings.Contains(raw, "null") {
		t.Errorf("the report contains a null:\n%s", raw)
	}

	presentation, ok := decoded["presentation"].(map[string]any)
	if !ok {
		t.Fatalf("presentation is not an object: %#v", decoded["presentation"])
	}
	if _, ok := presentation["findings"].([]any); !ok {
		t.Errorf("findings is not an array: %#v", presentation["findings"])
	}
	if _, ok := decoded["chain"].([]any); !ok {
		t.Errorf("chain is not an array: %#v", decoded["chain"])
	}
}

// TestJSONReport_TrustedChainCanStillBeMisserved is the headline case, and the
// reason a consumer must not stop at the trust level: incomplete-chain.badssl.com
// verifies on a platform that chases AIA and is still misconfigured.
func TestJSONReport_TrustedChainCanStillBeMisserved(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	// Only the leaf is sent, so the intermediate is missing.
	chainReport := AnalyzeChain([]*x509.Certificate{leaf})
	report := NewJSONReport("leaf.example.com", chainReport, &VerifyResult{Level: TrustAnchored})

	if !report.Trust.Trusted {
		t.Fatal("the fixture is meant to be trusted")
	}
	if report.Presentation.OK {
		t.Fatal("a chain missing its intermediate was reported as correctly served")
	}

	var found bool
	for _, finding := range report.Presentation.Findings {
		if finding.Problem == "missing issuer" {
			found = true
			if !strings.Contains(finding.Detail, "Issuing CA") {
				t.Errorf("the finding does not name the missing issuer: %q", finding.Detail)
			}
		}
	}
	if !found {
		t.Errorf("no missing-issuer finding; got %#v", report.Presentation.Findings)
	}
}

// TestJSONReport_ChainIsInThePresentedOrder: sorting is what destroys the
// evidence, so the emitted chain must be the one that was sent, and the indices
// must match it.
func TestJSONReport_ChainIsInThePresentedOrder(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.example.com", false, intermediate, intermediateKey)

	// Deliberately backwards: root first, leaf last.
	sent := []*x509.Certificate{root, intermediate, leaf}
	report := NewJSONReport("", AnalyzeChain(sent), &VerifyResult{Level: TrustSelfAnchored})

	if len(report.Chain) != len(sent) {
		t.Fatalf("chain has %d entries, want %d", len(report.Chain), len(sent))
	}
	for i, entry := range report.Chain {
		if entry.Index != i {
			t.Errorf("entry %d has index %d", i, entry.Index)
		}
		if entry.CommonName != sent[i].Subject.CommonName {
			t.Errorf("entry %d is %q, want %q (the order as presented)",
				i, entry.CommonName, sent[i].Subject.CommonName)
		}
	}
}

// TestJSONReport_CertificateFields checks the fields a script actually gates on.
func TestJSONReport_CertificateFields(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	leaf, _ := issue(t, "leaf.example.com", false, root, rootKey)

	report := NewJSONReport("", AnalyzeChain([]*x509.Certificate{leaf, root}), nil)
	if len(report.Chain) != 2 {
		t.Fatalf("chain has %d entries, want 2", len(report.Chain))
	}

	gotLeaf, gotRoot := report.Chain[0], report.Chain[1]

	if gotLeaf.IsCA {
		t.Error("the leaf is reported as a CA")
	}
	if gotLeaf.SelfSigned {
		t.Error("the leaf is reported as self-signed")
	}
	if !gotRoot.IsCA || !gotRoot.SelfSigned {
		t.Errorf("the root is not reported as a self-signed CA: isCa=%v selfSigned=%v",
			gotRoot.IsCA, gotRoot.SelfSigned)
	}
	if gotLeaf.Expired {
		t.Error("a freshly issued certificate is reported as expired")
	}
	// issue() mints a NotAfter 24 hours out, so the count is 1 -- or 0 if the
	// clock crossed a second boundary between minting the certificate and
	// building the report. Both are correct; pinning either one makes the test
	// flaky. The arithmetic itself is pinned in
	// TestJSONReport_ExpiredCertificateCountsBackwards, which supplies its own
	// "now" and so has no race to lose.
	if gotLeaf.DaysUntilExpiry != 1 && gotLeaf.DaysUntilExpiry != 0 {
		t.Errorf("daysUntilExpiry = %d, want 1 (or 0) for a certificate expiring in 24h",
			gotLeaf.DaysUntilExpiry)
	}
	if len(gotLeaf.DNSNames) != 1 || gotLeaf.DNSNames[0] != "leaf.example.com" {
		t.Errorf("dnsNames = %v", gotLeaf.DNSNames)
	}
	if gotLeaf.KeyAlgorithm != "ECDSA" {
		t.Errorf("keyAlgorithm = %q", gotLeaf.KeyAlgorithm)
	}
	// The fingerprint is what a consumer pins on, so it must be the same hex
	// SHA-256 the rest of the tool prints.
	if gotLeaf.FingerprintSHA256 != FormatFingerprint(leaf) {
		t.Errorf("fingerprintSha256 = %q, want %q",
			gotLeaf.FingerprintSHA256, FormatFingerprint(leaf))
	}
	// Hex, matching openssl and the CAs, not the decimal big.Int default.
	if gotLeaf.SerialNumber != leaf.SerialNumber.Text(16) {
		t.Errorf("serialNumber = %q, want the hex form %q",
			gotLeaf.SerialNumber, leaf.SerialNumber.Text(16))
	}
}

// TestJSONReport_ExpiredCertificateCountsBackwards: an expiry monitor needs to
// know how far past due a certificate is, so the count must go negative rather
// than clamp at zero.
func TestJSONReport_ExpiredCertificateCountsBackwards(t *testing.T) {
	now := time.Now()

	for _, tc := range []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"expires in ten days", now.AddDate(0, 0, 10).Add(time.Hour), 10},
		{"expires in twelve hours", now.Add(12 * time.Hour), 0},
		{"expired two hours ago", now.Add(-2 * time.Hour), -1},
		{"expired five days ago", now.AddDate(0, 0, -5).Add(-time.Hour), -6},
	} {
		if got := daysUntil(tc.notAfter, now); got != tc.want {
			t.Errorf("%s: daysUntil = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestJSONReport_FarFutureExpiryDoesNotOverflow guards the 9999-12-31 "no
// expiry" convention: time.Duration is int64 nanoseconds and caps at ~292
// years, so the arithmetic has to stay in Unix seconds.
func TestJSONReport_FarFutureExpiryDoesNotOverflow(t *testing.T) {
	now := time.Now()
	noExpiry := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

	days := daysUntil(noExpiry, now)
	if days <= 0 {
		t.Errorf("daysUntil = %d for a 9999 expiry; the arithmetic overflowed", days)
	}
}

// TestJSONReport_NilInputsDoNotPanic: NewJSONReport is reachable from a command
// that failed earlier, so it must not assume both arguments are present.
func TestJSONReport_NilInputsDoNotPanic(t *testing.T) {
	report := NewJSONReport("", nil, nil)
	if report == nil {
		t.Fatal("NewJSONReport returned nil")
	}
	if !report.Presentation.OK {
		t.Error("a report with no analysis claims a presentation problem")
	}
	marshal(t, report)
}
