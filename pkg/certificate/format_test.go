package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestTrustLevelString(t *testing.T) {
	tests := []struct {
		level TrustLevel
		want  string
	}{
		{TrustAnchored, "trusted"},
		{TrustSelfAnchored, "self-anchored"},
		{TrustBroken, "broken"},
		{TrustLevel(99), "broken"}, // an unnamed level must not read as trusted
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("TrustLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestFormatVerifyResultNil(t *testing.T) {
	// validate prints this unconditionally, so a nil result must not panic.
	got := FormatVerifyResult(nil)
	if !strings.Contains(got, "could not be verified") {
		t.Errorf("FormatVerifyResult(nil) = %q", got)
	}
}

func TestFormatVerifyResultAnchored(t *testing.T) {
	withAnchor := FormatVerifyResult(&VerifyResult{Level: TrustAnchored, Anchor: "Test CA"})
	if !strings.Contains(withAnchor, "valid") || !strings.Contains(withAnchor, "Test CA") {
		t.Errorf("output = %q, want it to report validity and name the anchor", withAnchor)
	}

	// An anchored result with no anchor name still has to read as a success.
	bare := FormatVerifyResult(&VerifyResult{Level: TrustAnchored})
	if !strings.Contains(bare, "valid") {
		t.Errorf("output = %q, want it to report validity", bare)
	}
	if strings.Contains(bare, "Trust anchor:") {
		t.Errorf("output = %q, want no empty anchor line", bare)
	}
}

func TestFormatVerifyResultSelfAnchored(t *testing.T) {
	got := FormatVerifyResult(&VerifyResult{
		Level:  TrustSelfAnchored,
		Anchor: "Internal CA",
		Err:    errors.New("x509: certificate signed by unknown authority"),
	})

	// This is the case users misread most often, so the output has to say all
	// three things: what happened, where it stopped, and what to do about it.
	for _, want := range []string{"self-anchored", "Internal CA", "unknown authority", "--roots"} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q:\n%s", want, got)
		}
	}
}

func TestFormatVerifyResultBroken(t *testing.T) {
	got := FormatVerifyResult(&VerifyResult{Level: TrustBroken, Err: errors.New("no certificates")})
	if !strings.Contains(got, "broken") || !strings.Contains(got, "no certificates") {
		t.Errorf("output = %q, want it to report breakage and the reason", got)
	}

	// A broken result with no error attached must still render.
	if got := FormatVerifyResult(&VerifyResult{Level: TrustBroken}); !strings.Contains(got, "broken") {
		t.Errorf("output = %q", got)
	}
}

func TestChainProblemString(t *testing.T) {
	tests := []struct {
		problem ChainProblem
		want    string
	}{
		{ProblemMissingIssuer, "missing issuer"},
		{ProblemRedundantRoot, "redundant root"},
		{ProblemOutOfOrder, "out of order"},
		{ProblemDuplicate, "duplicate"},
		{ProblemUnrelated, "unrelated"},
		{ChainProblem(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.problem.String(); got != tt.want {
			t.Errorf("ChainProblem(%d).String() = %q, want %q", tt.problem, got, tt.want)
		}
	}
}

func TestFormatChainReportSaysNothingWhenTheChainIsFine(t *testing.T) {
	// Callers print the result unconditionally, so a clean chain must produce an
	// empty string rather than a "no problems" banner.
	if got := FormatChainReport(nil); got != "" {
		t.Errorf("FormatChainReport(nil) = %q, want empty", got)
	}
	if got := FormatChainReport(&ChainReport{}); got != "" {
		t.Errorf("FormatChainReport(clean) = %q, want empty", got)
	}
}

func TestFormatChainReportListsFindingsAndFetchURLs(t *testing.T) {
	got := FormatChainReport(&ChainReport{
		Findings: []ChainFinding{
			{
				Problem:   ProblemMissingIssuer,
				Subject:   "leaf.example.com",
				Detail:    "the issuing certificate was not sent",
				FetchURLs: []string{"http://aia.example.com/ca.crt"},
			},
			{
				Problem: ProblemOutOfOrder,
				Subject: "Test CA",
				Detail:  "the leaf was not sent first",
			},
		},
	})

	for _, want := range []string{
		"Chain as presented",
		"missing issuer", "leaf.example.com", "the issuing certificate was not sent",
		"http://aia.example.com/ca.crt",
		"out of order", "Test CA",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q:\n%s", want, got)
		}
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("output ends in a newline; the caller adds its own spacing")
	}
}

func TestDisplayNameFallsBackToSerial(t *testing.T) {
	named := &x509.Certificate{Subject: pkix.Name{CommonName: "has a name"}}
	if got := displayName(named); got != "has a name" {
		t.Errorf("displayName() = %q, want the common name", got)
	}

	anonymous := &x509.Certificate{SerialNumber: big.NewInt(4242)}
	if got := displayName(anonymous); got != "serial 4242" {
		t.Errorf("displayName() = %q, want the serial as a fallback", got)
	}
}

func TestNameOrUnknown(t *testing.T) {
	if got := nameOrUnknown(""); got != "(no common name)" {
		t.Errorf("nameOrUnknown(\"\") = %q", got)
	}
	if got := nameOrUnknown("Test CA"); got != "Test CA" {
		t.Errorf("nameOrUnknown() = %q, want it left alone", got)
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
		{0x0200, "unknown (0x0200)"},
	}
	for _, tt := range tests {
		r := &ConnectResult{Version: tt.version}
		if got := r.TLSVersionName(); got != tt.want {
			t.Errorf("TLSVersionName() for 0x%04x = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestSetLoggerRoutesAndResets(t *testing.T) {
	t.Cleanup(func() { SetLogger(nil) })

	core, logs := observer.New(zapcore.DebugLevel)
	SetLogger(zap.New(core))

	// LoadCertificates logs when it cannot open the file, so a failed load is
	// enough to prove diagnostics reach the logger that was installed.
	if _, err := LoadCertificates("this-path-does-not-exist.pem"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	installed := logs.Len()
	if installed == 0 {
		t.Fatal("nothing was recorded; SetLogger did not route the package diagnostics")
	}

	// Passing nil must leave a usable no-op logger rather than a nil pointer the
	// package would later dereference, and nothing more may reach the old one.
	SetLogger(nil)
	if _, err := LoadCertificates("this-path-does-not-exist.pem"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if logs.Len() != installed {
		t.Errorf("the replaced logger recorded %d more entries after SetLogger(nil)",
			logs.Len()-installed)
	}
}

func TestValidateChainLinksMarksAWellFormedChainGood(t *testing.T) {
	ca, caKey := issue(t, "Test CA", true, nil, nil)
	leaf, _ := issue(t, "leaf.example.com", false, ca, caKey)

	certs := []*Info{{Certificate: leaf}, {Certificate: ca}}
	ValidateChainLinks(certs)

	for i, c := range certs {
		if c.ValidationStatus != StatusGood {
			t.Errorf("certs[%d] status = %v (err %v), want StatusGood", i, c.ValidationStatus, c.ValidationError)
		}
	}
}

func TestValidateChainLinksFlagsAnOrphan(t *testing.T) {
	ca, caKey := issue(t, "Test CA", true, nil, nil)
	leaf, _ := issue(t, "leaf.example.com", false, ca, caKey)

	// The issuer is absent from the bundle, which is the single most common
	// misconfiguration: a server that forgot its intermediate.
	certs := []*Info{{Certificate: leaf}}
	ValidateChainLinks(certs)

	if certs[0].ValidationStatus != StatusMismatchedIssuer {
		t.Errorf("status = %v, want StatusMismatchedIssuer", certs[0].ValidationStatus)
	}
	if certs[0].ValidationError == nil || !strings.Contains(certs[0].ValidationError.Error(), "Test CA") {
		t.Errorf("error = %v, want it to name the missing issuer", certs[0].ValidationError)
	}
}

func TestValidateChainLinksFlagsExpiry(t *testing.T) {
	ca, caKey := issue(t, "Test CA", true, nil, nil)
	leaf, _ := issue(t, "leaf.example.com", false, ca, caKey)

	// Rewriting NotAfter in place is enough: the function reads the parsed
	// fields, and expiry short-circuits before any signature check.
	leaf.NotAfter = leaf.NotBefore

	certs := []*Info{{Certificate: leaf}, {Certificate: ca}}
	ValidateChainLinks(certs)

	if certs[0].ValidationStatus != StatusExpired {
		t.Errorf("status = %v, want StatusExpired", certs[0].ValidationStatus)
	}
}

func TestValidateChainLinksResetsPreviousStatus(t *testing.T) {
	ca, caKey := issue(t, "Test CA", true, nil, nil)
	leaf, _ := issue(t, "leaf.example.com", false, ca, caKey)

	// A stale failure from an earlier run must not survive re-validation, or the
	// TUI keeps showing an error the user already fixed.
	certs := []*Info{
		{Certificate: leaf, ValidationStatus: StatusInvalidSignature, ValidationError: errors.New("stale")},
		{Certificate: ca},
	}
	ValidateChainLinks(certs)

	if certs[0].ValidationStatus != StatusGood || certs[0].ValidationError != nil {
		t.Errorf("status = %v, err = %v; want the previous failure cleared",
			certs[0].ValidationStatus, certs[0].ValidationError)
	}
}

func TestValidateChainLinksAcceptsASelfSignedRoot(t *testing.T) {
	ca, _ := issue(t, "Test CA", true, nil, nil)

	certs := []*Info{{Certificate: ca}}
	ValidateChainLinks(certs)

	if certs[0].ValidationStatus != StatusGood {
		t.Errorf("status = %v (err %v), want a self-signed root to pass",
			certs[0].ValidationStatus, certs[0].ValidationError)
	}
}
