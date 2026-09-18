package model

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/kanywst/y509/pkg/certificate"
)

// stapleModel puts a model on the leaf's Misc tab, which is where the handshake
// section lives.
func stapleModel(t *testing.T, conn *certificate.ConnectResult) Model {
	t.Helper()

	certs := createTestCertificates(2)
	// The handshake belongs to the certificate the server led with, so the
	// connection has to name it.
	conn.Certificates = certs

	m := NewModel(certs, loadTestConfig(t))
	m.SetConnection(conn)
	out := pump(t, *m, tea.WindowSizeMsg{Width: 140, Height: 44})
	out = pump(t, out, keyPress('x')) // leave the splash
	out = pump(t, out, keyPress('l')) // focus the details

	// Misc is the fifth tab: Subject, Issuer, Validity, SANs, Misc.
	for i := 0; i < 4; i++ {
		out = pump(t, out, tea.KeyPressMsg{Code: tea.KeyTab})
	}
	if out.tabs[out.activeTab] != "Misc" {
		t.Fatalf("landed on the %q tab, want Misc", out.tabs[out.activeTab])
	}
	return out
}

func TestStapleRendersAGoodResponse(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		OCSPStapled: true,
		Staple: &certificate.Staple{
			Status:       "good",
			SerialNumber: "2a",
			ThisUpdate:   time.Now().Add(-time.Hour),
			NextUpdate:   time.Now().Add(12 * time.Hour),
			Verified:     true,
			Responder:    "CN=Test Responder",
		},
	})

	got := m.View().Content
	for _, want := range []string{"Handshake", "TLS 1.3", "OCSP Staple", "good"} {
		if !strings.Contains(got, want) {
			t.Errorf("the Misc tab does not show %q", want)
		}
	}
	if strings.Contains(got, "signature not checked") {
		t.Error("a verified response is labelled as unchecked")
	}
	if strings.Contains(got, "stale") {
		t.Error("a response with NextUpdate in the future is labelled stale")
	}
}

// TestStapleSaysNothingWhenNoneWasStapled is the rule the roadmap sets: the
// absence is the norm, not news, and not a finding.
func TestStapleSaysNothingWhenNoneWasStapled(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{Version: tls.VersionTLS13})

	got := m.View().Content
	if !strings.Contains(got, "Handshake") {
		t.Fatal("the handshake section is missing, so the test cannot show the staple row absent from it")
	}
	if strings.Contains(got, "OCSP Staple") {
		t.Error("a server that stapled nothing still produced an OCSP Staple row")
	}
}

// TestStapleReportsAnUnreadableResponse covers bytes that would not parse: a
// fact about the server, so it is said rather than dropped.
func TestStapleReportsAnUnreadableResponse(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{
		Version:     tls.VersionTLS13,
		OCSPStapled: true,
		StapleErr:   errors.New("asn1: structure error"),
	})

	got := m.View().Content
	if !strings.Contains(got, "unreadable") {
		t.Error("an unreadable staple is not reported on the Misc tab")
	}
	if !strings.Contains(got, "asn1") {
		t.Error("the parse error itself is not shown")
	}
}

// TestStapleLabelsAnUnverifiedResponse keeps two different claims apart: what
// the responder said, and whether we could check that it said it.
func TestStapleLabelsAnUnverifiedResponse(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{
		Version:     tls.VersionTLS13,
		OCSPStapled: true,
		Staple: &certificate.Staple{
			Status:     "good",
			ThisUpdate: time.Now().Add(-time.Hour),
			NextUpdate: time.Now().Add(time.Hour),
			Verified:   false,
		},
	})

	if !strings.Contains(m.View().Content, "signature not checked") {
		t.Error("a response read without its issuer is not labelled as unverified")
	}
}

func TestStapleLabelsAStaleResponse(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{
		Version:     tls.VersionTLS13,
		OCSPStapled: true,
		Staple: &certificate.Staple{
			Status:     "good",
			ThisUpdate: time.Now().Add(-48 * time.Hour),
			NextUpdate: time.Now().Add(-24 * time.Hour),
			Verified:   true,
		},
	})

	if !strings.Contains(m.View().Content, "stale") {
		t.Error("a response whose NextUpdate has passed is not labelled stale")
	}
}

// TestStapleWithoutNextUpdateSaysDoNotCache covers the distinction a blank
// would lose: no NextUpdate is an instruction, not an omission.
func TestStapleWithoutNextUpdateSaysDoNotCache(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{
		Version:     tls.VersionTLS13,
		OCSPStapled: true,
		Staple: &certificate.Staple{
			Status:     "good",
			ThisUpdate: time.Now().Add(-time.Hour),
			Verified:   true,
		},
	})

	got := m.View().Content
	if !strings.Contains(got, "do not cache") {
		t.Error("a response with no NextUpdate does not say why")
	}
	if strings.Contains(got, "stale") {
		t.Error("a response with no NextUpdate is labelled stale")
	}
}

// TestStapleShowsRevocation covers the strongest thing a staple can say.
func TestStapleShowsRevocation(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{
		Version:     tls.VersionTLS13,
		OCSPStapled: true,
		Staple: &certificate.Staple{
			Status:           "revoked",
			ThisUpdate:       time.Now().Add(-time.Hour),
			NextUpdate:       time.Now().Add(time.Hour),
			RevokedAt:        time.Now().Add(-48 * time.Hour),
			RevocationReason: "key compromise",
			Verified:         true,
		},
	})

	got := m.View().Content
	if !strings.Contains(got, "revoked") {
		t.Error("a revoked staple does not say so")
	}
	if !strings.Contains(got, "key compromise") {
		t.Error("the revocation reason is not shown")
	}
}

// TestRedialReplacesTheHandshakeFacts covers the pairing: the TLS version and
// the staple belong to the connection the chain arrived over, so keeping the
// old ones after a redial would report a handshake that is no longer on screen.
func TestRedialReplacesTheHandshakeFacts(t *testing.T) {
	fresh := createTestCertificates(1)
	after := &certificate.ConnectResult{
		Certificates: fresh,
		Address:      "example.com:443",
		Version:      tls.VersionTLS13,
		OCSPStapled:  true,
		Staple: &certificate.Staple{
			Status:     "revoked",
			ThisUpdate: time.Now().Add(-time.Hour),
			NextUpdate: time.Now().Add(time.Hour),
			RevokedAt:  time.Now().Add(-2 * time.Hour),
			Verified:   true,
		},
	}

	before := createTestCertificates(1)
	after.Certificates = fresh

	m := NewModel(before, loadTestConfig(t))
	m.SetConnection(&certificate.ConnectResult{
		Certificates: before,
		Address:      "example.com:443",
		Version:      tls.VersionTLS12,
		OCSPStapled:  false,
	})
	m.SetRedial(func(context.Context) (*certificate.ConnectResult, error) {
		return after, nil
	})
	out := pump(t, *m, tea.WindowSizeMsg{Width: 140, Height: 44})
	out = pump(t, out, keyPress('x'))

	out = pump(t, out, keyPress('r'))

	out = pump(t, out, keyPress('l'))
	for i := 0; i < 4; i++ {
		out = pump(t, out, tea.KeyPressMsg{Code: tea.KeyTab})
	}

	got := out.View().Content
	if strings.Contains(got, "TLS 1.2") {
		t.Error("the Misc tab still shows the TLS version from the connection the redial replaced")
	}
	if !strings.Contains(got, "TLS 1.3") {
		t.Error("the Misc tab does not show the redialled connection's TLS version")
	}
	if !strings.Contains(got, "revoked") {
		t.Error("the staple from the redialled connection is not shown")
	}
}

// TestHandshakeFollowsTheCertificateNotTheCursor covers a filter putting a
// different certificate at position zero. Keying the section off the list index
// rendered the connection's TLS version and staple under whatever survived the
// predicate, as though they were that certificate's own.
func TestHandshakeFollowsTheCertificateNotTheCursor(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{
		Version:     tls.VersionTLS13,
		OCSPStapled: true,
		Staple: &certificate.Staple{
			Status:     "good",
			ThisUpdate: time.Now().Add(-time.Hour),
			NextUpdate: time.Now().Add(time.Hour),
			Verified:   true,
		},
	})
	if !strings.Contains(m.View().Content, "Handshake") {
		t.Fatal("the handshake section is missing before the filter, so the test proves nothing")
	}

	// Select the second certificate. The handshake belongs to the first.
	m.list.Select(1)
	m = m.refreshViewportContent()

	if strings.Contains(m.View().Content, "Handshake") {
		t.Error("the handshake section is shown under a certificate the server did not lead with")
	}

	// And with only that certificate left by a filter, it is still at index 0
	// and must still not claim the handshake.
	m.certificates = m.allCertificates[1:]
	m.list.SetItems(toListItems(m.certificates, nil))
	m.list.Select(0)
	m.filterActive = true
	m = m.refreshViewportContent()

	if strings.Contains(m.View().Content, "Handshake") {
		t.Error("a filter that leaves a non-leaf at position zero gives it the handshake section")
	}
}

// TestStapleDistinguishesAFailedSignatureFromAMissingIssuer covers two very
// different claims that a single Verified bool collapsed into one. An operator
// told "the issuer is not in the chain" when the real answer is "the response
// does not verify against the issuer the server sent" fixes the wrong thing.
func TestStapleDistinguishesAFailedSignatureFromAMissingIssuer(t *testing.T) {
	m := stapleModel(t, &certificate.ConnectResult{
		Version:     tls.VersionTLS13,
		OCSPStapled: true,
		Staple: &certificate.Staple{
			Status:     "good",
			ThisUpdate: time.Now().Add(-time.Hour),
			NextUpdate: time.Now().Add(time.Hour),
			Verified:   false,
			VerifyErr:  errors.New("ocsp: signature verification failed"),
		},
	})

	got := m.View().Content
	if strings.Contains(got, "issuer not in the chain") {
		t.Error("a response that failed against the presented issuer is reported as a missing issuer")
	}
	if !strings.Contains(got, "DID NOT VERIFY") {
		t.Error("a response that failed against the presented issuer is not called out")
	}
	if !strings.Contains(got, "signature verification failed") {
		t.Error("the verification error itself is not shown")
	}
}

// TestHandshakeSectionIsAbsentForAFile covers the other input: a file has no
// handshake, so the section must not appear at all.
func TestHandshakeSectionIsAbsentForAFile(t *testing.T) {
	m := *NewModel(createTestCertificates(2), loadTestConfig(t))
	m = pump(t, m, tea.WindowSizeMsg{Width: 140, Height: 44})
	m = pump(t, m, keyPress('x'))
	m = pump(t, m, keyPress('l'))
	for i := 0; i < 4; i++ {
		m = pump(t, m, tea.KeyPressMsg{Code: tea.KeyTab})
	}

	if strings.Contains(m.View().Content, "Handshake") {
		t.Error("a chain read from a file shows a handshake section")
	}
}
