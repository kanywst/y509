package model

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/kanywst/y509/pkg/certificate"
)

// redialModel builds a model already wired to a server, with dial standing in
// for the handshake.
func redialModel(t *testing.T, certs []*certificate.Info, dial Redialer) Model {
	t.Helper()
	m := NewModel(certs, loadTestConfig(t))
	m.SetRedial("example.com:443", dial)
	out := pump(t, *m, tea.WindowSizeMsg{Width: 120, Height: 40})
	// Leave the splash, so r reaches updateNormalMode.
	return pump(t, out, keyPress('x'))
}

// TestRedialDisabledWithoutAServer covers the file case: r must do nothing and
// must not be advertised, because there is no handshake to repeat.
func TestRedialDisabledWithoutAServer(t *testing.T) {
	m := *NewModel(createTestCertificates(2), loadTestConfig(t))
	m = pump(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = pump(t, m, keyPress('x'))

	if m.keys.Redial.Enabled() {
		t.Error("the redial binding is enabled for a chain that did not come from a server")
	}

	before := m.View().Content
	m = pump(t, m, keyPress('r'))
	if m.redialing {
		t.Error("r started a redial with no server to dial")
	}
	if m.View().Content != before {
		t.Error("r changed the view for a chain that did not come from a server")
	}
}

// TestRedialReplacesTheChain is the point of the feature: the certificates on
// screen become the ones the server just served.
func TestRedialReplacesTheChain(t *testing.T) {
	fresh := createTestCertificates(3)
	m := redialModel(t, createTestCertificates(1), func(context.Context) (*certificate.ConnectResult, error) {
		return &certificate.ConnectResult{Certificates: fresh, Address: "example.com:443"}, nil
	})

	if got := len(m.allCertificates); got != 1 {
		t.Fatalf("expected the model to start with the first chain, got %d certificates", got)
	}

	m = pump(t, m, keyPress('r'))

	if got := len(m.allCertificates); got != len(fresh) {
		t.Errorf("expected %d certificates after the redial, got %d", len(fresh), got)
	}
	if m.redialing {
		t.Error("the model is still marked as redialing after the result arrived")
	}
	if m.chainReport == nil {
		t.Error("the chain report was not rebuilt from the new chain")
	}
	if m.list.Index() != 0 {
		t.Errorf("expected the cursor on the leaf after a redial, got %d", m.list.Index())
	}
}

// TestRedialFailureKeepsTheChain covers the evidence rule: a refused connection
// must not blank what the server did serve last time.
func TestRedialFailureKeepsTheChain(t *testing.T) {
	m := redialModel(t, createTestCertificates(2), func(context.Context) (*certificate.ConnectResult, error) {
		return nil, errors.New("connection refused")
	})

	m = pump(t, m, keyPress('r'))

	if got := len(m.allCertificates); got != 2 {
		t.Errorf("a failed redial changed the chain: expected 2 certificates, got %d", got)
	}
	if m.popupType != PopupAlert {
		t.Errorf("expected an alert after a failed redial, got popup type %v", m.popupType)
	}
	if !strings.Contains(m.popupMessage, "connection refused") {
		t.Errorf("the alert does not carry the dial error: %q", m.popupMessage)
	}
	if m.redialing {
		t.Error("the model is still marked as redialing after a failure")
	}
}

// TestRedialEmptyResultKeepsTheChain covers the same rule for a handshake that
// succeeds and presents nothing.
func TestRedialEmptyResultKeepsTheChain(t *testing.T) {
	m := redialModel(t, createTestCertificates(2), func(context.Context) (*certificate.ConnectResult, error) {
		return &certificate.ConnectResult{Address: "example.com:443"}, nil
	})

	m = pump(t, m, keyPress('r'))

	if got := len(m.allCertificates); got != 2 {
		t.Errorf("an empty redial changed the chain: expected 2 certificates, got %d", got)
	}
	if m.popupType != PopupAlert {
		t.Errorf("expected an alert for an empty redial, got popup type %v", m.popupType)
	}
}

// TestRedialDoesNotStack covers a leaned-on r key: a second press while a
// handshake is in flight must not open another connection.
func TestRedialDoesNotStack(t *testing.T) {
	var dials atomic.Int32
	fresh := createTestCertificates(1)
	m := redialModel(t, createTestCertificates(1), func(context.Context) (*certificate.ConnectResult, error) {
		dials.Add(1)
		return &certificate.ConnectResult{Certificates: fresh}, nil
	})

	// Press without pumping, so the result is still outstanding, then press again.
	m.redialing = true
	before := dials.Load()
	next, cmd := m.Update(keyPress('r'))
	m = next.(Model)
	if cmd != nil {
		t.Error("a second r while a handshake is in flight produced another dial command")
	}
	if dials.Load() != before {
		t.Error("a second r while a handshake is in flight dialled again")
	}
}

// TestRedialClearsTheFilter covers why the filter is dropped: it was an answer
// about the previous chain.
func TestRedialClearsTheFilter(t *testing.T) {
	// Built up front: generating keys inside the closure outruns the test
	// pump's budget for a command, and the result would never be delivered.
	fresh := createTestCertificates(3)
	m := redialModel(t, createTestCertificates(2), func(context.Context) (*certificate.ConnectResult, error) {
		return &certificate.ConnectResult{Certificates: fresh}, nil
	})

	m = pumpKeys(t, m, 'f')
	m = pump(t, m, keyPress('v'))
	m = pumpKeys(t, m, 'a', 'l', 'i', 'd')
	m = pump(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if !m.filterActive {
		t.Fatalf("the filter did not take, so the test cannot show it being cleared")
	}

	m = pump(t, m, keyPress('r'))

	if m.filterActive {
		t.Error("the filter survived a redial, so the list mixes two chains' questions")
	}
	if got := len(m.certificates); got != 3 {
		t.Errorf("expected the full new chain on screen, got %d certificates", got)
	}
}

// TestRedialAppearsInTheHelpOnlyWhenBound covers the ? overlay, which is
// generated from the same key map Update dispatches on. A key listed there and
// dead on press would be worse than no key at all.
func TestRedialAppearsInTheHelpOnlyWhenBound(t *testing.T) {
	fresh := createTestCertificates(1)
	live := redialModel(t, createTestCertificates(1), func(context.Context) (*certificate.ConnectResult, error) {
		return &certificate.ConnectResult{Certificates: fresh}, nil
	})
	if got := pump(t, live, keyPress('?')).View().Content; !strings.Contains(got, "redial") {
		t.Error("the help overlay does not offer redial for a chain fetched from a server")
	}

	file := *NewModel(createTestCertificates(1), loadTestConfig(t))
	file = pump(t, file, tea.WindowSizeMsg{Width: 120, Height: 40})
	file = pump(t, file, keyPress('x'))
	if got := pump(t, file, keyPress('?')).View().Content; strings.Contains(got, "redial") {
		t.Error("the help overlay offers redial for a chain read from a file, where the key does nothing")
	}
}

// TestRedialNamesTheServer covers the header: a live chain and a file look
// identical once parsed, so the address has to be on screen.
func TestRedialNamesTheServer(t *testing.T) {
	fresh := createTestCertificates(1)
	m := redialModel(t, createTestCertificates(1), func(context.Context) (*certificate.ConnectResult, error) {
		return &certificate.ConnectResult{Certificates: fresh}, nil
	})

	if !strings.Contains(m.View().Content, "example.com:443") {
		t.Error("the header does not name the server the chain came from")
	}
}
