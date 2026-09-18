package model

import (
	"context"
	"fmt"

	tea "charm.land/bubbletea/v2"
	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"go.uber.org/zap"
)

// Redialer re-runs the handshake the chain on screen arrived over.
//
// It is a function rather than an address and a set of options because the
// model has no business owning connect flags: only the command that dialled
// the first time knows what it passed, and it already bounds the attempt with
// its own timeout.
type Redialer func(ctx context.Context) (*certificate.ConnectResult, error)

// redialResultMsg carries a finished handshake back into Update.
type redialResultMsg struct {
	result *certificate.ConnectResult
	err    error
}

// SetRedial records how to dial the server again, and the address to name
// while doing it. Without it the r binding stays disabled, because there is
// nothing to redial: a file does not change under you in a way a handshake
// would reveal, and re-reading it is what a shell is for.
//
// It is a setter rather than a constructor argument for the same reason as
// SetNotice: it is about where the input came from, which only the command
// that fetched it knows.
func (m *Model) SetRedial(address string, dial Redialer) {
	if dial == nil {
		return
	}
	m.address = address
	m.dial = dial
	m.keys.Redial.SetEnabled(true)
}

// redialCmd runs the handshake off the update loop. The Redialer bounds itself,
// so there is no timeout to apply here.
func (m Model) redialCmd() tea.Cmd {
	dial := m.dial
	return func() tea.Msg {
		result, err := dial(context.Background())
		return redialResultMsg{result: result, err: err}
	}
}

// startRedial kicks off a handshake, unless one is already in flight. Holding
// the second press is what keeps a leaned-on r key from opening a connection
// per repeat.
func (m Model) startRedial() (Model, tea.Cmd) {
	if m.dial == nil || m.redialing {
		return m, nil
	}
	logger.Log.Debug("redialing", zap.String("address", m.address))
	m.redialing = true
	return m, m.redialCmd()
}

// applyRedial installs a fresh handshake, or explains why the old one is still
// on screen. Update decides when it runs, which is only ever with the list in
// front of the user.
//
// A failed redial never clears the view. The chain you were looking at is
// still the last thing the server actually served, and replacing it with
// nothing would destroy the evidence on the strength of one refused
// connection.
func (m Model) applyRedial(msg redialResultMsg) Model {
	switch {
	case msg.err != nil:
		return m.alert(fmt.Sprintf("❌  Redial failed\n\n%v\n\nShowing the previous chain.", msg.err))
	case msg.result == nil || len(msg.result.Certificates) == 0:
		return m.alert("❌  Redial returned no certificates\n\nShowing the previous chain.")
	}

	m.allCertificates, m.chainReport = buildChain(msg.result.Certificates)
	m.certificates = m.allCertificates

	// Drop the filter and the search rather than re-applying them. They were
	// answers about the old chain, and a redial exists to show what the server
	// is serving now -- silently carrying a predicate across would leave the
	// list showing a question the user last asked about different input.
	m = m.resetAllFields()
	m.list.SetItems(toListItems(m.allCertificates, m.unparsed))
	m.list.Select(0)
	m = m.refreshViewportContent()

	logger.Log.Debug("redial complete",
		zap.String("address", msg.result.Address),
		zap.Int("certificates", len(msg.result.Certificates)))

	return m
}
