package model

import (
	"strings"
	"testing"
)

// TestHeaderShowsTheInputNotice covers the TUI half of a partially readable
// bundle. The list can only show what parsed, so without this the certificates
// that were skipped leave no trace anywhere on screen.
func TestHeaderShowsTheInputNotice(t *testing.T) {
	m := NewModel(createTestCertificates(2), loadTestConfig(t))
	m.SetDimensions(120, 40)
	m.SetReady(true)

	if got := m.renderHeader(); strings.Contains(got, "unreadable") {
		t.Fatalf("header carries a notice that was never set:\n%s", got)
	}

	m.SetNotice("1 unreadable certificate in the input")
	got := m.renderHeader()

	if !strings.Contains(got, "1 unreadable certificate in the input") {
		t.Errorf("header does not show the notice:\n%s", got)
	}
	// The certificate count stays: the notice is an addition, not a takeover.
	if !strings.Contains(got, "2 certs") {
		t.Errorf("header lost the certificate count:\n%s", got)
	}
}
