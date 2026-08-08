package model

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// sized returns a model with a viewport, since every renderer divides by the
// width and a zero-width model exercises nothing.
func sized(t *testing.T, certCount, width, height int) Model {
	t.Helper()
	m := *NewModel(createTestCertificates(certCount), loadTestConfig(t))
	m.SetDimensions(width, height)
	m.SetReady(true)
	return m
}

func TestSetDimensionsIsReadableThroughTheGetters(t *testing.T) {
	m := sized(t, 1, 120, 40)

	if m.GetWidth() != 120 || m.GetHeight() != 40 {
		t.Errorf("GetWidth()/GetHeight() = %d/%d, want 120/40", m.GetWidth(), m.GetHeight())
	}
}

func TestCertItemFilterValue(t *testing.T) {
	certs := createTestCertificates(1)

	item := certItem{info: certs[0]}
	if got := item.FilterValue(); got == "" {
		t.Error("FilterValue() is empty; the list would have nothing to filter on")
	}

	// Filtering has to stay usable for a certificate with no common name, which
	// is legal and does happen.
	certs[0].Certificate.Subject.CommonName = ""
	blank := certItem{info: certs[0]}
	if got := blank.FilterValue(); got != "(no CN)" {
		t.Errorf("FilterValue() = %q, want the placeholder for a blank CN", got)
	}
}

func TestCertDelegateUpdateIsANoOp(t *testing.T) {
	// The delegate has no state of its own; the model owns it all. If this ever
	// returns a command, something has moved.
	d := certDelegate{}
	if cmd := d.Update(nil, nil); cmd != nil {
		t.Error("certDelegate.Update returned a command")
	}
}

func TestKeyMapHelpIsPopulated(t *testing.T) {
	k := defaultKeyMap()

	short := k.ShortHelp()
	if len(short) == 0 {
		t.Error("ShortHelp() is empty; the status bar hints would be blank")
	}
	full := k.FullHelp()
	if len(full) == 0 {
		t.Fatal("FullHelp() is empty; the help overlay would be blank")
	}
	// The overlay groups bindings into columns, so every group must carry some.
	for i, group := range full {
		if len(group) == 0 {
			t.Errorf("FullHelp() group %d is empty", i)
		}
	}
	// The overlay exists to show more than the status bar hint does.
	var fullCount int
	for _, group := range full {
		fullCount += len(group)
	}
	if fullCount <= len(short) {
		t.Errorf("FullHelp() lists %d bindings against ShortHelp()'s %d; the overlay should show more",
			fullCount, len(short))
	}
}

func TestRenderHelpViewMentionsTheProgram(t *testing.T) {
	m := sized(t, 2, 100, 30)

	got := m.renderHelpView()
	if !strings.Contains(got, "y509") {
		t.Errorf("help view does not name the program:\n%s", got)
	}
	if strings.TrimSpace(got) == "" {
		t.Error("help view is blank")
	}
}

func TestRenderTwoPanesFillsTheWidth(t *testing.T) {
	m := sized(t, 3, 120, 40)

	got := m.renderTwoPanes(20)
	if strings.TrimSpace(got) == "" {
		t.Fatal("renderTwoPanes produced nothing")
	}
	// The panes are joined horizontally, so each line has to carry both.
	// The panes are joined horizontally, so the result must be at least as wide
	// as the left pane alone would be.
	if w := lipgloss.Width(got); w < m.GetWidth()/2 {
		t.Errorf("rendered width %d is well under the model's %d; the panes did not join",
			w, m.GetWidth())
	}
}

func TestRenderSplashScreenAdaptsToTheTerminalSize(t *testing.T) {
	tests := []struct {
		name          string
		width, height int
	}{
		{"comfortable", 120, 40},
		{"narrow", CompactArtWidthThreshold - 1, 40},
		{"short", 120, CompactArtHeightThreshold - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := sized(t, 1, tt.width, tt.height)

			got := m.renderSplashScreen()
			if strings.TrimSpace(got) == "" {
				t.Fatalf("splash screen is blank at %dx%d", tt.width, tt.height)
			}
			// A splash that overruns the terminal width wraps and turns into
			// noise, which is the whole reason for the compact variant.
			// Measure with lipgloss so the colour escapes do not count as width.
			for _, line := range strings.Split(got, "\n") {
				if w := lipgloss.Width(line); w > tt.width {
					t.Errorf("line is %d wide at width %d: %q", w, tt.width, line)
					break
				}
			}
		})
	}
}

func TestHandleValidateCommandOpensAnAlert(t *testing.T) {
	m := sized(t, 2, 100, 30)

	got := m.handleValidateCommand()

	// The test chain is self-signed, so the trust store will reject it. Either
	// way the user must end up looking at a popup rather than at nothing.
	if got.viewMode != ViewPopup {
		t.Errorf("viewMode = %v, want ViewPopup", got.viewMode)
	}
	if got.popupMessage == "" {
		t.Error("popupMessage is empty; the popup would render blank")
	}
}

func TestHandleValidateCommandWithNoCertificatesIsANoOp(t *testing.T) {
	m := *NewModel(nil, loadTestConfig(t))
	m.SetDimensions(100, 30)

	got := m.handleValidateCommand()

	if got.viewMode == ViewPopup {
		t.Error("opened a popup with nothing loaded")
	}
}

func TestHandleYankCommandCopiesPEMAndConfirms(t *testing.T) {
	m := sized(t, 1, 100, 30)

	got, cmd := m.handleYankCommand()

	if cmd == nil {
		t.Error("no command returned; nothing would reach the clipboard")
	}
	if got.viewMode != ViewPopup || got.popupType != PopupAlert {
		t.Errorf("viewMode/popupType = %v/%v, want ViewPopup/PopupAlert", got.viewMode, got.popupType)
	}
	// The confirmation names what was copied and how much, which is how the user
	// tells a successful yank from a silent one.
	if !strings.Contains(got.popupMessage, "Copied PEM") {
		t.Errorf("popupMessage = %q, want it to confirm the copy", got.popupMessage)
	}
	if !strings.Contains(got.popupMessage, "Bytes:") {
		t.Errorf("popupMessage = %q, want it to report the size", got.popupMessage)
	}
}

func TestHandleYankCommandWithNoCertificatesIsANoOp(t *testing.T) {
	m := *NewModel(nil, loadTestConfig(t))

	got, cmd := m.handleYankCommand()

	if cmd != nil {
		t.Error("returned a clipboard command with nothing selected")
	}
	if got.viewMode == ViewPopup {
		t.Error("opened a popup with nothing loaded")
	}
}
