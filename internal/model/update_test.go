package model

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/kanywst/y509/pkg/certificate"
)

// Helper to create a dummy certificate
func createDummyCert(index int) *certificate.Info {
	return &certificate.Info{
		Certificate: &x509.Certificate{
			SerialNumber: big.NewInt(int64(index)),
			Subject:      pkix.Name{CommonName: "Test Cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		},
		Index: index,
		Label: "Test Cert",
	}
}

func keyPress(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)})
}

func TestNavigationKeys(t *testing.T) {
	certs := []*certificate.Info{
		createDummyCert(1),
		createDummyCert(2),
		createDummyCert(3),
	}
	cfg := loadTestConfig(t)
	modelPtr := NewModel(certs, cfg)
	m := *modelPtr
	m.SetDimensions(100, 20)
	m.list.SetSize(40, 10)
	m.viewMode = ViewNormal
	m.focus = FocusLeft
	m.ready = true

	// Test 'j' (down) in list
	t.Run("NormalMode_List_Down_j", func(t *testing.T) {
		initialCursor := m.list.Index()
		newModel, _ := m.Update(keyPress('j'))
		m = newModel.(Model)
		if m.list.Index() != initialCursor+1 {
			t.Errorf("Expected cursor to increment (j), got %d", m.list.Index())
		}
	})

	// Test 'k' (up) in list
	t.Run("NormalMode_List_Up_k", func(t *testing.T) {
		initialCursor := m.list.Index()
		newModel, _ := m.Update(keyPress('k'))
		m = newModel.(Model)
		if m.list.Index() != initialCursor-1 {
			t.Errorf("Expected cursor to decrement (k), got %d", m.list.Index())
		}
	})

	// Switch focus to right pane and seed the viewport with scrollable
	// content so that ScrollDown actually moves the offset.
	m.focus = FocusRight
	m.viewport.SetWidth(20)
	m.viewport.SetHeight(2)
	m.viewport.SetContent("line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8")
	m.viewport.SetYOffset(0)

	// Test 'j' (scroll down) in detail pane (Normal Mode)
	t.Run("NormalMode_Detail_Down_j", func(t *testing.T) {
		initialScroll := m.viewport.YOffset()
		newModel, _ := m.Update(keyPress('j'))
		m = newModel.(Model)
		if m.viewport.YOffset() != initialScroll+1 {
			t.Errorf("Expected viewport YOffset to increment, got %d", m.viewport.YOffset())
		}
	})

	// Test 'k' (scroll up) in detail pane (Normal Mode)
	t.Run("NormalMode_Detail_Up_k", func(t *testing.T) {
		initialScroll := m.viewport.YOffset()
		newModel, _ := m.Update(keyPress('k'))
		m = newModel.(Model)
		if m.viewport.YOffset() != initialScroll-1 {
			t.Errorf("Expected viewport YOffset to decrement, got %d", m.viewport.YOffset())
		}
	})
}

// pump delivers a message to the model and then feeds the resulting commands
// back in, the way the Bubble Tea runtime does: batches are expanded and the
// messages they produce are delivered in turn. Components like huh advance
// their own state through messages they emit as commands, so a test that only
// calls Update once never exercises the real key path.
func pump(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()

	queue := []tea.Msg{msg}
	for delivered := 0; len(queue) > 0 && delivered < 64; delivered++ {
		next := queue[0]
		queue = queue[1:]

		updated, cmd := m.Update(next)
		m = updated.(Model)

		queue = append(queue, flatten(settle(cmd))...)
	}
	return m
}

// flatten reduces a produced message to the concrete messages that should be
// delivered to Update, expanding batches to any depth. Update does not itself
// understand a tea.BatchMsg, so a nested batch left un-expanded would simply be
// dropped.
func flatten(msg tea.Msg) []tea.Msg {
	switch m := msg.(type) {
	case nil:
		return nil
	case tea.BatchMsg:
		var out []tea.Msg
		for _, cmd := range m {
			out = append(out, flatten(settle(cmd))...)
		}
		return out
	default:
		return []tea.Msg{m}
	}
}

// settle runs a command and returns the message it produced, giving up on any
// command that does not produce one promptly. Cursor blink ticks sleep on a
// wall-clock timer before re-arming themselves, so waiting on them would make
// every keystroke in a test take half a second and never settle.
func settle(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}

	produced := make(chan tea.Msg, 1)
	go func() { produced <- cmd() }()

	select {
	case msg := <-produced:
		return msg
	case <-time.After(50 * time.Millisecond):
		return nil
	}
}

// TestExportFormCompletesThroughUpdate drives the export popup the way a user
// does: press e, type a filename, confirm the filename field, then confirm the
// format field. The form only reaches StateCompleted if Update hands huh's own
// messages back to it.
func TestExportFormCompletesThroughUpdate(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel(createTestCertificates(1), cfg)
	m = pump(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m.viewMode = ViewNormal

	// An absolute path in a temp dir, entered in one paste rather than typed
	// character by character. Each keystroke otherwise pays the cursor-blink
	// settle, which a long path makes slow; pasting also keeps the test off the
	// process working directory, so it stays safe to run in parallel.
	target := filepath.Join(t.TempDir(), "out")

	m = pump(t, m, keyPress('e'))
	if !m.exportFormOpen() {
		t.Fatal("e did not open the export form")
	}

	m = pump(t, m, tea.PasteMsg{Content: target})

	// First enter confirms the filename, second confirms the format select.
	m = pump(t, m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	m = pump(t, m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))

	if m.exportForm != nil {
		t.Fatalf("export form never completed (huh state = %v)", m.exportForm.State)
	}
	if m.popupType != PopupAlert {
		t.Errorf("expected an alert popup after export, got popupType=%v", m.popupType)
	}
	if !strings.Contains(m.popupMessage, "successfully") {
		t.Errorf("expected a success message, got %q", m.popupMessage)
	}
	// The form's default format is PEM, so the extension is appended for us.
	if _, err := os.Stat(target + ".pem"); err != nil {
		t.Errorf("expected %s.pem to be written: %v", target, err)
	}
}

func TestHelpModeQClosesWithoutQuitting(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel([]*certificate.Info{createDummyCert(1)}, cfg)
	m.ready = true
	m.viewMode = ViewHelp

	newModel, cmd := m.Update(keyPress('q'))
	m = newModel.(Model)

	if m.viewMode != ViewNormal {
		t.Errorf("expected help to close to ViewNormal, got %v", m.viewMode)
	}
	if cmd != nil {
		t.Error("q in help mode should not issue a command (no quit)")
	}
}

func TestCtrlCQuitsFromSplash(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel([]*certificate.Info{createDummyCert(1)}, cfg)
	// Still on the splash screen.
	if m.viewMode != ViewSplash {
		t.Fatalf("expected initial ViewSplash, got %v", m.viewMode)
	}

	ctrlC := tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl})
	if ctrlC.String() != "ctrl+c" {
		t.Fatalf("test setup wrong, key string = %q", ctrlC.String())
	}

	_, cmd := m.Update(ctrlC)
	if cmd == nil {
		t.Fatal("expected a quit command from ctrl+c on splash")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("ctrl+c on splash did not produce tea.QuitMsg")
	}
}

// TestInvalidFilterShowsAlert checks that submitting an unknown filter type
// surfaces the error. filterCertificates raises a PopupAlert; the enter handler
// used to clear popupType right after calling it, leaving ViewPopup with no
// type -- an empty, title-less box, with the message discarded.
func TestInvalidFilterShowsAlert(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel(createTestCertificates(3), cfg)
	m.SetDimensions(100, 30)
	m.viewMode = ViewNormal
	m.ready = true

	m = pumpKeys(t, m, 'f', 'b', 'o', 'g', 'u', 's')
	next, _ := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	m = next.(Model)

	if m.popupType != PopupAlert {
		t.Fatalf("expected PopupAlert for an unknown filter, got popupType=%v", m.popupType)
	}
	if !strings.Contains(m.popupMessage, "Invalid filter type") {
		t.Errorf("expected the error in popupMessage, got %q", m.popupMessage)
	}
	if !strings.Contains(m.View().Content, "Invalid filter type") {
		t.Error("the invalid-filter error is not rendered on screen")
	}
}

// pumpKeys presses each key in turn, discarding commands.
func pumpKeys(t *testing.T, m Model, keys ...rune) Model {
	t.Helper()
	for _, r := range keys {
		next, _ := m.Update(keyPress(r))
		m = next.(Model)
	}
	return m
}

// TestLateSplashDoneDoesNotClosePopup covers a race: the splash is dismissed by
// any key, but the 500ms timer message is still in flight. If it retires the
// splash unconditionally it tears down whatever the user opened in the
// meantime, discarding their input.
func TestLateSplashDoneDoesNotClosePopup(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel(createTestCertificates(2), cfg)
	m = pump(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})

	if m.viewMode != ViewSplash {
		t.Fatalf("expected to start on the splash, got %v", m.viewMode)
	}

	// A key dismisses the splash, and the user immediately opens search.
	m = pump(t, m, keyPress('x'))
	m = pump(t, m, keyPress('/'))
	m = pump(t, m, keyPress('a'))

	if m.viewMode != ViewPopup || m.popupType != PopupSearch {
		t.Fatalf("expected the search popup to be open, got viewMode=%v popupType=%v",
			m.viewMode, m.popupType)
	}

	// Now the splash timer finally fires.
	m = pump(t, m, SplashDoneMsg{})

	if m.viewMode != ViewPopup || m.popupType != PopupSearch {
		t.Errorf("a late SplashDoneMsg closed the search popup: viewMode=%v popupType=%v",
			m.viewMode, m.popupType)
	}
	if got := m.textInput.Value(); got != "a" {
		t.Errorf("the typed query was lost, textInput = %q", got)
	}
}

// TestExportFormAbortClosesPopup checks that an aborted export form tears the
// popup down instead of leaving it on screen, unresponsive.
func TestExportFormAbortClosesPopup(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel(createTestCertificates(1), cfg)
	m = pump(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m.viewMode = ViewNormal

	m = pump(t, m, keyPress('e'))
	if !m.exportFormOpen() {
		t.Fatal("e did not open the export form")
	}

	// Abort via the form's own quit binding (ctrl+c). It reaches the form here
	// because this drives updateExportForm directly, past the Update-level
	// interception.
	m = m.updateExportFormModel(t, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))

	if m.exportForm != nil {
		t.Errorf("aborted form was not cleared (state=%v)", m.exportForm.State)
	}
	if m.viewMode != ViewNormal || m.popupType != PopupNone {
		t.Errorf("aborted form left the popup open: viewMode=%v popupType=%v", m.viewMode, m.popupType)
	}
}

// updateExportFormModel is a tiny test shim that runs updateExportForm and
// settles the resulting command, returning the concrete model.
func (m Model) updateExportFormModel(t *testing.T, msg tea.Msg) Model {
	t.Helper()
	next, cmd := m.updateExportForm(msg)
	out := next.(Model)
	settle(cmd)
	return out
}
