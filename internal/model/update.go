package model

import (
	"path/filepath"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"github.com/kanywst/y509/internal/logger"
	"go.uber.org/zap"
)

// Update handles messages and updates the model accordingly
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		m = m.resizeComponents()
		m = m.refreshViewportContent()
		logger.Log.Debug("window size updated",
			zap.Int("width", m.width),
			zap.Int("height", m.height))
		if m.exportFormOpen() {
			return m.updateExportForm(msg)
		}
		return m, nil

	case tea.MouseWheelMsg:
		if m.viewMode != ViewNormal {
			return m, nil
		}
		switch msg.Button {
		case tea.MouseWheelUp:
			m = m.moveCursorUp()
		case tea.MouseWheelDown:
			m = m.moveCursorDown()
		}
		return m, nil

	case SplashDoneMsg:
		// The splash is also dismissed by any key press, and the timer message
		// is still in flight when that happens. Only let it retire the splash,
		// never anything else: a popup opened within the first half-second
		// would otherwise be torn down, taking whatever was typed into it.
		if m.viewMode == ViewSplash {
			m.viewMode = ViewNormal
		}
		return m, nil

	case tea.KeyPressMsg:
		// Ctrl+C always quits, before any mode-specific handling (including
		// the splash dismissal below). In help and popup modes the other
		// keys close the overlay rather than the app, so q only quits from
		// the normal view.
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.viewMode == ViewSplash {
			m.viewMode = ViewNormal
			return m, nil
		}

		switch m.viewMode {
		case ViewNormal:
			if key.Matches(msg, m.keys.Quit) {
				return m, tea.Quit
			}
			return m.updateNormalMode(msg)
		case ViewHelp:
			return m.updateHelpMode(msg)
		case ViewPopup:
			return m.updatePopupMode(msg)
		default:
			m.viewMode = ViewNormal
			return m, nil
		}
	}

	// huh drives the export form through its own messages (nextFieldMsg,
	// nextGroupMsg, ...), which it returns as commands. They come back here as
	// plain tea.Msg values, so the form only ever advances a field or reaches
	// StateCompleted if we hand them back to it.
	if m.exportFormOpen() {
		return m.updateExportForm(msg)
	}

	return m, nil
}

// exportFormOpen reports whether the huh-driven export popup is on screen.
func (m Model) exportFormOpen() bool {
	return m.viewMode == ViewPopup && m.popupType == PopupExport && m.exportForm != nil
}

// updateExportForm feeds a message to the export form and, once the form is
// complete, performs the export.
func (m Model) updateExportForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	form, cmd := m.exportForm.Update(msg)
	updated, ok := form.(*huh.Form)
	if !ok {
		// Nothing else huh can return is a form we can drive. Leave the popup
		// as it was rather than reading state off the copy we no longer hold.
		return m, cmd
	}
	m.exportForm = updated

	if m.exportForm.State != huh.StateCompleted {
		return m, cmd
	}

	filename := m.exportForm.GetString("filename")
	format := m.exportForm.GetString("format")
	// filepath.Ext only inspects the final path component, so paths like
	// "./out/cert" or "dir.with.dots/cert" still get a suffix.
	if filename != "" && filepath.Ext(filename) == "" {
		filename = filename + "." + format
	}
	m.exportForm = nil
	m = m.handleExportCommand(filename)
	return m, cmd
}

// updateNormalMode handles key events in normal (two-pane) mode
func (m Model) updateNormalMode(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Left):
		m.focus = FocusLeft
		return m, nil
	case key.Matches(msg, m.keys.Right):
		m.focus = FocusRight
		return m, nil
	case key.Matches(msg, m.keys.Tab):
		if m.focus == FocusRight {
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
			m.viewport.SetYOffset(0)
			m = m.refreshViewportContent()
		}
		return m, nil
	case key.Matches(msg, m.keys.Up):
		m = m.moveCursorUp()
		return m, nil
	case key.Matches(msg, m.keys.Down):
		m = m.moveCursorDown()
		return m, nil
	case key.Matches(msg, m.keys.Back):
		if m.filterActive {
			m = m.resetView()
		}
		return m, nil
	case key.Matches(msg, m.keys.Help):
		m.viewMode = ViewHelp
		return m, nil
	case key.Matches(msg, m.keys.Search):
		m.viewMode = ViewPopup
		m.popupType = PopupSearch
		m.textInput.Placeholder = "Search query..."
		m.textInput.Focus()
		return m, textinput.Blink
	case key.Matches(msg, m.keys.Filter):
		m.viewMode = ViewPopup
		m.popupType = PopupFilter
		m.textInput.Placeholder = "Filter (expired, expiring, valid, self-signed)"
		m.textInput.Focus()
		return m, textinput.Blink
	case key.Matches(msg, m.keys.Validate):
		m = m.handleValidateCommand()
		return m, nil
	case key.Matches(msg, m.keys.Export):
		m.viewMode = ViewPopup
		m.popupType = PopupExport
		m.exportForm = newExportForm()
		return m, m.exportForm.Init()
	case key.Matches(msg, m.keys.Yank):
		var cmd tea.Cmd
		m, cmd = m.handleYankCommand()
		return m, cmd
	}

	return m, nil
}

// moveCursorUp moves the selection cursor up and handles scrolling
func (m Model) moveCursorUp() Model {
	if m.focus == FocusLeft {
		prev := m.list.Index()
		m.list.CursorUp()
		if m.list.Index() != prev {
			m.viewport.SetYOffset(0)
			m = m.refreshViewportContent()
		}
	} else {
		m.viewport.ScrollUp(1)
	}
	return m
}

// moveCursorDown moves the selection cursor down and handles scrolling
func (m Model) moveCursorDown() Model {
	if m.focus == FocusLeft {
		prev := m.list.Index()
		m.list.CursorDown()
		if m.list.Index() != prev {
			m.viewport.SetYOffset(0)
			m = m.refreshViewportContent()
		}
	} else {
		m.viewport.ScrollDown(1)
	}
	return m
}

// resizeComponents recomputes child component sizes from the current
// terminal dimensions. Both panes derive their geometry from the same
// constants used by the renderers, keeping Update and View in agreement.
func (m Model) resizeComponents() Model {
	if m.width <= 0 || m.height <= 0 {
		return m
	}

	leftPaneWidth := m.width * 2 / 5
	rightPaneWidth := m.width - leftPaneWidth
	paneHeight := m.height - HeaderHeight - statusBarHeight

	// List sits inside the left pane, below the SUBJECT/EXPIRES header,
	// inside one visible left border column and the rounded top + bottom
	// border rows.
	listInnerWidth := leftPaneWidth - PaneSideBorderWidth
	listInnerHeight := paneHeight - PaneBorderHeight - ListHeaderHeight
	if listInnerHeight < 1 {
		listInnerHeight = 1
	}
	m.list.SetSize(listInnerWidth, listInnerHeight)

	// Viewport sits inside the right pane, below the tab strip, with a
	// 1x2 inner padding and the rounded top + bottom border.
	const horizontalPadding = 2
	const verticalPadding = 1
	const tabStripHeight = 2 // label row + underline row
	const scrollFooterHeight = 1
	vpWidth := rightPaneWidth - 2*horizontalPadding - PaneBorderWidth
	vpHeight := paneHeight - PaneBorderHeight - tabStripHeight - 2*verticalPadding - scrollFooterHeight
	if vpWidth < 1 {
		vpWidth = 1
	}
	if vpHeight < 1 {
		vpHeight = 1
	}
	m.viewport.SetWidth(vpWidth)
	m.viewport.SetHeight(vpHeight)
	return m
}

// refreshViewportContent re-renders the active tab into the viewport.
// Must be called any time the selected certificate, the active tab, or
// the viewport width changes.
func (m Model) refreshViewportContent() Model {
	if m.viewport.Width() <= 0 || m.list.Index() >= len(m.certificates) {
		return m
	}
	m.viewport.SetContent(m.renderTabContent(m.viewport.Width()))
	return m
}

// updateHelpMode handles key events in help mode
func (m Model) updateHelpMode(_ tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	m.viewMode = ViewNormal
	return m, nil
}

// updatePopupMode handles key events in popup mode
func (m Model) updatePopupMode(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	keyStr := msg.String()

	// Handle Alert Popup (no input, just dismiss)
	if m.popupType == PopupAlert {
		if keyStr == "enter" || keyStr == "esc" || keyStr == "q" {
			m.viewMode = ViewNormal
			m.popupType = PopupNone
			return m, nil
		}
		return m, nil
	}

	// Export popup is driven by huh; delegate the message and bail out.
	if m.popupType == PopupExport && m.exportForm != nil {
		if keyStr == "esc" {
			m.viewMode = ViewNormal
			m.popupType = PopupNone
			m.exportForm = nil
			return m, nil
		}
		return m.updateExportForm(msg)
	}

	// Handle Input Popups (Search/Filter)
	switch keyStr {
	case "enter":
		value := m.textInput.Value()
		submitted := m.popupType

		// Dismiss the input popup before dispatching. The handler may raise an
		// alert of its own -- an unknown filter type does -- and clearing the
		// popup afterwards would throw that alert away, leaving an empty box on
		// screen with the error discarded.
		m.viewMode = ViewNormal
		m.popupType = PopupNone
		m.textInput.Reset()

		switch submitted {
		case PopupSearch:
			m = m.searchCertificates(value)
		case PopupFilter:
			m = m.filterCertificates(value)
		}
		return m, nil

	case "esc":
		m.viewMode = ViewNormal
		m.popupType = PopupNone
		m.textInput.Reset()
		return m, nil
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}
