package model

import (
	"strings"

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
		// Re-size the bubbles/list so its internal pagination tracks the
		// current pane dimensions. Approximations matching renderLeftPane.
		leftPaneWidth := m.width * 2 / 5
		listInnerWidth := leftPaneWidth - 2
		listInnerHeight := m.height - 2 - 1 - ListHeaderHeight - 2
		if listInnerHeight < 1 {
			listInnerHeight = 1
		}
		m.list.SetSize(listInnerWidth, listInnerHeight)
		logger.Log.Debug("window size updated",
			zap.Int("width", m.width),
			zap.Int("height", m.height))
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
		m.viewMode = ViewNormal
		return m, nil

	case tea.KeyPressMsg:
		if m.viewMode == ViewSplash {
			m.viewMode = ViewNormal
			return m, nil
		}
		// Global quit (except in Popup mode where q might be part of input)
		if m.viewMode != ViewPopup {
			if key.Matches(msg, m.keys.Quit) {
				return m, tea.Quit
			}
		} else if msg.String() == "ctrl+c" {
			// In Popup, only Ctrl+C quits app. Esc closes popup.
			return m, tea.Quit
		}

		switch m.viewMode {
		case ViewNormal:
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

	return m, nil
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
		}
	} else {
		m.viewport.ScrollDown(1)
	}
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
		form, cmd := m.exportForm.Update(msg)
		if f, ok := form.(*huh.Form); ok {
			m.exportForm = f
		}
		if m.exportForm.State == huh.StateCompleted {
			filename := m.exportForm.GetString("filename")
			format := m.exportForm.GetString("format")
			if filename != "" && !strings.Contains(filename, ".") {
				filename = filename + "." + format
			}
			m.exportForm = nil
			m = m.handleExportCommand(filename)
			return m, cmd
		}
		return m, cmd
	}

	// Handle Input Popups (Search/Filter)
	switch keyStr {
	case "enter":
		value := m.textInput.Value()
		m.viewMode = ViewNormal // Return to normal mode first

		switch m.popupType {
		case PopupSearch:
			m = m.searchCertificates(value)
		case PopupFilter:
			m = m.filterCertificates(value)
		}
		m.popupType = PopupNone
		m.textInput.Reset()
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
