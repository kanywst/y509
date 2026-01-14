package model

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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
		logger.Log.Debug("window size updated",
			zap.Int("width", m.width),
			zap.Int("height", m.height))
		return m, nil

	case tea.MouseMsg:
		if m.viewMode != ViewNormal {
			return m, nil
		}
		// Mouse scrolling
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			m = m.moveCursorUp()
		case tea.MouseButtonWheelDown:
			m = m.moveCursorDown()
		}
		return m, nil

	case SplashDoneMsg:
		m.viewMode = ViewNormal
		return m, nil

	case tea.KeyMsg:
		if m.viewMode == ViewSplash {
			m.viewMode = ViewNormal
			return m, nil
		}
		// Global quit (except in Popup mode where q might be part of input)
		if m.viewMode != ViewPopup {
			if msg.Type == tea.KeyCtrlC || msg.String() == "q" {
				return m, tea.Quit
			}
		} else {
			// In Popup, only Ctrl+C quits app. Esc closes popup.
			if msg.Type == tea.KeyCtrlC {
				return m, tea.Quit
			}
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
func (m Model) updateNormalMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Key type based shortcuts
	switch msg.Type {
	case tea.KeyLeft:
		m.focus = FocusLeft
		return m, nil
	case tea.KeyRight:
		m.focus = FocusRight
		return m, nil
	case tea.KeyTab:
		if m.focus == FocusRight {
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
			m.rightPaneScroll = 0
		}
		return m, nil
	case tea.KeyUp:
		m = m.moveCursorUp()
		return m, nil
	case tea.KeyDown:
		m = m.moveCursorDown()
		return m, nil
	case tea.KeyEsc:
		// Clear filters if active
		if m.filterActive {
			m = m.resetView()
		}
		return m, nil
	}

	// Key string based shortcuts
	switch msg.String() {
	case "h":
		m.focus = FocusLeft
		return m, nil
	case "l":
		m.focus = FocusRight
		return m, nil
	case "q":
		return m, tea.Quit
	case "?":
		m.viewMode = ViewHelp
		return m, nil
	case "k":
		m = m.moveCursorUp()
	case "j":
		m = m.moveCursorDown()
	case "/":
		m.viewMode = ViewPopup
		m.popupType = PopupSearch
		m.textInput.Placeholder = "Search query..."
		m.textInput.Focus()
		return m, textinput.Blink
	case "f":
		m.viewMode = ViewPopup
		m.popupType = PopupFilter
		m.textInput.Placeholder = "Filter (expired, expiring, valid, self-signed)"
		m.textInput.Focus()
		return m, textinput.Blink
	case "v":
		// Trigger validation and show popup
		m = m.handleValidateCommand()
		return m, nil
	case "e":
		// Trigger export popup
		m.viewMode = ViewPopup
		m.popupType = PopupExport
		m.textInput.Placeholder = "Filename (e.g. cert.pem)..."
		m.textInput.Focus()
		return m, textinput.Blink
	}

	return m, nil
}

// moveCursorUp moves the selection cursor up and handles scrolling
func (m Model) moveCursorUp() Model {
	if m.focus == FocusLeft {
		if m.cursor > 0 {
			m.cursor--
			m.rightPaneScroll = 0
			// Auto-scroll list
			if m.cursor < m.listScroll {
				m.listScroll = m.cursor
			}
		}
	} else {
		if m.rightPaneScroll > 0 {
			m.rightPaneScroll--
		}
	}
	return m
}

// moveCursorDown moves the selection cursor down and handles scrolling
func (m Model) moveCursorDown() Model {
	if m.focus == FocusLeft {
		if m.cursor < len(m.certificates)-1 {
			m.cursor++
			m.rightPaneScroll = 0
			// Auto-scroll list
			availableHeight := m.height - HeaderHeight - statusBarHeight - PaneBorderHeight
			listHeight := availableHeight - ListHeaderHeight
			if listHeight > 0 {
				if m.cursor >= m.listScroll+listHeight {
					m.listScroll = m.cursor - listHeight + 1
				}
			}
		}
	} else {
		m.rightPaneScroll++
	}
	return m
}

// updateHelpMode handles key events in help mode
func (m Model) updateHelpMode(_ tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.viewMode = ViewNormal
	return m, nil
}

// updatePopupMode handles key events in popup mode
func (m Model) updatePopupMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle Alert Popup (no input, just dismiss)
	if m.popupType == PopupAlert {
		if msg.Type == tea.KeyEnter || msg.Type == tea.KeyEsc || msg.String() == "q" {
			m.viewMode = ViewNormal
			m.popupType = PopupNone
			return m, nil
		}
		return m, nil
	}

	// Handle Input Popups (Search/Filter)
	switch msg.Type {
	case tea.KeyEnter:
		value := m.textInput.Value()
		m.viewMode = ViewNormal // Return to normal mode first

		switch m.popupType {
		case PopupSearch:
			m = m.searchCertificates(value)
		case PopupFilter:
			m = m.filterCertificates(value)
		case PopupExport:
			m = m.handleExportCommand(value)
		}
		m.popupType = PopupNone
		m.textInput.Reset()
		return m, nil

	case tea.KeyEsc:
		m.viewMode = ViewNormal
		m.popupType = PopupNone
		m.textInput.Reset()
		return m, nil
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}
