package model

import (
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
		if m.viewMode != ViewNormal && m.viewMode != ViewDetail {
			return m, nil
		}

		switch msg.Button {
		case tea.MouseButtonWheelUp:
			if m.focus == FocusLeft && m.viewMode == ViewNormal {
				if m.cursor > 0 {
					m.cursor--
					m.rightPaneScroll = 0
				}
			} else {
				if m.rightPaneScroll > 0 {
					m.rightPaneScroll--
				}
			}
		case tea.MouseButtonWheelDown:
			if m.focus == FocusLeft && m.viewMode == ViewNormal {
				if m.cursor < len(m.certificates)-1 {
					m.cursor++
					m.rightPaneScroll = 0
				}
			} else {
				m.rightPaneScroll++
			}
		}
		return m, nil

	case SplashDoneMsg:
		m.viewMode = ViewNormal
		return m, nil

	case tea.KeyMsg:
		// Handle splash screen exit
		if m.viewMode == ViewSplash {
			m.viewMode = ViewNormal
			return m, nil
		}

		// Handle quit command
		if msg.Type == tea.KeyCtrlC || (msg.Type == tea.KeyRunes && msg.String() == "q") {
			return m, tea.Quit
		}

		// If view mode is not set, default to normal mode
		if m.viewMode == 0 {
			m.viewMode = ViewNormal
		}

		// Handle key events based on current view mode
		switch m.viewMode {
		case ViewNormal:
			logger.Log.Debug("processing key in Update",
				zap.String("type", msg.Type.String()),
				zap.String("runes", string(msg.Runes)))
			return m.updateNormalMode(msg)
		case ViewCommand:
			return m.updateCommandMode(msg)
		case ViewDetail:
			return m.updateDetailMode(msg)
		}
	}

	return m, nil
}

// updateNormalMode handles key events in normal mode
func (m Model) updateNormalMode(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		logger.Log.Debug("processing key in normal mode",
			zap.String("type", msg.Type.String()),
			zap.String("runes", string(msg.Runes)))

		// Handle special keys
		switch msg.Type {
		case tea.KeyRunes:
			switch msg.String() {
			case ":":
				m.viewMode = ViewCommand
				return m, nil
			case "q":
				return m, tea.Quit
			case "?":
				m.viewMode = ViewDetail
				m.detailField = "Help"
				m.detailValue = m.getQuickHelp()
				return m, nil
			case "h":
				m.focus = FocusLeft
				return m, nil
			case "l":
				m.focus = FocusRight
				return m, nil
			case "j":
				if m.focus == FocusLeft && len(m.certificates) > 0 {
					if m.cursor < len(m.certificates)-1 {
						m.cursor++
						m.rightPaneScroll = 0
					}
				} else if m.focus == FocusRight {
					m.rightPaneScroll++
				}
				return m, nil
			case "k":
				if m.focus == FocusLeft && len(m.certificates) > 0 {
					if m.cursor > 0 {
						m.cursor--
						m.rightPaneScroll = 0
					}
				} else if m.focus == FocusRight {
					if m.rightPaneScroll > 0 {
						m.rightPaneScroll--
					}
				}
				return m, nil
			}
		case tea.KeyDown:
			if m.focus == FocusLeft && len(m.certificates) > 0 {
				if m.cursor < len(m.certificates)-1 {
					m.cursor++
					m.rightPaneScroll = 0
				}
			} else if m.focus == FocusRight {
				m.rightPaneScroll++
			}
			return m, nil
		case tea.KeyUp:
			if m.focus == FocusLeft && len(m.certificates) > 0 {
				if m.cursor > 0 {
					m.cursor--
					m.rightPaneScroll = 0
				}
			} else if m.focus == FocusRight {
				if m.rightPaneScroll > 0 {
					m.rightPaneScroll--
				}
			}
			return m, nil
		case tea.KeyLeft:
			m.focus = FocusLeft
			return m, nil
		case tea.KeyRight:
			m.focus = FocusRight
			return m, nil
		case tea.KeyTab:
			if m.focus == FocusLeft {
				m.focus = FocusRight
			} else {
				m.focus = FocusLeft
			}
			return m, nil
		}
	}
	return m, nil
}

// updateCommandMode handles key events in command mode
func (m Model) updateCommandMode(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			// Execute command
			m = m.executeCommand()
			// サブコマンド（issuer等）ならViewDetailに遷移済みなのでそのまま、それ以外はViewNormalに戻す
			if m.viewMode != ViewDetail {
				m.viewMode = ViewNormal
				m.focus = FocusLeft
			}
			return m, nil
		case tea.KeyEscape:
			// Cancel command and return to normal mode
			m.viewMode = ViewNormal
			m.focus = FocusLeft
			m.commandInput = ""
			m.commandError = ""
			return m, nil
		case tea.KeyBackspace:
			// Handle backspace
			if len(m.commandInput) > 0 {
				m.commandInput = m.commandInput[:len(m.commandInput)-1]
			}
			return m, nil
		case tea.KeySpace:
			// Add space to command input
			m.commandInput += " "
			return m, nil
		case tea.KeyRunes:
			// Add character to command input
			m.commandInput += string(msg.Runes)
			return m, nil
		}
	}
	return m, nil
}

// updateDetailMode handles key events in detail mode
func (m Model) updateDetailMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	logger.Log.Debug("processing detail mode key",
		zap.String("key", msg.String()))

	switch msg.Type {
	case tea.KeyEscape:
		// Return to normal mode
		m.viewMode = ViewNormal
		m.focus = FocusLeft
		m.detailField = ""
		m.detailValue = ""
		return m, nil
	case tea.KeyUp:
		// Scroll up in detail view
		if m.rightPaneScroll > 0 {
			m.rightPaneScroll--
		}
		return m, nil
	case tea.KeyDown:
		// Scroll down in detail view
		m.rightPaneScroll++
		return m, nil
	case tea.KeyRunes:
		switch msg.String() {
		case "j":
			m.rightPaneScroll++
			return m, nil
		case "k":
			if m.rightPaneScroll > 0 {
				m.rightPaneScroll--
			}
			return m, nil
		case ":":
			m.viewMode = ViewCommand
			m.commandInput = ""
			m.commandError = ""
			return m, nil
		}
	}
	return m, nil
}
