package model

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/pkg/certificate"
)

// Focus represents which pane is currently focused
type Focus int

const (
	FocusLeft Focus = iota
	FocusRight
	FocusCommand
)

// ViewMode represents the current view mode
type ViewMode int

const (
	ViewNormal ViewMode = iota
	ViewCommand
	ViewDetail
)

// Model represents the application state
type Model struct {
	certificates []*certificate.CertificateInfo
	cursor       int
	focus        Focus
	width        int
	height       int
	ready        bool

	// Command mode
	viewMode     ViewMode
	commandInput string
	commandError string

	// Detail view
	detailField string
	detailValue string
}

// NewModel creates a new model with certificates
func NewModel(certs []*certificate.CertificateInfo) Model {
	return Model{
		certificates: certs,
		cursor:       0,
		focus:        FocusLeft,
		ready:        false,
		viewMode:     ViewNormal,
		commandInput: "",
		commandError: "",
		detailField:  "",
		detailValue:  "",
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		return m, nil

	case tea.KeyMsg:
		switch m.viewMode {
		case ViewCommand:
			return m.updateCommandMode(msg)
		case ViewDetail:
			return m.updateDetailMode(msg)
		default:
			return m.updateNormalMode(msg)
		}
	}

	return m, nil
}

// updateNormalMode handles key events in normal mode
func (m Model) updateNormalMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit

	case "up", "k":
		if m.focus == FocusLeft && len(m.certificates) > 0 {
			if m.cursor > 0 {
				m.cursor--
			}
		}

	case "down", "j":
		if m.focus == FocusLeft && len(m.certificates) > 0 {
			if m.cursor < len(m.certificates)-1 {
				m.cursor++
			}
		}

	case "left", "h":
		m.focus = FocusLeft

	case "right", "l":
		m.focus = FocusRight

	case ":":
		// Enter command mode
		m.viewMode = ViewCommand
		m.focus = FocusCommand
		m.commandInput = ""
		m.commandError = ""

	case "enter":
		// Could be used for additional actions like exporting certificate
		return m, nil
	}

	return m, nil
}

// updateCommandMode handles key events in command mode
func (m Model) updateCommandMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc":
		// Exit command mode
		m.viewMode = ViewNormal
		m.focus = FocusLeft
		m.commandInput = ""
		m.commandError = ""

	case "enter":
		// Execute command
		m.executeCommand()

	case "backspace":
		if len(m.commandInput) > 0 {
			m.commandInput = m.commandInput[:len(m.commandInput)-1]
		}

	default:
		// Add character to command input
		if len(msg.String()) == 1 {
			m.commandInput += msg.String()
		}
	}

	return m, nil
}

// updateDetailMode handles key events in detail mode
func (m Model) updateDetailMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc", "q":
		// Exit detail mode
		m.viewMode = ViewNormal
		m.focus = FocusLeft
		m.detailField = ""
		m.detailValue = ""
	}

	return m, nil
}

// executeCommand processes the entered command
func (m *Model) executeCommand() {
	cmd := strings.TrimSpace(m.commandInput)
	m.commandError = ""

	if len(m.certificates) == 0 {
		m.commandError = "No certificates available"
		return
	}

	cert := m.certificates[m.cursor].Certificate

	switch {
	case cmd == "subject" || cmd == "s":
		m.showDetail("Subject", certificate.FormatSubject(cert))
	case cmd == "issuer" || cmd == "i":
		m.showDetail("Issuer", certificate.FormatIssuer(cert))
	case cmd == "validity" || cmd == "v":
		m.showDetail("Validity", certificate.FormatValidity(cert))
	case cmd == "san":
		m.showDetail("Subject Alternative Names", certificate.FormatSAN(cert))
	case cmd == "fingerprint" || cmd == "fp":
		m.showDetail("SHA256 Fingerprint", certificate.FormatFingerprint(cert))
	case cmd == "serial":
		m.showDetail("Serial Number", cert.SerialNumber.String())
	case cmd == "pubkey" || cmd == "pk":
		m.showDetail("Public Key", certificate.FormatPublicKey(cert))
	case strings.HasPrefix(cmd, "goto ") || strings.HasPrefix(cmd, "g "):
		parts := strings.Fields(cmd)
		if len(parts) == 2 {
			if index, err := strconv.Atoi(parts[1]); err == nil {
				if index >= 1 && index <= len(m.certificates) {
					m.cursor = index - 1
					m.viewMode = ViewNormal
					m.focus = FocusLeft
					return
				}
			}
		}
		m.commandError = "Invalid certificate number"
		return
	case cmd == "help" || cmd == "h":
		m.showDetail("Commands", `Available commands:
subject, s     - Show certificate subject
issuer, i      - Show certificate issuer  
validity, v    - Show validity period
san            - Show Subject Alternative Names
fingerprint, fp - Show SHA256 fingerprint
serial         - Show serial number
pubkey, pk     - Show public key info
goto N, g N    - Go to certificate N
help, h        - Show this help
quit, q        - Quit application

Press ESC to return to normal mode`)
	case cmd == "quit" || cmd == "q":
		m.viewMode = ViewNormal
		m.focus = FocusLeft
	default:
		m.commandError = fmt.Sprintf("Unknown command: %s (type 'help' for available commands)", cmd)
		return
	}
}

// showDetail switches to detail view mode
func (m *Model) showDetail(field, value string) {
	m.viewMode = ViewDetail
	m.detailField = field
	m.detailValue = value
}

// View renders the model
func (m Model) View() string {
	if !m.ready {
		return "Loading..."
	}

	if len(m.certificates) == 0 {
		return "No certificates found."
	}

	switch m.viewMode {
	case ViewDetail:
		return m.renderDetailView()
	default:
		return m.renderNormalView()
	}
}

// renderNormalView renders the normal two-pane view
func (m Model) renderNormalView() string {
	// Calculate dimensions
	leftWidth := m.width / 3
	rightWidth := m.width - leftWidth - 2 // Account for borders
	contentHeight := m.height - 3         // Account for status bar

	if m.viewMode == ViewCommand {
		contentHeight -= 2 // Account for command input
	}

	// Render left pane (certificate list)
	leftContent := m.renderCertificateList(contentHeight - 2) // Account for borders
	leftPane := m.createPane(leftContent, leftWidth, contentHeight, m.focus == FocusLeft, "Certificates")

	// Render right pane (certificate details)
	rightContent := m.renderCertificateDetails(rightWidth-2, contentHeight-2) // Account for borders and padding
	rightPane := m.createPane(rightContent, rightWidth, contentHeight, m.focus == FocusRight, "Details")

	// Combine panes
	mainView := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)

	// Status bar
	statusBar := m.renderStatusBar()

	// Command input (if in command mode)
	if m.viewMode == ViewCommand {
		commandBar := m.renderCommandBar()
		return lipgloss.JoinVertical(lipgloss.Left, mainView, commandBar, statusBar)
	}

	return lipgloss.JoinVertical(lipgloss.Left, mainView, statusBar)
}

// renderDetailView renders the full-screen detail view
func (m Model) renderDetailView() string {
	title := fmt.Sprintf("%s - Certificate %d/%d", m.detailField, m.cursor+1, len(m.certificates))

	// Create full-screen pane
	content := m.detailValue
	pane := m.createPane(content, m.width-2, m.height-3, true, title)

	// Status bar for detail view
	statusBar := lipgloss.NewStyle().
		Background(lipgloss.Color("62")).
		Foreground(lipgloss.Color("230")).
		Bold(true).
		Width(m.width).
		Padding(0, 1).
		Render("ESC: back to normal view • q: quit")

	return lipgloss.JoinVertical(lipgloss.Left, pane, statusBar)
}

// renderCommandBar renders the command input bar
func (m Model) renderCommandBar() string {
	prompt := ":"
	input := m.commandInput

	if m.commandError != "" {
		errorStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)
		return errorStyle.Render(fmt.Sprintf("Error: %s", m.commandError))
	}

	commandStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("240")).
		Foreground(lipgloss.Color("255")).
		Width(m.width).
		Padding(0, 1)

	return commandStyle.Render(prompt + input)
}

// renderCertificateList renders the list of certificates
func (m Model) renderCertificateList(height int) string {
	var content string
	start := 0
	end := len(m.certificates)

	// Handle scrolling if there are too many certificates
	if len(m.certificates) > height {
		if m.cursor >= height {
			start = m.cursor - height + 1
			end = start + height
		} else {
			end = height
		}
	}

	for i := start; i < end && i < len(m.certificates); i++ {
		cert := m.certificates[i]
		line := cert.Label

		// Add status indicators
		if certificate.IsExpired(cert.Certificate) {
			line = "🔴 " + line
		} else if certificate.IsExpiringSoon(cert.Certificate) {
			line = "🟡 " + line
		} else {
			line = "🟢 " + line
		}

		// Highlight current selection
		if i == m.cursor {
			if m.focus == FocusLeft {
				line = lipgloss.NewStyle().
					Background(lipgloss.Color("62")).
					Foreground(lipgloss.Color("230")).
					Bold(true).
					Render(line)
			} else {
				line = lipgloss.NewStyle().
					Background(lipgloss.Color("240")).
					Render(line)
			}
		}

		content += line + "\n"
	}

	// Fill remaining space
	for i := len(content); i < height; i++ {
		content += "\n"
	}

	return content
}

// renderCertificateDetails renders the details of the selected certificate
func (m Model) renderCertificateDetails(width, height int) string {
	if len(m.certificates) == 0 {
		return "No certificate selected"
	}

	cert := m.certificates[m.cursor]
	details := certificate.GetCertificateDetails(cert.Certificate)

	// Apply text wrapping and height limiting
	style := lipgloss.NewStyle().
		Width(width).
		Height(height)

	return style.Render(details)
}

// createPane creates a styled pane with border
func (m Model) createPane(content string, width, height int, focused bool, title string) string {
	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Width(width).
		Height(height)

	if focused {
		borderStyle = borderStyle.
			BorderForeground(lipgloss.Color("62")).
			Bold(true)
	} else {
		borderStyle = borderStyle.
			BorderForeground(lipgloss.Color("240"))
	}

	// Add title
	if title != "" {
		titleStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205"))

		if focused {
			titleStyle = titleStyle.Foreground(lipgloss.Color("62"))
		}

		content = titleStyle.Render(title) + "\n\n" + content
	}

	return borderStyle.Render(content)
}

// renderStatusBar renders the status bar with help text
func (m Model) renderStatusBar() string {
	helpText := "↑/↓: navigate • ←/→: switch panes • :: command mode • q: quit"

	if len(m.certificates) > 0 {
		cert := m.certificates[m.cursor]
		certInfo := fmt.Sprintf("Certificate %d/%d", m.cursor+1, len(m.certificates))

		if certificate.IsExpired(cert.Certificate) {
			certInfo += " (EXPIRED)"
		} else if certificate.IsExpiringSoon(cert.Certificate) {
			certInfo += " (EXPIRING SOON)"
		}

		helpText = certInfo + " • " + helpText
	}

	return lipgloss.NewStyle().
		Background(lipgloss.Color("62")).
		Foreground(lipgloss.Color("230")).
		Bold(true).
		Width(m.width).
		Padding(0, 1).
		Render(helpText)
}
