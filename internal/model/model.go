package model

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/pkg/certificate"
)

// Focus represents which pane is currently focused
type Focus int

const (
	FocusLeft Focus = iota
	FocusRight
)

// Model represents the application state
type Model struct {
	certificates []*certificate.CertificateInfo
	cursor       int
	focus        Focus
	width        int
	height       int
	ready        bool
}

// NewModel creates a new model with certificates
func NewModel(certs []*certificate.CertificateInfo) Model {
	return Model{
		certificates: certs,
		cursor:       0,
		focus:        FocusLeft,
		ready:        false,
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

		case "enter":
			// Could be used for additional actions like exporting certificate
			return m, nil
		}
	}

	return m, nil
}

// View renders the model
func (m Model) View() string {
	if !m.ready {
		return "Loading..."
	}

	if len(m.certificates) == 0 {
		return "No certificates found."
	}

	// Calculate dimensions
	leftWidth := m.width / 3
	rightWidth := m.width - leftWidth - 2 // Account for borders
	contentHeight := m.height - 3         // Account for status bar

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

	return lipgloss.JoinVertical(lipgloss.Left, mainView, statusBar)
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
	helpText := "↑/↓: navigate • ←/→: switch panes • q: quit"

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
