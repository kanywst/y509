package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"

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
	ViewSplash ViewMode = iota
	ViewNormal
	ViewCommand
	ViewDetail
)

// SplashDoneMsg indicates splash screen is complete
type SplashDoneMsg struct{}

// Model represents the application state
type Model struct {
	certificates    []*certificate.CertificateInfo
	allCertificates []*certificate.CertificateInfo // Original unfiltered list
	cursor          int
	focus           Focus
	width           int
	height          int
	ready           bool

	// Command mode
	viewMode     ViewMode
	commandInput string
	commandError string

	// Detail view
	detailField string
	detailValue string

	// Search and filter
	searchQuery  string
	filterActive bool
	filterType   string

	// Splash screen
	splashTimer int

	// Right pane scrolling
	rightPaneScroll int
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// NewModel creates a new model with certificates
func NewModel(certs []*certificate.CertificateInfo) Model {
	return Model{
		certificates:    certs,
		allCertificates: certs,
		cursor:          0,
		focus:           FocusLeft,
		ready:           false,
		viewMode:        ViewSplash,
		commandInput:    "",
		commandError:    "",
		detailField:     "",
		detailValue:     "",
		searchQuery:     "",
		filterActive:    false,
		filterType:      "",
		splashTimer:     0,
		rightPaneScroll: 0,
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return SplashDoneMsg{}
	})
}

// Update handles messages and updates the model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		return m, nil

	case SplashDoneMsg:
		if m.viewMode == ViewSplash {
			m.splashTimer++
			if m.splashTimer >= 20 { // 2 seconds (20 * 100ms)
				m.viewMode = ViewNormal
				return m, nil
			}
			return m, tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
				return SplashDoneMsg{}
			})
		}
		return m, nil

	case tea.KeyMsg:
		// Skip splash screen on any key press
		if m.viewMode == ViewSplash {
			m.viewMode = ViewNormal
			return m, nil
		}

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
				// Reset right pane scroll when changing certificate
				m.rightPaneScroll = 0
			}
		} else if m.focus == FocusRight {
			// Scroll up in right pane
			if m.rightPaneScroll > 0 {
				m.rightPaneScroll--
			}
		}

	case "down", "j":
		if m.focus == FocusLeft && len(m.certificates) > 0 {
			if m.cursor < len(m.certificates)-1 {
				m.cursor++
				// Reset right pane scroll when changing certificate
				m.rightPaneScroll = 0
			}
		} else if m.focus == FocusRight {
			// Scroll down in right pane
			m.rightPaneScroll++
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

	// Check if we have certificates for commands that require them
	if !m.hasValidCertificatesForCommand(cmd) {
		m.commandError = "No certificates available"
		return
	}

	// Handle global commands (don't require selected certificate)
	if m.handleGlobalCommands(cmd) {
		return
	}

	// Handle certificate-specific commands
	if len(m.certificates) == 0 {
		m.commandError = "No certificates available"
		return
	}

	m.handleCertificateCommands(cmd)
}

// hasValidCertificatesForCommand checks if we have certificates for the given command
func (m *Model) hasValidCertificatesForCommand(cmd string) bool {
	globalCommands := []string{"search", "filter", "reset", "validate", "val", "export", "help", "h", "quit", "q"}

	for _, globalCmd := range globalCommands {
		if cmd == globalCmd || strings.HasPrefix(cmd, globalCmd+" ") {
			return true
		}
	}

	return len(m.certificates) > 0
}

// handleGlobalCommands processes commands that don't require a selected certificate
func (m *Model) handleGlobalCommands(cmd string) bool {
	switch {
	case strings.HasPrefix(cmd, "search "):
		query := strings.TrimSpace(cmd[7:])
		m.searchCertificates(query)
		return true
	case cmd == "reset":
		m.resetView()
		return true
	case strings.HasPrefix(cmd, "filter "):
		filterType := strings.TrimSpace(cmd[7:])
		m.filterCertificates(filterType)
		return true
	case cmd == "validate" || cmd == "val":
		m.handleValidateCommand()
		return true
	case strings.HasPrefix(cmd, "export "):
		m.exportCertificate(cmd)
		return true
	case cmd == "help" || cmd == "h":
		m.showHelpCommand()
		return true
	case cmd == "quit" || cmd == "q":
		m.viewMode = ViewNormal
		m.focus = FocusLeft
		return true
	}
	return false
}

// handleCertificateCommands processes commands that require a selected certificate
func (m *Model) handleCertificateCommands(cmd string) {
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
		m.handleGotoCommand(cmd)
	default:
		m.commandError = fmt.Sprintf("Unknown command: %s (type 'help' for available commands)", cmd)
	}
}

// handleValidateCommand processes the validate command
func (m *Model) handleValidateCommand() {
	result := certificate.ValidateChain(m.allCertificates)
	m.showDetail("Chain Validation", certificate.FormatChainValidation(result))
}

// handleGotoCommand processes the goto command
func (m *Model) handleGotoCommand(cmd string) {
	parts := strings.Fields(cmd)
	if len(parts) != 2 {
		m.commandError = "Usage: goto <number> or g <number>"
		return
	}

	index, err := strconv.Atoi(parts[1])
	if err != nil {
		m.commandError = "Invalid certificate number"
		return
	}

	if index < 1 || index > len(m.certificates) {
		m.commandError = "Invalid certificate number"
		return
	}

	m.cursor = index - 1
	m.rightPaneScroll = 0 // Reset scroll when jumping to certificate
	m.viewMode = ViewNormal
	m.focus = FocusLeft
}

// showHelpCommand displays the help information
func (m *Model) showHelpCommand() {
	helpText := `Available commands:

Certificate Information:
subject, s      - Show certificate subject
issuer, i       - Show certificate issuer  
validity, v     - Show validity period
san             - Show Subject Alternative Names
fingerprint, fp - Show SHA256 fingerprint
serial          - Show serial number
pubkey, pk      - Show public key info

Navigation:
goto N, g N     - Go to certificate N

Chain Operations:
validate, val   - Validate certificate chain

Search & Filter:
search <query>  - Search certificates by CN, org, DNS, issuer
filter expired  - Show only expired certificates
filter expiring - Show only expiring certificates
filter valid    - Show only valid certificates
filter self-signed - Show only self-signed certificates
reset           - Reset search/filter

Export:
export pem <file> - Export current cert as PEM
export der <file> - Export current cert as DER

Other:
help, h         - Show this help
quit, q         - Quit application

Press ESC to return to normal mode`

	m.showDetail("Commands", helpText)
}

// searchCertificates searches certificates based on query
func (m *Model) searchCertificates(query string) {
	if query == "" {
		m.commandError = "Search query cannot be empty"
		return
	}

	results := certificate.SearchCertificates(m.allCertificates, query)
	m.certificates = results
	m.searchQuery = query
	m.filterActive = true
	m.filterType = fmt.Sprintf("search: %s", query)
	m.cursor = 0
	m.rightPaneScroll = 0 // Reset scroll when searching

	m.viewMode = ViewNormal
	m.focus = FocusLeft

	if len(results) == 0 {
		m.commandError = fmt.Sprintf("No certificates found matching '%s'", query)
	}
}

// filterCertificates filters certificates based on criteria
func (m *Model) filterCertificates(filterType string) {
	validFilters := []string{"expired", "expiring", "valid", "self-signed"}
	found := false
	for _, valid := range validFilters {
		if filterType == valid {
			found = true
			break
		}
	}

	if !found {
		m.commandError = fmt.Sprintf("Invalid filter type: %s (valid: %s)", filterType, strings.Join(validFilters, ", "))
		return
	}

	results := certificate.FilterCertificates(m.allCertificates, filterType)
	m.certificates = results
	m.filterActive = true
	m.filterType = filterType
	m.cursor = 0
	m.rightPaneScroll = 0 // Reset scroll when filtering

	m.viewMode = ViewNormal
	m.focus = FocusLeft

	if len(results) == 0 {
		m.commandError = fmt.Sprintf("No certificates found with filter '%s'", filterType)
	}
}

// resetView resets search and filter
func (m *Model) resetView() {
	m.certificates = m.allCertificates
	m.searchQuery = ""
	m.filterActive = false
	m.filterType = ""
	m.cursor = 0
	m.rightPaneScroll = 0 // Reset scroll when resetting view
	m.viewMode = ViewNormal
	m.focus = FocusLeft
}

// exportCertificate exports the current certificate
func (m *Model) exportCertificate(cmd string) {
	if len(m.certificates) == 0 {
		m.commandError = "No certificate selected"
		return
	}

	parts := strings.Fields(cmd)
	if len(parts) != 3 {
		m.commandError = "Usage: export <format> <filename> (format: pem, der)"
		return
	}

	format := parts[1]
	filename := parts[2]

	cert := m.certificates[m.cursor].Certificate
	err := certificate.ExportCertificate(cert, format, filename)
	if err != nil {
		m.commandError = fmt.Sprintf("Export failed: %v", err)
		return
	}

	m.showDetail("Export Success", fmt.Sprintf("Certificate exported successfully!\n\nFormat: %s\nFile: %s\nCertificate: %s",
		strings.ToUpper(format), filename, cert.Subject.CommonName))
}

// showDetail switches to detail view mode
func (m *Model) showDetail(field, value string) {
	m.viewMode = ViewDetail
	m.detailField = field
	m.detailValue = value
}

// View renders the model - WITH SPLASH SCREEN
func (m Model) View() string {
	if !m.ready {
		return "Initializing..."
	}

	switch m.viewMode {
	case ViewSplash:
		return m.renderSplashScreen()
	case ViewDetail:
		return m.renderDetailView()
	default:
		if len(m.allCertificates) == 0 {
			return "No certificates found."
		}
		return m.renderNormalView()
	}
}

// renderNormalView renders the normal two-pane view - ALWAYS DUAL PANE
func (m Model) renderNormalView() string {
	// Calculate available space for main content
	statusBarHeight := 1
	commandBarHeight := 0
	if m.viewMode == ViewCommand {
		commandBarHeight = 1
	}

	// Calculate main content height
	mainHeight := m.height - statusBarHeight - commandBarHeight
	if mainHeight < 3 {
		mainHeight = 3
	}

	// Always use dual pane layout, regardless of width
	// Calculate pane widths - make left pane smaller for narrow screens
	var leftWidth, rightWidth int
	if m.width < 40 {
		// Very narrow: 1/4 and 3/4
		leftWidth = max(8, m.width/4)
		rightWidth = m.width - leftWidth
	} else if m.width < 60 {
		// Narrow: 1/3 and 2/3
		leftWidth = max(12, m.width/3)
		rightWidth = m.width - leftWidth
	} else {
		// Normal: 1/3 and 2/3
		leftWidth = m.width / 3
		rightWidth = m.width - leftWidth
	}

	// Ensure minimum widths
	if leftWidth < 8 {
		leftWidth = 8
		rightWidth = m.width - leftWidth
	}
	if rightWidth < 8 {
		rightWidth = 8
		leftWidth = m.width - rightWidth
	}

	// Calculate content height for list (subtract borders only)
	contentHeight := mainHeight - 2 // borders(2) only
	if contentHeight < 1 {
		contentHeight = 1
	}

	leftContent := m.renderCertificateList(contentHeight)
	leftPane := m.createPane(leftContent, leftWidth, mainHeight, m.focus == FocusLeft, "")

	// Render right pane (certificate details) with scrolling
	rightContent := m.renderCertificateDetails(rightWidth-4, contentHeight)
	rightPane := m.createPane(rightContent, rightWidth, mainHeight, m.focus == FocusRight, "")

	// Combine panes
	mainView := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)

	// Build final view
	var parts []string
	parts = append(parts, mainView)

	if m.viewMode == ViewCommand {
		parts = append(parts, m.renderCommandBar())
	}

	parts = append(parts, m.renderStatusBar())

	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// renderDetailView renders the full-screen detail view
func (m Model) renderDetailView() string {
	title := m.detailField
	if len(m.certificates) > 0 {
		title = fmt.Sprintf("%s - Certificate %d/%d", m.detailField, m.cursor+1, len(m.certificates))
	}

	// Calculate main content height
	mainHeight := m.height - 1 // Status bar

	// Create full-screen pane
	content := m.detailValue
	pane := m.createPane(content, m.width, mainHeight, true, "")

	// Status bar for detail view with title
	statusText := fmt.Sprintf("[%s] ESC: back to normal view • q: quit", title)
	statusBar := lipgloss.NewStyle().
		Background(lipgloss.Color("62")).
		Foreground(lipgloss.Color("230")).
		Bold(true).
		Width(m.width).
		Padding(0, 1).
		Render(statusText)

	return lipgloss.JoinVertical(lipgloss.Left, pane, statusBar)
}

// renderCommandBar renders the command input bar
func (m Model) renderCommandBar() string {
	prompt := ":"
	input := m.commandInput

	if m.commandError != "" {
		errorStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true).
			Width(m.width).
			Padding(0, 1)
		return errorStyle.Render(fmt.Sprintf("Error: %s", m.commandError))
	}

	commandStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("240")).
		Foreground(lipgloss.Color("255")).
		Width(m.width).
		Padding(0, 1)

	return commandStyle.Render(prompt + input)
}

// renderCertificateList renders the list of certificates - COMPACT FOR SMALL SCREENS
func (m Model) renderCertificateList(height int) string {
	if len(m.certificates) == 0 {
		if m.filterActive {
			return fmt.Sprintf("No certs match filter: %s\n\nUse ':reset' to clear", m.filterType)
		}
		return "No certificates"
	}

	// Ensure height is positive
	if height <= 0 {
		height = 1
	}

	var content strings.Builder
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

		// Create compact label for narrow screens
		var line string
		if m.width < 40 {
			// Very compact: just number and status
			line = fmt.Sprintf("%d", i+1)
		} else if m.width < 60 {
			// Compact: number and short name
			shortName := cert.Label
			if len(shortName) > 15 {
				shortName = shortName[:12] + "..."
			}
			line = fmt.Sprintf("%d. %s", i+1, shortName)
		} else {
			// Normal: full label
			line = fmt.Sprintf("%d. %s", i+1, cert.Label)
		}

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

		content.WriteString(line)
		if i < end-1 || i < len(m.certificates)-1 {
			content.WriteString("\n")
		}
	}

	return content.String()
}

// renderCertificateDetails renders the details of the selected certificate with scrolling support
func (m Model) renderCertificateDetails(width, height int) string {
	if len(m.certificates) == 0 {
		return "No certificate selected"
	}

	cert := m.certificates[m.cursor]

	// Get full details
	var details string
	if width < 30 {
		// Very compact details
		details = fmt.Sprintf("Cert %d/%d\n%s\n\nSubject:\n%s\n\nIssuer:\n%s\n\nValid:\n%s - %s",
			m.cursor+1, len(m.certificates),
			cert.Label,
			cert.Certificate.Subject.CommonName,
			cert.Certificate.Issuer.CommonName,
			cert.Certificate.NotBefore.Format("2006-01-02"),
			cert.Certificate.NotAfter.Format("2006-01-02"))
	} else {
		// Use full details
		details = certificate.GetCertificateDetails(cert.Certificate)
	}

	// Split details into lines for scrolling
	lines := strings.Split(details, "\n")

	// Apply scrolling
	start := m.rightPaneScroll
	end := start + height

	// Ensure we don't scroll past the content
	if start >= len(lines) {
		start = max(0, len(lines)-height)
		m.rightPaneScroll = start
	}
	if end > len(lines) {
		end = len(lines)
	}

	// Get visible lines
	var visibleLines []string
	if start < len(lines) {
		visibleLines = lines[start:end]
	}

	// Join visible lines
	scrolledContent := strings.Join(visibleLines, "\n")

	// Add scroll indicator if there's more content
	if len(lines) > height {
		scrollInfo := ""
		if start > 0 {
			scrollInfo += "↑ "
		}
		if end < len(lines) {
			scrollInfo += "↓ "
		}
		if scrollInfo != "" {
			scrollInfo = fmt.Sprintf(" [%s%d/%d]", scrollInfo, start+1, len(lines))
			scrolledContent += "\n" + scrollInfo
		}
	}

	// Apply text wrapping with proper width
	style := lipgloss.NewStyle().
		Width(width)

	return style.Render(scrolledContent)
}

// createPane creates a styled pane with border (no internal title)
func (m Model) createPane(content string, width, height int, focused bool, title string) string {
	// Create the bordered pane without internal title
	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Width(width).
		Padding(0, 1)

	if focused {
		borderStyle = borderStyle.BorderForeground(lipgloss.Color("62"))
	} else {
		borderStyle = borderStyle.BorderForeground(lipgloss.Color("240"))
	}

	return borderStyle.Render(content)
}

// renderStatusBar renders the status bar with help text and pane titles - COMPACT FOR SMALL SCREENS
func (m Model) renderStatusBar() string {
	// Build pane titles
	leftTitle := "Certs"
	if m.filterActive {
		if m.width < 40 {
			leftTitle = "Filtered"
		} else {
			leftTitle = fmt.Sprintf("Certs (%s)", m.filterType)
			if len(leftTitle) > 15 {
				leftTitle = "Certs (filtered)"
			}
		}
	}
	rightTitle := "Details"

	// Add focus indicators
	if m.focus == FocusLeft {
		leftTitle = "[" + leftTitle + "]"
	} else {
		rightTitle = "[" + rightTitle + "]"
	}

	// Build help text - compact for narrow screens
	var helpText string
	if m.width < 50 {
		if m.focus == FocusRight {
			helpText = "↑/↓:scroll ←/→:pane ::cmd q:quit"
		} else {
			helpText = "↑/↓:nav ←/→:pane ::cmd q:quit"
		}
	} else {
		if m.focus == FocusRight {
			helpText = "↑/↓: scroll details • ←/→: switch panes • :: command mode • q: quit"
		} else {
			helpText = "↑/↓: navigate • ←/→: switch panes • :: command mode • q: quit"
		}
	}

	if len(m.certificates) > 0 {
		cert := m.certificates[m.cursor]
		var certInfo string
		if m.width < 50 {
			certInfo = fmt.Sprintf("%d/%d", m.cursor+1, len(m.certificates))
		} else {
			certInfo = fmt.Sprintf("Certificate %d/%d", m.cursor+1, len(m.certificates))
		}

		if certificate.IsExpired(cert.Certificate) {
			certInfo += " (EXPIRED)"
		} else if certificate.IsExpiringSoon(cert.Certificate) {
			if m.width < 50 {
				certInfo += " (EXP)"
			} else {
				certInfo += " (EXPIRING SOON)"
			}
		}

		helpText = certInfo + " • " + helpText
	}

	// Combine titles and help text
	var statusText string
	if m.width < 50 {
		statusText = fmt.Sprintf("%s|%s • %s", leftTitle, rightTitle, helpText)
	} else {
		statusText = fmt.Sprintf("%s | %s • %s", leftTitle, rightTitle, helpText)
	}

	return lipgloss.NewStyle().
		Background(lipgloss.Color("62")).
		Foreground(lipgloss.Color("230")).
		Bold(true).
		Width(m.width).
		Padding(0, 1).
		Render(statusText)
}
