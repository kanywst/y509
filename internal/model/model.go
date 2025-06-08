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

// calculateAvailableWidth calculates the available width for display elements
// based on the current screen width and view mode (single or dual pane)
func (m Model) calculateAvailableWidth() int {
	if m.shouldUseSinglePane() {
		return m.width - 4 // subtract padding/borders for single pane
	}

	// In dual pane mode, calculate left pane width
	if m.width < 60 {
		return max(12, m.width*2/5) - 4 // subtract padding/borders
	}
	return m.width/3 - 4
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

// getMinimumSize returns the minimum required width and height for the TUI
func getMinimumSize() (int, int) {
	return 20, 6 // minimum 20 chars wide, 6 lines high
}

// shouldUseSinglePane determines if single pane mode should be used
func (m Model) shouldUseSinglePane() bool {
	minWidth, _ := getMinimumSize()
	return m.width < minWidth*2 // Use single pane if less than 40 chars wide
}

// wrapText wraps text to fit within the specified width
func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	var lines []string
	var currentLine strings.Builder

	for _, word := range words {
		// If adding this word would exceed width, start new line
		if currentLine.Len() > 0 && currentLine.Len()+1+len(word) > width {
			lines = append(lines, currentLine.String())
			currentLine.Reset()
		}

		// Add word to current line
		if currentLine.Len() > 0 {
			currentLine.WriteString(" ")
		}
		currentLine.WriteString(word)
	}

	// Add the last line
	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}

	return strings.Join(lines, "\n")
}

// truncateText truncates text to fit within the specified width with ellipsis
func truncateText(text string, width int) string {
	if width <= 0 {
		return ""
	}
	if len(text) <= width {
		return text
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}
	return text[:width-3] + "..."
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
		if m.shouldUseSinglePane() {
			// In single pane mode, left arrow goes back to list
			m.focus = FocusLeft
		} else {
			// In dual pane mode, left arrow switches to left pane
			m.focus = FocusLeft
		}

	case "right", "l":
		if m.shouldUseSinglePane() {
			// In single pane mode, right arrow goes to details
			m.focus = FocusRight
		} else {
			// In dual pane mode, right arrow switches to right pane
			m.focus = FocusRight
		}

	case "tab":
		// Tab always switches focus between panes
		if m.focus == FocusLeft {
			m.focus = FocusRight
		} else {
			m.focus = FocusLeft
		}

	case ":":
		// Enter command mode
		m.viewMode = ViewCommand
		m.focus = FocusCommand
		m.commandInput = ""
		m.commandError = ""

	case "enter":
		// Could be used for additional actions like exporting certificate
		return m, nil

	case "escape":
		// Quick exit from any special mode
		if m.viewMode == ViewCommand || m.viewMode == ViewDetail {
			m.viewMode = ViewNormal
			m.focus = FocusLeft
			m.commandInput = ""
			m.commandError = ""
			m.detailField = ""
			m.detailValue = ""
		}

	case "?":
		// Show quick help in normal mode
		helpText := m.getQuickHelp()
		m.showDetail("Quick Help", helpText)
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

// getQuickHelp returns contextual quick help text
func (m Model) getQuickHelp() string {
	var help strings.Builder

	if m.shouldUseSinglePane() {
		help.WriteString("SINGLE PANE MODE\n\n")
		help.WriteString("Navigation:\n")
		help.WriteString("  ↑/↓ or j/k  - Navigate certificates (in list mode)\n")
		help.WriteString("  ↑/↓ or j/k  - Scroll details (in detail mode)\n")
		help.WriteString("  ←/→ or h/l  - Switch between list and details\n")
		help.WriteString("  Tab         - Switch between list and details\n")
	} else {
		help.WriteString("DUAL PANE MODE\n\n")
		help.WriteString("Navigation:\n")
		help.WriteString("  ↑/↓ or j/k  - Navigate certificates (left) / Scroll details (right)\n")
		help.WriteString("  ←/→ or h/l  - Switch between panes\n")
		help.WriteString("  Tab         - Switch between panes\n")
	}

	help.WriteString("\nCommands:\n")
	help.WriteString("  :           - Enter command mode\n")
	help.WriteString("  :help       - Show full help\n")
	help.WriteString("  :search X   - Search certificates\n")
	help.WriteString("  :filter X   - Filter certificates (expired, valid, etc.)\n")
	help.WriteString("  :reset      - Clear search/filter\n")
	help.WriteString("  ?           - Show this quick help\n")
	help.WriteString("  Esc         - Exit command/detail mode\n")
	help.WriteString("  q           - Quit application\n")

	if len(m.certificates) > 0 {
		help.WriteString("\nCertificate Commands:\n")
		help.WriteString("  :subject    - Show certificate subject\n")
		help.WriteString("  :issuer     - Show certificate issuer\n")
		help.WriteString("  :validity   - Show validity period\n")
		help.WriteString("  :san        - Show Subject Alternative Names\n")
	}

	return help.String()
}

// View renders the model - WITH SPLASH SCREEN
func (m Model) View() string {
	if !m.ready {
		return "Initializing..."
	}

	// Ensure minimum terminal size
	minWidth, minHeight := getMinimumSize()
	if m.width < minWidth || m.height < minHeight {
		return m.renderMinimumSizeWarning(minWidth, minHeight)
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

// renderMinimumSizeWarning renders a warning when terminal is too small
func (m Model) renderMinimumSizeWarning(minWidth, minHeight int) string {
	warning := fmt.Sprintf("Terminal too small!\nMinimum: %dx%d\nCurrent: %dx%d\n\nResize terminal or press 'q' to quit",
		minWidth, minHeight, m.width, m.height)

	style := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Foreground(lipgloss.Color("196")).
		Bold(true)

	return style.Render(warning)
}

// renderNormalView renders the normal view - adaptive layout
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

	// Use single pane mode for very narrow terminals
	if m.shouldUseSinglePane() {
		return m.renderSinglePaneView(mainHeight)
	}

	// Use dual pane layout for wider terminals
	return m.renderDualPaneView(mainHeight)
}

// renderSinglePaneView renders a single pane view for very narrow terminals
func (m Model) renderSinglePaneView(mainHeight int) string {
	var content string

	// Calculate content height (subtract borders)
	contentHeight := mainHeight - 2
	if contentHeight < 1 {
		contentHeight = 1
	}

	if m.focus == FocusLeft {
		// Show certificate list
		content = m.renderCertificateList(contentHeight)
	} else {
		// Show certificate details
		content = m.renderCertificateDetails(m.width-4, contentHeight)
	}

	// Create single pane
	pane := m.createPane(content, m.width, mainHeight, true, "")

	// Build final view
	var parts []string
	parts = append(parts, pane)

	if m.viewMode == ViewCommand {
		parts = append(parts, m.renderCommandBar())
	}

	parts = append(parts, m.renderStatusBar())

	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// renderDualPaneView renders the dual pane view for wider terminals
func (m Model) renderDualPaneView(mainHeight int) string {
	// Calculate pane widths - more flexible allocation
	var leftWidth, rightWidth int
	if m.width < 60 {
		// Narrow: give more space to details
		leftWidth = max(12, m.width*2/5)
		rightWidth = m.width - leftWidth
	} else if m.width < 100 {
		// Medium: balanced split
		leftWidth = m.width / 3
		rightWidth = m.width - leftWidth
	} else {
		// Wide: give more space to details
		leftWidth = m.width / 4
		rightWidth = m.width - leftWidth
	}

	// Ensure minimum widths
	if leftWidth < 10 {
		leftWidth = 10
		rightWidth = m.width - leftWidth
	}
	if rightWidth < 15 {
		rightWidth = 15
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

// renderCertificateList renders the list of certificates - optimized for all screen sizes
func (m Model) renderCertificateList(height int) string {
	if len(m.certificates) == 0 {
		if m.filterActive {
			return fmt.Sprintf("No certs match filter: %s\n\nUse ':reset' to clear", truncateText(m.filterType, 20))
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

		// Create adaptive label based on available width
		var line string
		availableWidth := m.calculateAvailableWidth()

		// Build line based on available width
		if availableWidth < 15 {
			// Ultra compact: just number and emoji
			line = fmt.Sprintf("%d", i+1)
		} else if availableWidth < 25 {
			// Very compact: number only
			line = fmt.Sprintf("%d. %s", i+1, truncateText(cert.Label, availableWidth-5))
		} else if availableWidth < 40 {
			// Compact: number and short name
			shortName := truncateText(cert.Label, availableWidth-8)
			line = fmt.Sprintf("%d. %s", i+1, shortName)
		} else {
			// Normal: full label (truncated if necessary)
			maxLabelWidth := availableWidth - 8 // account for number, dots, emoji, spaces
			line = fmt.Sprintf("%d. %s", i+1, truncateText(cert.Label, maxLabelWidth))
		}

		// Add status indicators
		if certificate.IsExpired(cert.Certificate) {
			if availableWidth >= 15 {
				line = "🔴 " + line
			} else {
				line = "X " + line
			}
		} else if certificate.IsExpiringSoon(cert.Certificate) {
			if availableWidth >= 15 {
				line = "🟡 " + line
			} else {
				line = "! " + line
			}
		} else {
			if availableWidth >= 15 {
				line = "🟢 " + line
			} else {
				line = "✓ " + line
			}
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

// renderCertificateDetails renders the details of the selected certificate with improved text handling
func (m Model) renderCertificateDetails(width, height int) string {
	if len(m.certificates) == 0 {
		return "No certificate selected"
	}

	cert := m.certificates[m.cursor]

	// Get appropriate details based on width
	var details string
	if width < 25 {
		// Ultra compact details - only essential info
		details = fmt.Sprintf("Cert %d/%d\n%s\n\nCN: %s\nExp: %s",
			m.cursor+1, len(m.certificates),
			truncateText(cert.Label, width),
			truncateText(cert.Certificate.Subject.CommonName, width),
			cert.Certificate.NotAfter.Format("2006-01-02"))
	} else if width < 40 {
		// Compact details
		details = fmt.Sprintf("Certificate %d/%d\n%s\n\nSubject:\n%s\n\nExpires:\n%s",
			m.cursor+1, len(m.certificates),
			truncateText(cert.Label, width),
			truncateText(cert.Certificate.Subject.CommonName, width),
			cert.Certificate.NotAfter.Format("2006-01-02 15:04"))
	} else if width < 60 {
		// Medium details
		details = fmt.Sprintf("Certificate %d/%d\n%s\n\nSubject:\n%s\n\nIssuer:\n%s\n\nValid:\n%s - %s",
			m.cursor+1, len(m.certificates),
			cert.Label,
			wrapText(cert.Certificate.Subject.CommonName, width),
			wrapText(cert.Certificate.Issuer.CommonName, width),
			cert.Certificate.NotBefore.Format("2006-01-02"),
			cert.Certificate.NotAfter.Format("2006-01-02"))
	} else {
		// Full details with proper wrapping
		fullDetails := certificate.GetCertificateDetails(cert.Certificate)
		details = wrapText(fullDetails, width)
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

	// Add scroll indicator if there's more content (only if there's room)
	if len(lines) > height && width > 10 {
		scrollInfo := ""
		if start > 0 {
			scrollInfo += "↑ "
		}
		if end < len(lines) {
			scrollInfo += "↓ "
		}
		if scrollInfo != "" {
			scrollInfo = fmt.Sprintf(" [%s%d/%d]", scrollInfo, start+1, len(lines))
			if len(scrollInfo) <= width {
				scrolledContent += "\n" + scrollInfo
			}
		}
	}

	return scrolledContent
}

// renderImprovedCertificateDetails renders certificate details with enhanced UX and better formatting
func (m Model) renderImprovedCertificateDetails(width, height int) string {
	if len(m.certificates) == 0 {
		return "No certificate selected"
	}

	cert := m.certificates[m.cursor]

	// Format details based on width with better content prioritization
	var details string
	if width < 30 {
		// Ultra compact: Focus on critical information only
		status := ""
		if certificate.IsExpired(cert.Certificate) {
			status = "❌ EXPIRED"
		} else if certificate.IsExpiringSoon(cert.Certificate) {
			status = "⚠️ EXPIRING"
		} else {
			status = "✅ VALID"
		}

		details = fmt.Sprintf("Certificate %d/%d\n%s\n\n%s\n\nSubject:\n%s\n\nIssuer:\n%s\n\nValidity:\n%s\n\nDNS:\n%s",
			m.cursor+1, len(m.certificates),
			truncateText(cert.Label, width-2),
			status,
			truncateText(cert.Certificate.Subject.CommonName, width-2),
			truncateText(cert.Certificate.Issuer.CommonName, width-2),
			cert.Certificate.NotAfter.Format("2006-01-02"),
			truncateText(strings.Join(cert.Certificate.DNSNames, ", "), width-2))

	} else if width < 50 {
		// Compact: Essential information with better organization
		status := ""
		statusIcon := ""
		now := time.Now()
		if certificate.IsExpired(cert.Certificate) {
			status = "EXPIRED"
			statusIcon = "❌"
		} else if certificate.IsExpiringSoon(cert.Certificate) {
			status = "EXPIRING SOON"
			statusIcon = "⚠️"
		} else {
			status = "VALID"
			statusIcon = "✅"
		}

		// Add days remaining/expired info
		daysInfo := ""
		if cert.Certificate.NotAfter.Before(now) {
			duration := now.Sub(cert.Certificate.NotAfter)
			days := int(duration.Hours() / 24)
			daysInfo = fmt.Sprintf(" (%d days ago)", days)
		} else {
			duration := cert.Certificate.NotAfter.Sub(now)
			days := int(duration.Hours() / 24)
			daysInfo = fmt.Sprintf(" (%d days)", days)
		}

		details = fmt.Sprintf("Certificate %d/%d\n%s\n%s Status: %s%s\n\nSubject: %s",
			m.cursor+1, len(m.certificates),
			wrapText(cert.Label, width-2),
			statusIcon, status, daysInfo,
			wrapText(cert.Certificate.Subject.CommonName, width-10))

		if len(cert.Certificate.Subject.Organization) > 0 {
			details += fmt.Sprintf("\nOrganization: %s", wrapText(strings.Join(cert.Certificate.Subject.Organization, ", "), width-14))
		}

		details += fmt.Sprintf("\nIssuer: %s", wrapText(cert.Certificate.Issuer.CommonName, width-8))

		// Add key DNS names if available
		if len(cert.Certificate.DNSNames) > 0 {
			details += "\nDNS: " + strings.Join(cert.Certificate.DNSNames[:min(len(cert.Certificate.DNSNames), 2)], ", ")
			if len(cert.Certificate.DNSNames) > 2 {
				details += fmt.Sprintf(" +%d more", len(cert.Certificate.DNSNames)-2)
			}
		}

		details += fmt.Sprintf("\nValidity: %s to %s",
			cert.Certificate.NotBefore.Format("2006-01-02"),
			cert.Certificate.NotAfter.Format("2006-01-02"))

	} else {
		// Full width: Ultra-compact comprehensive information
		var builder strings.Builder

		// Header with certificate position and status
		statusIcon := ""
		statusText := ""
		statusDetail := ""
		now := time.Now()

		if certificate.IsExpired(cert.Certificate) {
			statusIcon = "❌"
			statusText = "EXPIRED"
			duration := now.Sub(cert.Certificate.NotAfter)
			days := int(duration.Hours() / 24)
			statusDetail = fmt.Sprintf("Expired %d days ago", days)
		} else if certificate.IsExpiringSoon(cert.Certificate) {
			statusIcon = "⚠️"
			statusText = "EXPIRING SOON"
			duration := cert.Certificate.NotAfter.Sub(now)
			days := int(duration.Hours() / 24)
			statusDetail = fmt.Sprintf("Expires in %d days", days)
		} else {
			statusIcon = "✅"
			statusText = "VALID"
			duration := cert.Certificate.NotAfter.Sub(now)
			days := int(duration.Hours() / 24)
			statusDetail = fmt.Sprintf("Valid for %d days", days)
		}

		builder.WriteString(fmt.Sprintf("Certificate %d/%d %s %s\n",
			m.cursor+1, len(m.certificates), statusIcon, statusText))
		builder.WriteString(fmt.Sprintf("%s\n", strings.Repeat("─", min(width-2, 40))))

		// Subject information - ultra compact format
		builder.WriteString("📋 Subject:\n")
		builder.WriteString(fmt.Sprintf("  Common Name: %s\n", cert.Certificate.Subject.CommonName))
		if len(cert.Certificate.Subject.Organization) > 0 {
			builder.WriteString(fmt.Sprintf("  Organization: %s\n", strings.Join(cert.Certificate.Subject.Organization, ", ")))
		}
		if len(cert.Certificate.Subject.OrganizationalUnit) > 0 {
			builder.WriteString(fmt.Sprintf("  Organizational Unit: %s\n", strings.Join(cert.Certificate.Subject.OrganizationalUnit, ", ")))
		}
		// Combine geographic fields on one line
		var geoFields []string
		if len(cert.Certificate.Subject.Country) > 0 {
			geoFields = append(geoFields, "Country: "+strings.Join(cert.Certificate.Subject.Country, ", "))
		}
		if len(cert.Certificate.Subject.Province) > 0 {
			geoFields = append(geoFields, "Province: "+strings.Join(cert.Certificate.Subject.Province, ", "))
		}
		if len(cert.Certificate.Subject.Locality) > 0 {
			geoFields = append(geoFields, "Locality: "+strings.Join(cert.Certificate.Subject.Locality, ", "))
		}
		if len(geoFields) > 0 {
			builder.WriteString(fmt.Sprintf("  %s\n", strings.Join(geoFields, ", ")))
		}

		// Issuer information - ultra compact format
		builder.WriteString("🏢 Issuer:\n")
		builder.WriteString(fmt.Sprintf("  Common Name: %s\n", cert.Certificate.Issuer.CommonName))
		var issuerFields []string
		if len(cert.Certificate.Issuer.Organization) > 0 {
			issuerFields = append(issuerFields, "Organization: "+strings.Join(cert.Certificate.Issuer.Organization, ", "))
		}
		if len(cert.Certificate.Issuer.Country) > 0 {
			issuerFields = append(issuerFields, "Country: "+strings.Join(cert.Certificate.Issuer.Country, ", "))
		}
		if len(issuerFields) > 0 {
			builder.WriteString(fmt.Sprintf("  %s\n", strings.Join(issuerFields, ", ")))
		}

		// Validity information - compact format
		builder.WriteString("📅 Validity:\n")
		builder.WriteString(fmt.Sprintf("  Not Before: %s\n", cert.Certificate.NotBefore.Format("2006-01-02 15:04:05 MST")))
		builder.WriteString(fmt.Sprintf("  Not After:  %s\n", cert.Certificate.NotAfter.Format("2006-01-02 15:04:05 MST")))
		builder.WriteString(fmt.Sprintf("  Status: %s %s, %s\n", statusIcon, statusText, statusDetail))

		// Subject Alternative Names - prioritized and compact
		builder.WriteString("🌐 Subject Alternative Names:\n")
		if len(cert.Certificate.DNSNames) > 0 || len(cert.Certificate.IPAddresses) > 0 || len(cert.Certificate.EmailAddresses) > 0 {
			for _, dns := range cert.Certificate.DNSNames {
				builder.WriteString(fmt.Sprintf("  DNS: %s\n", dns))
			}
			for _, ip := range cert.Certificate.IPAddresses {
				builder.WriteString(fmt.Sprintf("  IP: %s\n", ip.String()))
			}
			for _, email := range cert.Certificate.EmailAddresses {
				builder.WriteString(fmt.Sprintf("  Email: %s\n", email))
			}
		} else {
			builder.WriteString("  None\n")
		}

		// Fingerprint and Serial Number - compact format
		fingerprint := certificate.FormatFingerprint(cert.Certificate)
		// Format fingerprint with colons for better readability
		formattedFingerprint := ""
		for i, char := range fingerprint {
			if i > 0 && i%2 == 0 {
				formattedFingerprint += ":"
			}
			formattedFingerprint += string(char)
		}
		builder.WriteString("🔒 SHA256 Fingerprint:\n")
		builder.WriteString(fmt.Sprintf("  %s\n", formattedFingerprint))
		builder.WriteString(fmt.Sprintf("🔢 Serial Number: %s\n", cert.Certificate.SerialNumber.String()))

		details = builder.String()
	}

	// Apply scrolling with improved scroll indicators
	lines := strings.Split(details, "\n")
	start := m.rightPaneScroll
	end := start + height

	// Ensure we don't scroll past the content
	if start >= len(lines) && len(lines) > 0 {
		start = max(0, len(lines)-height)
		// Note: We can't modify m.rightPaneScroll here as this is a read-only method
	}
	if end > len(lines) {
		end = len(lines)
	}

	// Get visible lines
	var visibleLines []string
	if start < len(lines) {
		visibleLines = lines[start:end]
	}

	scrolledContent := strings.Join(visibleLines, "\n")

	// Add enhanced scroll indicators
	if len(lines) > height && width > 15 {
		scrollInfo := ""
		if start > 0 {
			scrollInfo += "↑ "
		}
		if end < len(lines) {
			scrollInfo += "↓ "
		}
		if scrollInfo != "" {
			percentage := int(float64(start+height) / float64(len(lines)) * 100)
			if percentage > 100 {
				percentage = 100
			}
			scrollInfo = fmt.Sprintf(" [%s%d%%]", scrollInfo, percentage)
			if len(scrollInfo) <= width {
				scrolledContent += "\n" + scrollInfo
			}
		}
	}

	return scrolledContent
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

// renderStatusBar renders the status bar with adaptive help text
func (m Model) renderStatusBar() string {
	// Build pane titles
	leftTitle := "Certs"
	if m.filterActive {
		if m.width < 40 {
			leftTitle = "Filtered"
		} else {
			filterTitle := fmt.Sprintf("Certs (%s)", m.filterType)
			if len(filterTitle) > 20 {
				leftTitle = "Filtered"
			} else {
				leftTitle = filterTitle
			}
		}
	}
	rightTitle := "Details"

	// Adaptive help text based on current mode and width
	var helpText string
	if m.shouldUseSinglePane() {
		// Single pane mode - different help text
		if m.focus == FocusLeft {
			if m.width < 30 {
				helpText = "↑↓:nav →:detail ::cmd q:quit"
			} else {
				helpText = "↑/↓:navigate • →:view details • ::command • q:quit"
			}
		} else {
			if m.width < 30 {
				helpText = "↑↓:scroll ←:list ::cmd q:quit"
			} else {
				helpText = "↑/↓:scroll • ←:back to list • ::command • q:quit"
			}
		}
	} else {
		// Dual pane mode
		// Add focus indicators
		if m.focus == FocusLeft {
			leftTitle = "[" + leftTitle + "]"
		} else {
			rightTitle = "[" + rightTitle + "]"
		}

		if m.width < 50 {
			if m.focus == FocusRight {
				helpText = "↑↓:scroll ←→:pane ::cmd q:quit"
			} else {
				helpText = "↑↓:nav ←→:pane ::cmd q:quit"
			}
		} else if m.width < 80 {
			if m.focus == FocusRight {
				helpText = "↑/↓:scroll • ←/→:pane • ::cmd • q:quit"
			} else {
				helpText = "↑/↓:navigate • ←/→:pane • ::cmd • q:quit"
			}
		} else {
			if m.focus == FocusRight {
				helpText = "↑/↓: scroll details • ←/→: switch panes • :: command mode • q: quit"
			} else {
				helpText = "↑/↓: navigate • ←/→: switch panes • :: command mode • q: quit"
			}
		}
	}

	// Add certificate info if available
	if len(m.certificates) > 0 {
		cert := m.certificates[m.cursor]
		var certInfo string
		if m.width < 40 {
			certInfo = fmt.Sprintf("%d/%d", m.cursor+1, len(m.certificates))
		} else {
			certInfo = fmt.Sprintf("Certificate %d/%d", m.cursor+1, len(m.certificates))
		}

		if certificate.IsExpired(cert.Certificate) {
			if m.width < 50 {
				certInfo += " (EXP!)"
			} else {
				certInfo += " (EXPIRED)"
			}
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
	if m.shouldUseSinglePane() {
		if m.focus == FocusLeft {
			statusText = fmt.Sprintf("%s • %s", leftTitle, helpText)
		} else {
			statusText = fmt.Sprintf("%s • %s", rightTitle, helpText)
		}
	} else {
		if m.width < 50 {
			statusText = fmt.Sprintf("%s|%s • %s", leftTitle, rightTitle, helpText)
		} else {
			statusText = fmt.Sprintf("%s | %s • %s", leftTitle, rightTitle, helpText)
		}
	}

	// Truncate if too long
	if len(statusText) > m.width-2 {
		statusText = truncateText(statusText, m.width-2)
	}

	return lipgloss.NewStyle().
		Background(lipgloss.Color("62")).
		Foreground(lipgloss.Color("230")).
		Bold(true).
		Width(m.width).
		Padding(0, 1).
		Render(statusText)
}
