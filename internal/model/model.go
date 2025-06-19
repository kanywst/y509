package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"crypto/x509"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"go.uber.org/zap"
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

// Formatting constants
const (
	// Border and padding
	borderPadding  = 2
	contentPadding = 4

	// Minimum widths for different display modes
	minUltraCompactWidth = 25
	minCompactWidth      = 40
	minMediumWidth       = 60

	// Label truncation
	labelPadding           = 8
	cnPadding              = 4
	subjectPadding         = 10
	scrollIndicatorPadding = 6

	// Status bar
	statusBarHeight  = 1
	commandBarHeight = 1
)

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

// SetDimensions sets the width and height of the model (for testing only)
func (m *Model) SetDimensions(width, height int) {
	m.width = width
	m.height = height
}

// SetReady sets the ready state of the model (for testing only)
func (m *Model) SetReady(ready bool) {
	m.ready = ready
}

// GetWidth returns the width of the model (for testing only)
func (m Model) GetWidth() int {
	return m.width
}

// GetHeight returns the height of the model (for testing only)
func (m Model) GetHeight() int {
	return m.height
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
func NewModel(certs []*certificate.CertificateInfo) *Model {
	return &Model{
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
	// スプラッシュスクリーンを表示するために少し待機
	return tea.Tick(time.Millisecond*500, func(t time.Time) tea.Msg {
		return SplashDoneMsg{}
	})
}

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
		if msg.String() == ":" {
			m.viewMode = ViewCommand
			m.commandInput = ""
			m.commandError = ""
			return m, nil
		}
	}
	return m, nil
}

// executeCommand processes the entered command
func (m Model) executeCommand() Model {
	cmd := strings.TrimSpace(m.commandInput)
	if cmd == "" {
		return m
	}

	m.commandError = ""

	logger.Log.Debug("executing command",
		zap.String("command", cmd))

	// Check if we have certificates for commands that require them
	if !m.hasValidCertificatesForCommand(cmd) {
		m.commandError = "No certificates available"
		logger.Log.Warn("no certificates available for command",
			zap.String("command", cmd))
		return m
	}

	// Handle global commands (don't require selected certificate)
	var handled bool
	m, handled = m.handleGlobalCommands(cmd)
	if handled {
		m.commandInput = "" // Always clear commandInput after global command
		return m
	}

	// Handle certificate-specific commands
	if len(m.certificates) == 0 || m.cursor >= len(m.certificates) {
		m.commandError = "No certificates available"
		logger.Log.Warn("no certificates available for certificate-specific command",
			zap.String("command", cmd))
		return m
	}

	// Execute certificate command
	m = m.handleCertificateCommands(cmd)

	// Clear command input after execution
	m.commandInput = ""
	return m
}

// hasValidCertificatesForCommand checks if we have certificates for the given command
func (m Model) hasValidCertificatesForCommand(cmd string) bool {
	globalCommands := []string{"search", "filter", "reset", "validate", "val", "export", "help", "h", "quit", "q"}

	for _, globalCmd := range globalCommands {
		if cmd == globalCmd || strings.HasPrefix(cmd, globalCmd+" ") {
			return true
		}
	}

	return len(m.certificates) > 0
}

// handleGlobalCommands processes commands that don't require a selected certificate
func (m Model) handleGlobalCommands(cmd string) (Model, bool) {
	logger.Log.Debug("handling global command",
		zap.String("command", cmd))
	switch {
	case strings.HasPrefix(cmd, "search "):
		query := strings.TrimSpace(cmd[7:])
		m = m.searchCertificates(query)
		m.viewMode = ViewNormal
		m.focus = FocusLeft
		return m, true
	case cmd == "reset":
		m = m.resetView()
		m.viewMode = ViewNormal
		m.focus = FocusLeft
		return m, true
	case strings.HasPrefix(cmd, "filter "):
		filterType := strings.TrimSpace(cmd[7:])
		m = m.filterCertificates(filterType)
		m.viewMode = ViewNormal
		m.focus = FocusLeft
		return m, true
	case cmd == "validate" || cmd == "val":
		m = m.handleValidateCommand()
		m.viewMode = ViewDetail
		m.focus = FocusRight
		return m, true
	case strings.HasPrefix(cmd, "export "):
		m = m.exportCertificate(cmd)
		m.viewMode = ViewDetail
		m.focus = FocusRight
		return m, true
	case cmd == "help" || cmd == "h":
		m = m.showHelpCommand()
		m.viewMode = ViewDetail
		m.focus = FocusRight
		return m, true
	case cmd == "quit" || cmd == "q":
		m.viewMode = ViewNormal
		m.focus = FocusLeft
		return m, true
	}
	return m, false
}

// handleCertificateCommands processes commands that require a selected certificate
func (m Model) handleCertificateCommands(cmd string) Model {
	if len(m.certificates) == 0 || m.cursor >= len(m.certificates) {
		m.commandError = "No certificates available"
		logger.Log.Warn("no certificates available for certificate-specific command",
			zap.String("command", cmd))
		return m
	}

	cert := m.certificates[m.cursor].Certificate
	logger.Log.Debug("handling certificate command",
		zap.String("command", cmd),
		zap.String("certificate", cert.Subject.CommonName))

	switch {
	case cmd == "subject" || cmd == "s":
		m = m.showDetail("Subject", certificate.FormatSubject(cert))
	case cmd == "issuer" || cmd == "i":
		m = m.showDetail("Issuer", certificate.FormatIssuer(cert))
	case cmd == "validity" || cmd == "v":
		m = m.showDetail("Validity", certificate.FormatValidity(cert))
	case cmd == "san":
		m = m.showDetail("Subject Alternative Names", certificate.FormatSAN(cert))
	case cmd == "fingerprint" || cmd == "fp":
		m = m.showDetail("SHA256 Fingerprint", certificate.FormatFingerprint(cert))
	case cmd == "serial":
		m = m.showDetail("Serial Number", cert.SerialNumber.String())
	case cmd == "pubkey" || cmd == "pk":
		m = m.showDetail("Public Key", certificate.FormatPublicKey(cert))
	case strings.HasPrefix(cmd, "goto ") || strings.HasPrefix(cmd, "g "):
		m.handleGotoCommand(cmd)
	default:
		m.commandError = fmt.Sprintf("Unknown command: %s (type 'help' for available commands)", cmd)
		logger.Log.Warn("unknown certificate command",
			zap.String("command", cmd))
	}
	return m
}

// handleValidateCommand processes the validate command
func (m Model) handleValidateCommand() Model {
	logger.Log.Debug("validating certificate chain")

	// Convert CertificateInfo to x509.Certificate
	certs := make([]*x509.Certificate, len(m.allCertificates))
	for i, cert := range m.allCertificates {
		certs[len(m.allCertificates)-1-i] = cert.Certificate // reverse: leaf→root
	}

	isValid, err := certificate.ValidateChain(certs)
	// Create ValidationResult
	result := &certificate.ValidationResult{
		IsValid: isValid,
	}

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	}

	// 検証結果を表示
	m = m.showDetail("Certificate Chain Validation", certificate.FormatChainValidation(result))
	m.viewMode = ViewDetail
	m.focus = FocusRight
	return m
}

// handleGotoCommand processes the goto command
func (m Model) handleGotoCommand(cmd string) Model {
	parts := strings.Fields(cmd)
	if len(parts) != 2 {
		m.commandError = "Usage: goto <number> or g <number>"
		logger.Log.Warn("invalid goto command format",
			zap.String("command", cmd))
		return m
	}

	index, err := strconv.Atoi(parts[1])
	if err != nil {
		m.commandError = "Invalid certificate number"
		logger.Log.Warn("invalid certificate number in goto command",
			zap.String("command", cmd),
			zap.Error(err))
		return m
	}

	if index < 1 || index > len(m.certificates) {
		m.commandError = "Invalid certificate number"
		logger.Log.Warn("certificate number out of range",
			zap.String("command", cmd),
			zap.Int("index", index),
			zap.Int("max", len(m.certificates)))
		return m
	}

	m.cursor = index - 1
	m.rightPaneScroll = 0 // Reset scroll when jumping to certificate
	m.viewMode = ViewNormal
	m.focus = FocusLeft
	logger.Log.Debug("goto command executed",
		zap.Int("new_cursor", m.cursor))
	return m
}

// showHelpCommand displays the help information
func (m Model) showHelpCommand() Model {
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

	m = m.showDetail("Commands", helpText)
	m.viewMode = ViewDetail
	m.focus = FocusRight
	return m
}

// searchCertificates searches certificates based on query
func (m Model) searchCertificates(query string) Model {
	if query == "" {
		m.commandError = "Search query cannot be empty"
		logger.Log.Warn("empty search query")
		return m
	}

	logger.Log.Debug("searching certificates",
		zap.String("query", query))

	m.searchQuery = query
	m.filterActive = true
	m.filterType = fmt.Sprintf("search: %s", query)
	m.cursor = 0
	m.viewMode = ViewNormal
	m.focus = FocusLeft

	// Filter certificates based on search query (Label, CommonName, Org, OU, DNS, Issuer)
	var filtered []*certificate.CertificateInfo
	queryLower := strings.ToLower(query)
	for _, cert := range m.allCertificates {
		if strings.Contains(strings.ToLower(cert.Label), queryLower) ||
			strings.Contains(strings.ToLower(cert.Certificate.Subject.CommonName), queryLower) ||
			strings.Contains(strings.ToLower(strings.Join(cert.Certificate.Subject.Organization, " ")), queryLower) ||
			strings.Contains(strings.ToLower(strings.Join(cert.Certificate.Subject.OrganizationalUnit, " ")), queryLower) ||
			strings.Contains(strings.ToLower(strings.Join(cert.Certificate.DNSNames, " ")), queryLower) ||
			strings.Contains(strings.ToLower(cert.Certificate.Issuer.CommonName), queryLower) {
			filtered = append(filtered, cert)
		}
	}

	if len(filtered) > 0 {
		m.certificates = filtered
	} else {
		m.commandError = fmt.Sprintf("No certificates found matching '%s'", query)
		logger.Log.Warn("no certificates found matching search query",
			zap.String("query", query))
	}
	return m
}

// filterCertificates filters certificates based on criteria
func (m Model) filterCertificates(filterType string) Model {
	validFilters := []string{"expired", "expiring", "valid", "self-signed"}
	found := false
	for _, f := range validFilters {
		if f == filterType {
			found = true
			break
		}
	}

	if !found {
		m.commandError = fmt.Sprintf("Invalid filter type: %s (valid: %s)", filterType, strings.Join(validFilters, ", "))
		logger.Log.Warn("invalid filter type",
			zap.String("filter_type", filterType),
			zap.Strings("valid_filters", validFilters))
		return m
	}

	logger.Log.Debug("filtering certificates",
		zap.String("filter_type", filterType))

	m.filterActive = true
	m.filterType = filterType
	m.cursor = 0
	m.viewMode = ViewNormal
	m.focus = FocusLeft

	// Filter certificates based on criteria
	var filtered []*certificate.CertificateInfo
	now := time.Now()

	for _, cert := range m.allCertificates {
		switch filterType {
		case "expired":
			if cert.Certificate.NotAfter.Before(now) {
				filtered = append(filtered, cert)
			}
		case "expiring":
			if cert.Certificate.NotAfter.After(now) && cert.Certificate.NotAfter.Before(now.AddDate(0, 0, 30)) {
				filtered = append(filtered, cert)
			}
		case "valid":
			if cert.Certificate.NotAfter.After(now) {
				filtered = append(filtered, cert)
			}
		case "self-signed":
			if cert.Certificate.Subject.CommonName == cert.Certificate.Issuer.CommonName {
				filtered = append(filtered, cert)
			}
		}
	}

	if len(filtered) > 0 {
		m.certificates = filtered
	} else {
		m.commandError = fmt.Sprintf("No certificates found with filter '%s'", filterType)
		logger.Log.Warn("no certificates found matching filter",
			zap.String("filter_type", filterType))
	}
	return m
}

// resetView resets search and filter
func (m Model) resetView() Model {
	logger.Log.Debug("resetting view")
	m = m.resetAllFields()
	m.certificates = m.allCertificates
	m.cursor = 0
	return m
}

// exportCertificate exports the current certificate
func (m Model) exportCertificate(cmd string) Model {
	if len(m.certificates) == 0 {
		m.commandError = "No certificate selected"
		logger.Log.Warn("no certificate selected for export")
		return m
	}

	parts := strings.Fields(cmd)
	if len(parts) != 3 {
		m.commandError = "Usage: export <format> <filename> (format: pem, der)"
		logger.Log.Warn("invalid export command format",
			zap.String("command", cmd))
		return m
	}

	format := strings.ToLower(parts[1])
	filename := parts[2]
	cert := m.certificates[m.cursor].Certificate

	logger.Log.Debug("exporting certificate",
		zap.String("format", format),
		zap.String("filename", filename),
		zap.String("certificate", cert.Subject.CommonName))

	err := certificate.ExportCertificate(cert, format, filename)
	if err != nil {
		m.commandError = fmt.Sprintf("Export failed: %v", err)
		logger.Log.Error("certificate export failed",
			zap.String("format", format),
			zap.String("filename", filename),
			zap.Error(err))
		return m
	}

	m = m.showDetail("Export Success", fmt.Sprintf("Certificate exported successfully!\n\nFormat: %s\nFile: %s\nCertificate: %s",
		strings.ToUpper(format), filename, cert.Subject.CommonName))
	m.viewMode = ViewDetail
	m.focus = FocusRight
	return m
}

// showDetail switches to detail view mode
func (m Model) showDetail(field, value string) Model {
	logger.Log.Debug("showing detail view",
		zap.String("field", field))
	m.viewMode = ViewDetail
	m.detailField = field
	m.detailValue = value
	m.focus = FocusRight
	return m
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
	mainHeight := m.height - statusBarHeight
	if m.viewMode == ViewCommand {
		mainHeight -= commandBarHeight
	}

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
	contentHeight := mainHeight - borderPadding
	if contentHeight < 1 {
		contentHeight = 1
	}

	if m.focus == FocusLeft {
		// Show certificate list
		content = m.renderCertificateList(contentHeight)
	} else {
		// Show certificate details
		content = m.renderCertificateDetails(m.width-contentPadding, contentHeight)
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
	if m.width < minMediumWidth {
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
	contentHeight := mainHeight - borderPadding
	if contentHeight < 1 {
		contentHeight = 1
	}

	leftContent := m.renderCertificateList(contentHeight)
	leftPane := m.createPane(leftContent, leftWidth, mainHeight, m.focus == FocusLeft, "")

	// Render right pane (certificate details) with scrolling
	rightContent := m.renderCertificateDetails(rightWidth-contentPadding, contentHeight)
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
				line = "⚠️ " + line
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

// getCertificateStatus returns the status icon and text for a certificate
func (m Model) getCertificateStatus(cert *certificate.CertificateInfo) (string, string) {
	if certificate.IsExpired(cert.Certificate) {
		return "❌", "EXPIRED"
	} else if certificate.IsExpiringSoon(cert.Certificate) {
		return "⚠️", "EXPIRING SOON"
	}
	return "✅", "VALID"
}

// renderCertificateDetails renders the details of the selected certificate with improved text handling
func (m Model) renderCertificateDetails(width, height int) string {
	if len(m.certificates) == 0 {
		return "No certificate selected"
	}

	cert := m.certificates[m.cursor]

	// Get appropriate details based on width
	var details string
	if width < minUltraCompactWidth {
		// Ultra compact details - only essential info
		statusIcon, _ := m.getCertificateStatus(cert)
		details = fmt.Sprintf("%s Cert %d/%d\n%s\n\nCN: %s\nExp: %s",
			statusIcon,
			m.cursor+1, len(m.certificates),
			truncateText(cert.Label, width-borderPadding),
			truncateText(cert.Certificate.Subject.CommonName, width-cnPadding),
			cert.Certificate.NotAfter.Format("2006-01-02"))
	} else if width < minCompactWidth {
		// Compact details with better organization
		statusIcon, statusText := m.getCertificateStatus(cert)

		details = fmt.Sprintf("%s %s\n%s\n\nSubject:\n%s\n\nIssuer:\n%s\n\nExpires:\n%s",
			statusIcon, statusText,
			truncateText(cert.Label, width-borderPadding),
			truncateText(cert.Certificate.Subject.CommonName, width-cnPadding),
			truncateText(cert.Certificate.Issuer.CommonName, width-cnPadding),
			cert.Certificate.NotAfter.Format("2006-01-02 15:04"))
	} else if width < minMediumWidth {
		// Medium details with better structure
		var builder strings.Builder

		// Header with status
		statusIcon, statusText := m.getCertificateStatus(cert)

		builder.WriteString(fmt.Sprintf("%s %s - Cert %d/%d\n", statusIcon, statusText, m.cursor+1, len(m.certificates)))
		builder.WriteString(fmt.Sprintf("%s\n", strings.Repeat("─", min(width-borderPadding, 30))))

		// Essential information
		builder.WriteString(fmt.Sprintf("Subject: %s\n", truncateText(cert.Certificate.Subject.CommonName, width-subjectPadding)))
		builder.WriteString(fmt.Sprintf("Issuer:  %s\n", truncateText(cert.Certificate.Issuer.CommonName, width-subjectPadding)))

		// Validity
		now := time.Now()
		if cert.Certificate.NotAfter.Before(now) {
			duration := now.Sub(cert.Certificate.NotAfter)
			days := int(duration.Hours() / 24)
			builder.WriteString(fmt.Sprintf("Expired: %d days ago\n", days))
		} else {
			duration := cert.Certificate.NotAfter.Sub(now)
			days := int(duration.Hours() / 24)
			builder.WriteString(fmt.Sprintf("Valid:   %d days left\n", days))
		}

		// DNS names if available
		if len(cert.Certificate.DNSNames) > 0 {
			builder.WriteString("DNS: ")
			if len(cert.Certificate.DNSNames) == 1 {
				builder.WriteString(truncateText(cert.Certificate.DNSNames[0], width-scrollIndicatorPadding))
			} else {
				builder.WriteString(fmt.Sprintf("%d names", len(cert.Certificate.DNSNames)))
			}
		}

		details = builder.String()
	} else {
		// Full details with proper formatting
		var builder strings.Builder

		// Header with certificate position and status
		statusIcon, statusText := m.getCertificateStatus(cert)
		now := time.Now()

		builder.WriteString(fmt.Sprintf("Certificate %d/%d %s %s\n",
			m.cursor+1, len(m.certificates), statusIcon, statusText))
		builder.WriteString(fmt.Sprintf("%s\n", strings.Repeat("─", min(width-borderPadding, 40))))

		// Subject information
		builder.WriteString("📋 Subject:\n")
		builder.WriteString(fmt.Sprintf("  Common Name: %s\n", cert.Certificate.Subject.CommonName))
		if len(cert.Certificate.Subject.Organization) > 0 {
			builder.WriteString(fmt.Sprintf("  Organization: %s\n", strings.Join(cert.Certificate.Subject.Organization, ", ")))
		}
		if len(cert.Certificate.Subject.OrganizationalUnit) > 0 {
			builder.WriteString(fmt.Sprintf("  Organizational Unit: %s\n", strings.Join(cert.Certificate.Subject.OrganizationalUnit, ", ")))
		}

		// Issuer information
		builder.WriteString("\n🏢 Issuer:\n")
		builder.WriteString(fmt.Sprintf("  Common Name: %s\n", cert.Certificate.Issuer.CommonName))
		if len(cert.Certificate.Issuer.Organization) > 0 {
			builder.WriteString(fmt.Sprintf("  Organization: %s\n", strings.Join(cert.Certificate.Issuer.Organization, ", ")))
		}

		// Validity information
		builder.WriteString("\n📅 Validity:\n")
		builder.WriteString(fmt.Sprintf("  Not Before: %s\n", cert.Certificate.NotBefore.Format("2006-01-02 15:04:05 MST")))
		builder.WriteString(fmt.Sprintf("  Not After:  %s\n", cert.Certificate.NotAfter.Format("2006-01-02 15:04:05 MST")))

		// Add days remaining/expired info
		if cert.Certificate.NotAfter.Before(now) {
			duration := now.Sub(cert.Certificate.NotAfter)
			days := int(duration.Hours() / 24)
			builder.WriteString(fmt.Sprintf("  Status: %s %s (Expired %d days ago)\n", statusIcon, statusText, days))
		} else {
			duration := cert.Certificate.NotAfter.Sub(now)
			days := int(duration.Hours() / 24)
			builder.WriteString(fmt.Sprintf("  Status: %s %s (Valid for %d days)\n", statusIcon, statusText, days))
		}

		// Subject Alternative Names
		builder.WriteString("\n🌐 Subject Alternative Names:\n")
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

		// Fingerprint and Serial Number
		builder.WriteString("\n🔒 SHA256 Fingerprint:\n")
		builder.WriteString(fmt.Sprintf("  %s\n", certificate.FormatFingerprint(cert.Certificate)))
		builder.WriteString(fmt.Sprintf("\n🔢 Serial Number: %s\n", cert.Certificate.SerialNumber.String()))

		details = builder.String()
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
	if len(lines) > height && width > 10 {
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

// 全フィールドをクリアする共通メソッド
func (m Model) resetAllFields() Model {
	logger.Log.Debug("resetting all fields")
	m.viewMode = ViewNormal
	m.focus = FocusLeft
	m.commandInput = ""
	m.commandError = ""
	m.detailField = ""
	m.detailValue = ""
	m.searchQuery = ""
	m.filterActive = false
	m.filterType = ""
	m.rightPaneScroll = 0
	return m
}
