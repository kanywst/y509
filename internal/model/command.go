package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"crypto/x509"

	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"go.uber.org/zap"
)

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
