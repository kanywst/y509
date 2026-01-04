package model

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/pkg/certificate"
)

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
