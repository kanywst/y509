package model

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/pkg/certificate"
)

// View renders the model
func (m Model) View() string {
	if !m.ready {
		return "Initializing..."
	}
	minWidth, minHeight := getMinimumSize()
	if m.width < minWidth || m.height < minHeight {
		return m.renderMinimumSizeWarning(minWidth, minHeight)
	}

	switch m.viewMode {
	case ViewSplash:
		return m.renderSplashScreen()
	case ViewHelp:
		return m.renderHelpView()
	case ViewPopup:
		return m.renderPopup()
	default:
		return m.renderNormalView()
	}
}

// renderNormalView renders the main view with header, panes, and status bar
func (m Model) renderNormalView() string {
	if len(m.certificates) == 0 {
		return "No certificates found."
	}

	header := m.renderHeader()
	panes := m.renderTwoPanes()
	statusBar := m.renderStatusBar()

	headerHeight := lipgloss.Height(header)
	statusBarHeight := lipgloss.Height(statusBar)
	panesHeight := m.height - headerHeight - statusBarHeight

	mainContent := lipgloss.NewStyle().Height(panesHeight).Render(panes)

	return lipgloss.JoinVertical(lipgloss.Left, header, mainContent, statusBar)
}

// renderHeader renders the application header
func (m Model) renderHeader() string {
	title := m.Styles.Title.Render("y509 - Certificate Viewer")
	line := lipgloss.NewStyle().
		Width(m.width).
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(lipgloss.Color("236")).
		Render("")
	return lipgloss.JoinVertical(lipgloss.Left, title, line)
}

// renderTwoPanes renders the left and right panes
func (m Model) renderTwoPanes() string {
	paneHeight := m.height - lipgloss.Height(m.renderHeader()) - lipgloss.Height(m.renderStatusBar())
	leftPaneWidth := m.width / 2
	rightPaneWidth := m.width - leftPaneWidth

	leftPane := m.renderLeftPane(leftPaneWidth, paneHeight)
	rightPane := m.renderRightPane(rightPaneWidth, paneHeight)

	return lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)
}

// renderLeftPane renders the certificate list pane
func (m Model) renderLeftPane(width, height int) string {
	paneStyle := m.Styles.Pane
	if m.focus == FocusLeft {
		paneStyle = m.Styles.PaneFocus
	}
	paneStyle = paneStyle.BorderRight(false).Width(width).Height(height)

	innerWidth := width - 1

	var b strings.Builder

	statusWidth := 8
	expiresWidth := 12
	subjectWidth := innerWidth - statusWidth - expiresWidth

	header := lipgloss.JoinHorizontal(lipgloss.Left,
		m.Styles.Title.Bold(true).Width(statusWidth).Render(" STATUS"),
		m.Styles.Title.Bold(true).Width(subjectWidth).Render("SUBJECT"),
		m.Styles.Title.Bold(true).Width(expiresWidth).Render("EXPIRES"),
	)
	b.WriteString(header)
	b.WriteString("\n")

	// Calculate visible range
	availableHeight := height - ListHeaderHeight
	if availableHeight <= 0 {
		return paneStyle.Render(b.String())
	}

	start := m.listScroll
	end := start + availableHeight
	if end > len(m.certificates) {
		end = len(m.certificates)
	}

	for i := start; i < end; i++ {
		certInfo := m.certificates[i]
		statusIcon, statusStyle := getStatusIconAndStyle(certInfo, m.Styles)
		expiresIn := humanizeDuration(time.Until(certInfo.Certificate.NotAfter))

		var baseStyle lipgloss.Style
		isCursor := i == m.cursor
		if isCursor {
			if m.focus == FocusLeft {
				baseStyle = m.Styles.Highlight
			} else {
				baseStyle = m.Styles.HighlightDim
			}
		} else if i%2 != 0 {
			baseStyle = m.Styles.ListRowAlt
		} else {
			baseStyle = lipgloss.NewStyle()
		}

		// Icon column
		sStyle := statusStyle.Background(baseStyle.GetBackground())
		sCol := sStyle.Width(statusWidth).Render(" " + statusIcon)

		// Subject column
		cCol := baseStyle.Width(subjectWidth).Render(truncateText(certInfo.Certificate.Subject.CommonName, subjectWidth-1))

		// Expires column
		eCol := baseStyle.Width(expiresWidth).Render(expiresIn)

		row := lipgloss.JoinHorizontal(lipgloss.Left, sCol, cCol, eCol)

		b.WriteString(row)
		b.WriteString("\n")
	}

	return paneStyle.Render(b.String())
}

// renderRightPane renders the tabbed certificate details pane
func (m Model) renderRightPane(width, height int) string {
	if m.cursor >= len(m.certificates) {
		return "No certificate selected."
	}

	tabs := m.renderTabs(width)
	content := m.renderTabContent(width, height-lipgloss.Height(tabs)-1)

	paddedContent := lipgloss.NewStyle().Padding(1, 2).Render(content)

	paneContent := lipgloss.JoinVertical(lipgloss.Left, tabs, paddedContent)

	paneStyle := m.Styles.Pane
	if m.focus == FocusRight {
		paneStyle = m.Styles.PaneFocus
	}
	return paneStyle.Width(width).Height(height).Render(paneContent)
}

// renderTabs renders the UI for switching between detail tabs
func (m Model) renderTabs(_ int) string {
	var renderedTabs []string
	for i, t := range m.tabs {
		style := m.Styles.Tab
		if i == m.activeTab {
			style = m.Styles.TabActive
		}
		renderedTabs = append(renderedTabs, style.Render(t))
		if i < len(m.tabs)-1 {
			renderedTabs = append(renderedTabs, m.Styles.TabSeparator.String())
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
}

// renderTabContent renders the content for the currently active tab
func (m Model) renderTabContent(width, height int) string {
	cert := m.certificates[m.cursor]
	var b strings.Builder

	kv := func(key, value string) {
		if value == "" {
			return
		}
		keyStyle := m.Styles.DetailKey.Width(16)
		valueStyle := lipgloss.NewStyle()
		row := lipgloss.JoinHorizontal(lipgloss.Left,
			keyStyle.Render(key),
			valueStyle.Render(value),
		)
		b.WriteString(row + "\n")
	}

	switch m.tabs[m.activeTab] {
	case "Subject":
		kv("CN:", cert.Certificate.Subject.CommonName)
		kv("Organization:", strings.Join(cert.Certificate.Subject.Organization, ", "))
		kv("OU:", strings.Join(cert.Certificate.Subject.OrganizationalUnit, ", "))
		kv("Country:", strings.Join(cert.Certificate.Subject.Country, ", "))
		kv("Province:", strings.Join(cert.Certificate.Subject.Province, ", "))
		kv("Locality:", strings.Join(cert.Certificate.Subject.Locality, ", "))
	case "Issuer":
		kv("CN:", cert.Certificate.Issuer.CommonName)
		kv("Organization:", strings.Join(cert.Certificate.Issuer.Organization, ", "))
		kv("Country:", strings.Join(cert.Certificate.Issuer.Country, ", "))
	case "Validity":
		kv("Not Before:", cert.Certificate.NotBefore.Format("2006-01-02 15:04:05 MST"))
		kv("Not After:", cert.Certificate.NotAfter.Format("2006-01-02 15:04:05 MST"))
	case "SANs":
		for _, dns := range cert.Certificate.DNSNames {
			kv("DNS Name:", dns)
		}
		for _, ip := range cert.Certificate.IPAddresses {
			kv("IP Address:", ip.String())
		}
		for _, email := range cert.Certificate.EmailAddresses {
			kv("Email:", email)
		}
		if len(cert.Certificate.DNSNames) == 0 && len(cert.Certificate.IPAddresses) == 0 && len(cert.Certificate.EmailAddresses) == 0 {
			b.WriteString("None")
		}
	case "Misc":
		kv("Serial:", cert.Certificate.SerialNumber.String())
		kv("SHA256 Fgp:", certificate.FormatFingerprint(cert.Certificate))
		b.WriteString(m.Styles.DetailKey.Render("Public Key:") + "\n")
		b.WriteString(certificate.FormatPublicKey(cert.Certificate) + "\n")
	}

	content := b.String()
	lines := strings.Split(content, "\n")
	start := m.rightPaneScroll
	end := start + height
	if start > len(lines) {
		start = len(lines)
	}
	if end > len(lines) {
		end = len(lines)
	}

	return lipgloss.NewStyle().Width(width).Render(strings.Join(lines[start:end], "\n"))
}

func getStatusIconAndStyle(certInfo *certificate.Info, styles Styles) (string, lipgloss.Style) {
	switch certInfo.ValidationStatus {
	case certificate.StatusWarning:
		return "⚠️", styles.StatusWarning
	case certificate.StatusExpired:
		return "❌", styles.StatusExpired
	case certificate.StatusMismatchedIssuer, certificate.StatusInvalidSignature:
		return "🔗", styles.StatusExpired
	default:
		return "✅", styles.StatusValid
	}
}

func (m Model) renderStatusBar() string {
	certInfo := fmt.Sprintf("Certs: %d", len(m.certificates))
	helpText := "↑/↓: navigate • ←/→: panes • tab: tabs • /: search • f: filter • v: validate • q: quit"
	statusText := fmt.Sprintf("%s • %s", certInfo, helpText)
	return m.Styles.StatusBar.Width(m.width).Render(statusText)
}

func humanizeDuration(d time.Duration) string {
	if d < 0 {
		return "Expired"
	}
	days := int(d.Hours() / 24)
	if days > 0 {
		return fmt.Sprintf("in %d days", days)
	}
	return "today"
}

func (m Model) renderHelpView() string {
	var content strings.Builder

	title := m.Styles.Title.Bold(true).Render("── Help ──")
	content.WriteString(title + "\n\n")

	content.WriteString(m.Styles.Title.Render("Keybindings") + "\n")
	content.WriteString("  ↑/k, ↓/j      Navigate list\n")
	content.WriteString("  ←/h, →/l      Switch panes\n")
	content.WriteString("  tab            Switch tabs\n")
	content.WriteString("  /              Search (Popup)\n")
	content.WriteString("  f              Filter (Popup: expired, expiring, valid, self-signed)\n")
	content.WriteString("  v              Validate Chain (Popup)\n")
	content.WriteString("  e              Export Certificate (Popup)\n")
	content.WriteString("  q, ctrl+c      Quit\n")

	pane := m.Styles.PaneFocus.
		Width(60).
		Padding(1, 2).
		Render(content.String())

	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(pane)
}

// renderMinimumSizeWarning renders a warning message when the terminal is too small
func (m Model) renderMinimumSizeWarning(minWidth, minHeight int) string {
	warning := fmt.Sprintf("Terminal too small! Minimum: %dx%d", minWidth, minHeight)
	return m.Styles.Warning.Width(m.width).Height(m.height).Align(lipgloss.Center, lipgloss.Center).Render(warning)
}

// renderPopup renders the modal popup box using lipgloss.Place (screen clear)
func (m Model) renderPopup() string {
	var content string
	var title string

	if m.popupType == PopupAlert {
		title = "Validation Result"
		content = m.popupMessage
	} else {
		// Input popup
		switch m.popupType {
		case PopupSearch:
			title = "Search"
		case PopupFilter:
			title = "Filter"
		case PopupExport:
			title = "Export Certificate"
		}
		content = m.textInput.View()
	}

	popupWidth := 60
	if m.width < 64 {
		popupWidth = m.width - 4
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(m.Config.Theme.BorderFocus)).
		Padding(1, 2).
		Width(popupWidth).
		Render(
			lipgloss.JoinVertical(lipgloss.Left,
				lipgloss.NewStyle().Width(popupWidth-4).Align(lipgloss.Center).Render(title),
				"\n",
				content,
				"\n",
				lipgloss.NewStyle().Width(popupWidth-4).Align(lipgloss.Center).Foreground(lipgloss.Color("240")).Render("Enter to confirm, Esc to cancel"),
			),
		)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}
