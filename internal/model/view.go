package model

import (
	"fmt"
	"math"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/kanywst/y509/pkg/certificate"
)

// View renders the model
func (m Model) View() tea.View {
	v := tea.NewView(m.viewContent())
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	return v
}

// viewContent renders the textual content for the current mode.
func (m Model) viewContent() string {
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

// renderHeader renders the application header with breadcrumb
func (m Model) renderHeader() string {
	// Title section
	titleIcon := "🔐"
	title := m.Styles.HeaderTitle.Render(titleIcon + " y509")

	// Breadcrumb
	var crumbs []string
	crumbs = append(crumbs, m.Styles.Breadcrumb.Render(fmt.Sprintf("%d certs", len(m.allCertificates))))

	if m.filterActive {
		crumbs = append(crumbs, m.Styles.Title.Render(m.filterType))
	}

	if idx := m.list.Index(); idx < len(m.certificates) {
		cn := m.certificates[idx].Certificate.Subject.CommonName
		if cn == "" {
			cn = "Unknown"
		}
		crumbs = append(crumbs, m.Styles.DetailValue.Render(truncateText(cn, 30)))
	}

	sep := m.Styles.BreadcrumbSep.String()
	breadcrumb := strings.Join(crumbs, sep)

	headerLine := lipgloss.JoinHorizontal(lipgloss.Center, title, "  ", breadcrumb)

	// Divider line
	divider := m.Styles.Dimmed.Render(strings.Repeat("─", m.width))

	return lipgloss.JoinVertical(lipgloss.Left, headerLine, divider)
}

// renderTwoPanes renders the left and right panes
func (m Model) renderTwoPanes() string {
	paneHeight := m.height - lipgloss.Height(m.renderHeader()) - lipgloss.Height(m.renderStatusBar())
	leftPaneWidth := m.width * 2 / 5
	rightPaneWidth := m.width - leftPaneWidth

	leftPane := m.renderLeftPane(leftPaneWidth, paneHeight)
	rightPane := m.renderRightPane(rightPaneWidth, paneHeight)

	return lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)
}

// renderLeftPane renders the certificate list pane backed by bubbles/list.
// The list itself is sized in Update via resizeComponents; this function
// is purely presentational.
func (m Model) renderLeftPane(width, height int) string {
	paneStyle := m.Styles.Pane
	if m.focus == FocusLeft {
		paneStyle = m.Styles.PaneFocus
	}
	paneStyle = paneStyle.BorderRight(false).Width(width).Height(height)

	innerWidth := width - PaneSideBorderWidth
	statusWidth := 4
	expiresWidth := 14
	subjectWidth := innerWidth - statusWidth - expiresWidth
	if subjectWidth < 10 {
		subjectWidth = 10
	}

	header := lipgloss.JoinHorizontal(lipgloss.Left,
		m.Styles.Dimmed.Bold(true).Width(statusWidth).Render("  "),
		m.Styles.Dimmed.Bold(true).Width(subjectWidth).Render("SUBJECT"),
		m.Styles.Dimmed.Bold(true).Width(expiresWidth).Render("EXPIRES"),
	)

	body := lipgloss.JoinVertical(lipgloss.Left, header, m.list.View())
	return paneStyle.Render(body)
}

// renderExpiryWithBar renders expiry info with a mini progress bar
func renderExpiryWithBar(certInfo *certificate.Info, styles Styles) string {
	cert := certInfo.Certificate
	d := time.Until(cert.NotAfter)

	if d < 0 {
		return styles.StatusExpired.Render("Expired")
	}

	days := int(d.Hours() / 24)
	totalDuration := cert.NotAfter.Sub(cert.NotBefore)
	if totalDuration <= 0 {
		totalDuration = time.Hour
	}

	ratio := d.Seconds() / totalDuration.Seconds()
	if ratio > 1 {
		ratio = 1
	} else if ratio < 0 {
		ratio = 0
	}

	barWidth := 6 // Fits well within the 14-char column width (6 + 1 + label)
	filled := int(ratio * float64(barWidth))
	if filled == 0 && days > 0 {
		filled = 1 // Show at least a minimal bar if active
	}

	var barStyle lipgloss.Style
	if days <= 30 {
		barStyle = styles.StatusWarning
	} else {
		barStyle = styles.StatusValid
	}

	bar := barStyle.Render(strings.Repeat("█", filled)) +
		styles.Dimmed.Render(strings.Repeat("░", barWidth-filled))

	label := fmt.Sprintf("%dd", days)
	// Right-align label for neat column
	return fmt.Sprintf("%s %4s", bar, label)
}

// renderRightPane renders the tabbed certificate details pane. The
// viewport is sized and populated in Update; here we only compose the
// already-rendered tab strip with the viewport view.
func (m Model) renderRightPane(width, height int) string {
	if m.list.Index() >= len(m.certificates) {
		return "No certificate selected."
	}

	tabs := m.renderTabs(width)
	const horizontalPadding = 2
	const verticalPadding = 1

	paddedContent := lipgloss.NewStyle().
		Padding(verticalPadding, horizontalPadding).
		Render(m.viewport.View())
	paneContent := lipgloss.JoinVertical(lipgloss.Left, tabs, paddedContent)

	paneStyle := m.Styles.Pane
	if m.focus == FocusRight {
		paneStyle = m.Styles.PaneFocus
	}
	return paneStyle.Width(width).Height(height).Render(paneContent)
}

// renderTabs renders the UI for switching between detail tabs with underline indicator
func (m Model) renderTabs(_ int) string {
	var renderedTabs []string
	for i, t := range m.tabs {
		if i == m.activeTab {
			label := m.Styles.TabActive.Render(t)
			underline := m.Styles.Title.Render(strings.Repeat("━", lipgloss.Width(t)+4))
			renderedTabs = append(renderedTabs, lipgloss.JoinVertical(lipgloss.Center, label, underline))
		} else {
			label := m.Styles.Tab.Render(t)
			spacer := lipgloss.NewStyle().Render(strings.Repeat(" ", lipgloss.Width(t)+4))
			renderedTabs = append(renderedTabs, lipgloss.JoinVertical(lipgloss.Center, label, spacer))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
}

// renderTabContent renders the content for the currently active tab.
// Width is used to size the inner column; vertical truncation is handled
// by the caller's viewport.
func (m Model) renderTabContent(width int) string {
	cert := m.certificates[m.list.Index()]
	var b strings.Builder

	kv := func(key, value string) {
		if value == "" {
			return
		}
		keyStyle := m.Styles.DetailKey.Width(16)
		valueStyle := m.Styles.DetailValue
		row := lipgloss.JoinHorizontal(lipgloss.Left,
			keyStyle.Render(key),
			valueStyle.Render(value),
		)
		b.WriteString(row + "\n")
	}

	switch m.tabs[m.activeTab] {
	case "Subject":
		kv("CN", cert.Certificate.Subject.CommonName)
		kv("Organization", strings.Join(cert.Certificate.Subject.Organization, ", "))
		kv("OU", strings.Join(cert.Certificate.Subject.OrganizationalUnit, ", "))
		kv("Country", strings.Join(cert.Certificate.Subject.Country, ", "))
		kv("Province", strings.Join(cert.Certificate.Subject.Province, ", "))
		kv("Locality", strings.Join(cert.Certificate.Subject.Locality, ", "))
	case "Issuer":
		kv("CN", cert.Certificate.Issuer.CommonName)
		kv("Organization", strings.Join(cert.Certificate.Issuer.Organization, ", "))
		kv("Country", strings.Join(cert.Certificate.Issuer.Country, ", "))
	case "Validity":
		notBefore := cert.Certificate.NotBefore.Format("2006-01-02 15:04:05 MST")
		notAfter := cert.Certificate.NotAfter.Format("2006-01-02 15:04:05 MST")
		kv("Not Before", notBefore)
		kv("Not After", notAfter)

		// Validity status badge
		b.WriteString("\n")
		d := time.Until(cert.Certificate.NotAfter)
		if d < 0 {
			b.WriteString(m.Styles.BadgeExpired.Render("  ✖ EXPIRED") + "\n")
		} else {
			days := int(d.Hours() / 24)
			if days <= 30 {
				b.WriteString(m.Styles.BadgeWarning.Render(fmt.Sprintf("  ▲ Expires in %d days", days)) + "\n")
			} else {
				b.WriteString(m.Styles.BadgeValid.Render(fmt.Sprintf("  ● Valid for %d days", days)) + "\n")
			}
		}

		// Expiry progress bar
		totalLife := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore).Hours() / 24
		elapsed := time.Since(cert.Certificate.NotBefore).Hours() / 24
		ratio := elapsed / math.Max(totalLife, 1)
		if ratio > 1 {
			ratio = 1
		}
		if ratio < 0 {
			ratio = 0
		}
		barWidth := 24
		filled := int(ratio * float64(barWidth))
		bar := m.Styles.ProgressFull.Render(strings.Repeat("█", filled)) +
			m.Styles.ProgressEmpty.Render(strings.Repeat("░", barWidth-filled))
		pct := fmt.Sprintf(" %.0f%% elapsed", ratio*100)
		b.WriteString("  " + bar + m.Styles.Dimmed.Render(pct) + "\n")

	case "SANs":
		hasSANs := false
		for _, dns := range cert.Certificate.DNSNames {
			kv("DNS", dns)
			hasSANs = true
		}
		for _, ip := range cert.Certificate.IPAddresses {
			kv("IP", ip.String())
			hasSANs = true
		}
		for _, email := range cert.Certificate.EmailAddresses {
			kv("Email", email)
			hasSANs = true
		}
		if !hasSANs {
			b.WriteString(m.Styles.Dimmed.Render("  No SANs present"))
		}
	case "Misc":
		kv("Serial", cert.Certificate.SerialNumber.String())
		kv("SHA256", certificate.FormatFingerprint(cert.Certificate))
		kv("Sig Algo", cert.Certificate.SignatureAlgorithm.String())
		b.WriteString("\n")
		b.WriteString(m.Styles.SectionTitle.Render("Public Key") + "\n")
		b.WriteString(certificate.FormatPublicKey(cert.Certificate) + "\n")

		// Chain position visualization
		b.WriteString("\n")
		b.WriteString(m.Styles.SectionTitle.Render("Chain Position") + "\n")
		b.WriteString(m.renderChainPosition(cert))
	}

	return lipgloss.NewStyle().Width(width).Render(b.String())
}

// renderChainPosition shows the certificate chain as a table, marking the
// current certificate with a leading caret. The table layout is provided
// by lipgloss/v2/table, including border and per-cell styling.
func (m Model) renderChainPosition(current *certificate.Info) string {
	currentRow := -1
	rows := make([][]string, 0, len(m.allCertificates))
	for i, cert := range m.allCertificates {
		cn := cert.Certificate.Subject.CommonName
		if cn == "" {
			cn = "(no CN)"
		}
		role := "Intermediate"
		switch {
		case i == 0:
			role = "Leaf"
		case i == len(m.allCertificates)-1 && cert.Certificate.Issuer.String() == cert.Certificate.Subject.String():
			role = "Root"
		}
		marker := " "
		if cert == current {
			marker = "►"
			currentRow = i
		}
		rows = append(rows, []string{marker, fmt.Sprintf("%d", i+1), role, cn})
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(m.Styles.ChainLine).
		Headers("", "#", "Type", "Subject").
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			base := lipgloss.NewStyle().Padding(0, 1)
			if row == table.HeaderRow {
				return base.Inherit(m.Styles.Dimmed.Bold(true))
			}
			if row == currentRow {
				return base.Inherit(m.Styles.Title.Bold(true))
			}
			if col == 0 {
				return base.Inherit(m.Styles.ChainNode)
			}
			return base.Inherit(m.Styles.Dimmed)
		})

	return t.Render()
}

func getStatusIconAndStyle(certInfo *certificate.Info, styles Styles) (string, lipgloss.Style) {
	switch certInfo.ValidationStatus {
	case certificate.StatusWarning:
		return "▲", styles.StatusWarning
	case certificate.StatusExpired:
		return "✖", styles.StatusExpired
	case certificate.StatusMismatchedIssuer, certificate.StatusInvalidSignature:
		return "◆", styles.StatusExpired
	default:
		return "●", styles.StatusValid
	}
}

func (m Model) renderStatusBar() string {
	// Left section: cert count and filter
	leftParts := []string{
		m.Styles.StatusBarKey.Render(fmt.Sprintf(" %d certs ", len(m.certificates))),
	}
	if m.filterActive {
		leftParts = append(leftParts, m.Styles.StatusBar.Foreground(lipgloss.Color(m.Config.Theme.StatusWarning)).Render(" ⏚ "+m.filterType+" "))
	}
	left := lipgloss.JoinHorizontal(lipgloss.Left, leftParts...)

	// Right section: keybinding hints
	hints := []struct{ key, desc string }{
		{"↑↓", "nav"},
		{"←→", "pane"},
		{"tab", "tabs"},
		{"/", "search"},
		{"f", "filter"},
		{"v", "validate"},
		{"?", "help"},
	}
	var hintParts []string
	for _, h := range hints {
		hintParts = append(hintParts,
			m.Styles.StatusBar.Bold(true).Render(h.key)+
				m.Styles.StatusBar.Render(" "+h.desc))
	}
	right := strings.Join(hintParts, m.Styles.StatusBar.Foreground(lipgloss.Color(m.Config.Theme.Border)).Render(" │ "))

	// Fill the middle with status bar background
	leftWidth := lipgloss.Width(left)
	rightWidth := lipgloss.Width(right)
	gap := max(0, m.width-leftWidth-rightWidth)
	middle := m.Styles.StatusBar.Render(strings.Repeat(" ", gap))

	return left + middle + right
}

func (m Model) renderHelpView() string {
	var content strings.Builder

	title := m.Styles.HeaderTitle.Render("🔐 y509 Help")
	content.WriteString(title + "\n\n")

	help := m.help
	help.ShowAll = true
	content.WriteString(help.View(m.keys))

	pane := m.Styles.PopupBorder.
		Width(56).
		Render(content.String())

	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(pane)
}

// renderMinimumSizeWarning renders a warning message when the terminal is too small
func (m Model) renderMinimumSizeWarning(minWidth, minHeight int) string {
	icon := "⚠"
	msg := fmt.Sprintf("%s Terminal too small\n\nMinimum: %dx%d\nCurrent: %dx%d", icon, minWidth, minHeight, m.width, m.height)
	return m.Styles.Warning.Width(m.width).Height(m.height).Align(lipgloss.Center, lipgloss.Center).Render(msg)
}

// renderPopup renders the modal popup box
func (m Model) renderPopup() string {
	var content string
	var title string
	var icon string

	switch {
	case m.popupType == PopupAlert:
		title = "Result"
		icon = "◈"
		content = m.popupMessage
	case m.popupType == PopupExport && m.exportForm != nil:
		title = "Export"
		icon = "📤"
		content = m.exportForm.View()
	default:
		switch m.popupType {
		case PopupSearch:
			title = "Search"
			icon = "🔍"
		case PopupFilter:
			title = "Filter"
			icon = "⏚"
		case PopupExport:
			title = "Export"
			icon = "📤"
		}
		content = m.textInput.View()
	}

	popupWidth := 60
	if m.width < 64 {
		popupWidth = m.width - 4
	}
	innerWidth := popupWidth - 6

	titleRendered := m.Styles.PopupTitle.Render(icon + "  " + title)
	divider := m.Styles.Dimmed.Render(strings.Repeat("─", innerWidth))

	var hint string
	if m.popupType == PopupAlert {
		hint = m.Styles.PopupHint.Render("Press Enter or Esc to dismiss")
	} else {
		hint = m.Styles.PopupHint.Render("Enter ⏎ confirm  ·  Esc cancel")
	}

	box := m.Styles.PopupBorder.
		Width(popupWidth).
		Render(
			lipgloss.JoinVertical(lipgloss.Left,
				titleRendered,
				divider,
				"",
				content,
				"",
				lipgloss.NewStyle().Width(innerWidth).Align(lipgloss.Center).Render(hint),
			),
		)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}
