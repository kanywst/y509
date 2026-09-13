package model

import (
	"fmt"
	"io"
	"strings"

	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/kanywst/y509/pkg/certificate"
)

// certItem wraps certificate.Info so the list package can manage selection
// and filter against the certificate Common Name.
type certItem struct {
	info *certificate.Info
}

func (c certItem) FilterValue() string {
	cn := c.info.Certificate.Subject.CommonName
	if cn == "" {
		return "(no CN)"
	}
	return cn
}

// certDelegate renders a single certificate row with the original three
// column layout (status icon, subject CN, expiry mini-bar). The focused
// pane is signalled by the surrounding border colour, so the delegate
// itself doesn't need to know which pane currently has focus.
type certDelegate struct {
	styles   Styles
	warnDays int
}

func (d certDelegate) Height() int                             { return 1 }
func (d certDelegate) Spacing() int                            { return 0 }
func (d certDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }

func (d certDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	if u, ok := item.(unparsedItem); ok {
		d.renderUnparsed(w, m, index, u)
		return
	}

	ci, ok := item.(certItem)
	if !ok || ci.info == nil || ci.info.Certificate == nil {
		return
	}

	width := m.Width()
	statusWidth := 4
	expiresWidth := 14
	subjectWidth := width - statusWidth - expiresWidth
	if subjectWidth < 10 {
		subjectWidth = 10
	}

	statusIcon, statusStyle := getStatusIconAndStyle(ci.info, d.styles, d.warnDays)
	expiresStr := renderExpiryWithBar(ci.info, d.styles, d.warnDays)

	var baseStyle lipgloss.Style
	switch {
	case index == m.Index():
		baseStyle = d.styles.Highlight
	case index%2 != 0:
		baseStyle = d.styles.ListRowAlt
	default:
		baseStyle = lipgloss.NewStyle()
	}

	sStyle := statusStyle.Background(baseStyle.GetBackground())
	sCol := sStyle.Width(statusWidth).Render(" " + statusIcon + " ")

	cn := ci.info.Certificate.Subject.CommonName
	if cn == "" {
		cn = "(no CN)"
	}
	cCol := baseStyle.Width(subjectWidth).Render(truncateText(cn, subjectWidth-1))

	eCol := baseStyle.Width(expiresWidth).Render(expiresStr)

	row := lipgloss.JoinHorizontal(lipgloss.Left, sCol, cCol, eCol)
	_, _ = io.WriteString(w, strings.TrimRight(row, "\n"))
}

// unparsedItem is a CERTIFICATE block that could not be read.
//
// It is a separate item type rather than an Info with a nil Certificate,
// because every renderer, the chain analysis and the JSON report dereference
// that field: one missed guard is a crashed TUI. A distinct type makes the
// compiler ask the question instead.
type unparsedItem struct {
	failure certificate.ParseFailure
}

func (u unparsedItem) FilterValue() string { return "unreadable certificate" }

// Label names the row and the detail pane heading.
func (u unparsedItem) Label() string {
	return fmt.Sprintf("unreadable certificate #%d", u.failure.Block+1)
}

// toListItems converts certificates, then the blocks that could not be read,
// to []list.Item.
//
// The unreadable ones come last and are never filtered out: a filter asks a
// question about a certificate ("expired", "self-signed") and there is no
// certificate here to answer it. Dropping the row would put the reader back
// where they started, looking at a list that quietly shows less than the file
// holds.
func toListItems(certs []*certificate.Info, unparsed []certificate.ParseFailure) []list.Item {
	out := make([]list.Item, 0, len(certs)+len(unparsed))
	for _, c := range certs {
		out = append(out, certItem{info: c})
	}
	for _, f := range unparsed {
		out = append(out, unparsedItem{failure: f})
	}
	return out
}

// renderUnparsed draws a row for a block that could not be read. It carries the
// expired colour and no expiry column: there is no validity period to report,
// and inventing one would be worse than an empty column.
func (d certDelegate) renderUnparsed(w io.Writer, m list.Model, index int, item unparsedItem) {
	width := m.Width()
	statusWidth := 4
	expiresWidth := 14
	subjectWidth := width - statusWidth - expiresWidth
	if subjectWidth < 10 {
		subjectWidth = 10
	}

	var baseStyle lipgloss.Style
	switch {
	case index == m.Index():
		baseStyle = d.styles.Highlight
	case index%2 != 0:
		baseStyle = d.styles.ListRowAlt
	default:
		baseStyle = lipgloss.NewStyle()
	}

	sStyle := d.styles.StatusExpired.Background(baseStyle.GetBackground())
	sCol := sStyle.Width(statusWidth).Render(" ? ")
	cCol := baseStyle.Width(subjectWidth).Render(truncateText(item.Label(), subjectWidth-1))
	eCol := baseStyle.Width(expiresWidth).Render("")

	row := lipgloss.JoinHorizontal(lipgloss.Left, sCol, cCol, eCol)
	_, _ = io.WriteString(w, strings.TrimRight(row, "\n"))
}
