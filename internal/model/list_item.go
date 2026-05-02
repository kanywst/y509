package model

import (
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
	styles Styles
}

func (d certDelegate) Height() int                             { return 1 }
func (d certDelegate) Spacing() int                            { return 0 }
func (d certDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }

func (d certDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	ci, ok := item.(certItem)
	if !ok {
		return
	}

	width := m.Width()
	statusWidth := 4
	expiresWidth := 14
	subjectWidth := width - statusWidth - expiresWidth
	if subjectWidth < 10 {
		subjectWidth = 10
	}

	statusIcon, statusStyle := getStatusIconAndStyle(ci.info, d.styles)
	expiresStr := renderExpiryWithBar(ci.info, d.styles)

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

// toListItems converts certificate slices to []list.Item.
func toListItems(certs []*certificate.Info) []list.Item {
	out := make([]list.Item, len(certs))
	for i, c := range certs {
		out[i] = certItem{info: c}
	}
	return out
}
