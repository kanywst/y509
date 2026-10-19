// Package model provides the core TUI application logic and view.
package model

import (
	"strings"

	"github.com/rivo/uniseg"
)

// getMinimumSize returns the minimum required width and height for the TUI
func getMinimumSize() (int, int) {
	return 20, 6 // minimum 20 chars wide, 6 lines high
}

// truncateText truncates text to the given number of terminal cells with an
// ellipsis. It measures display width by grapheme cluster, so a CJK name
// (two cells per character) fits its column and nothing is cut mid-character.
func truncateText(text string, width int) string {
	if width <= 0 {
		return ""
	}
	if uniseg.StringWidth(text) <= width {
		return text
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}
	return truncateWidth(text, width-3) + "..."
}

// truncateWidth is the longest prefix of text, in whole grapheme clusters,
// that is at most width cells wide.
func truncateWidth(text string, width int) string {
	var b strings.Builder
	used := 0
	g := uniseg.NewGraphemes(text)
	for g.Next() {
		if used+g.Width() > width {
			break
		}
		used += g.Width()
		b.WriteString(g.Str())
	}
	return b.String()
}
