// Package model provides the core TUI application logic and view.
package model

import (
	"strings"

	"github.com/kanywst/y509/internal/textwidth"
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
	if textwidth.Width(text) <= width {
		return text
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}
	return textwidth.Truncate(text, width-3) + "..."
}
