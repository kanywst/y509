// Package model provides the core TUI application logic and view.
package model

import "strings"

// getMinimumSize returns the minimum required width and height for the TUI
func getMinimumSize() (int, int) {
	return 20, 6 // minimum 20 chars wide, 6 lines high
}

// truncateText truncates text to the given number of characters with an
// ellipsis. It counts and slices runes, not bytes, so multibyte names
// (CJK, IDNs) aren't cut mid-character.
func truncateText(text string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(text)
	if len(r) <= width {
		return text
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}
	return string(r[:width-3]) + "..."
}
