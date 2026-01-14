// Package model provides the core TUI application logic and view.
package model

import "strings"

// getMinimumSize returns the minimum required width and height for the TUI
func getMinimumSize() (int, int) {
	return 20, 6 // minimum 20 chars wide, 6 lines high
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
