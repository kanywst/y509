package model

import "strings"

// calculateAvailableWidth calculates the available width for display elements
// based on the current screen width and view mode (single or dual pane)
func (m Model) calculateAvailableWidth() int {
	if m.shouldUseSinglePane() {
		return m.width - 4 // subtract padding/borders for single pane
	}

	// In dual pane mode, calculate left pane width
	if m.width < 60 {
		return max(12, m.width*2/5) - 4 // subtract padding/borders
	}
	return m.width/3 - 4
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getMinimumSize returns the minimum required width and height for the TUI
func getMinimumSize() (int, int) {
	return 20, 6 // minimum 20 chars wide, 6 lines high
}

// shouldUseSinglePane determines if single pane mode should be used
func (m Model) shouldUseSinglePane() bool {
	minWidth, _ := getMinimumSize()
	return m.width < minWidth*2 // Use single pane if less than 40 chars wide
}

// wrapText wraps text to fit within the specified width
func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	var lines []string
	var currentLine strings.Builder

	for _, word := range words {
		// If adding this word would exceed width, start new line
		if currentLine.Len() > 0 && currentLine.Len()+1+len(word) > width {
			lines = append(lines, currentLine.String())
			currentLine.Reset()
		}

		// Add word to current line
		if currentLine.Len() > 0 {
			currentLine.WriteString(" ")
		}
		currentLine.WriteString(word)
	}

	// Add the last line
	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}

	return strings.Join(lines, "\n")
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
