package model

import (
	"fmt"

	"charm.land/lipgloss/v2"
	"github.com/kanywst/y509/internal/version"
)

// Threshold constants for ASCII art display sizes
const (
	CompactArtWidthThreshold  = 45
	CompactArtHeightThreshold = 10

	MediumArtWidthThreshold  = 60
	MediumArtHeightThreshold = 14
)

// renderSplashScreen renders the y509 ASCII art splash screen with adaptive sizing
func (m Model) renderSplashScreen() string {
	ver := version.GetShortVersion()

	var asciiArt string
	var subtitle string

	if m.width < CompactArtWidthThreshold || m.height < CompactArtHeightThreshold {
		asciiArt = `
 ██   ██ ███████  ██████   █████
  ████   ██       █████   ██   ██
   ██    ███████ ██    ██  █████  `
		subtitle = fmt.Sprintf("Certificate Chain TUI Viewer  %s", ver)
	} else if m.width < MediumArtWidthThreshold || m.height < MediumArtHeightThreshold {
		asciiArt = `
██    ██ ███████  ██████   █████
 ██  ██  ██      ██    ██ ██   ██
  ████   ███████ ██    ██  █████
   ██         ██ ██    ██      ██
   ██    ███████  ██████   █████  `
		subtitle = fmt.Sprintf("Certificate Chain TUI Viewer  %s", ver)
	} else {
		asciiArt = `
██    ██ ███████  ██████   █████
 ██  ██  ██      ██    ██ ██   ██
  ████   ███████ ██    ██  █████
   ██         ██ ██    ██      ██
   ██    ███████  ██████   █████  `
		subtitle = fmt.Sprintf("🔐  Certificate Chain TUI Viewer\n%s", ver)
	}

	artStyle := m.Styles.Title.Bold(true)
	subtitleStyle := m.Styles.Dimmed

	rendered := lipgloss.JoinVertical(lipgloss.Center,
		artStyle.Render(asciiArt),
		"",
		subtitleStyle.Render(subtitle),
	)

	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(rendered)
}
