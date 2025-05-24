package model

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/internal/version"
)

// renderSplashScreen renders the y509 ASCII art splash screen
func (m Model) renderSplashScreen() string {
	// Get version dynamically
	ver := version.GetShortVersion()

	asciiArt := fmt.Sprintf(`
██    ██ ███████  ██████   █████  
 ██  ██  ██      ██    ██ ██   ██ 
  ████   ███████ ██    ██  █████  
   ██         ██ ██    ██      ██ 
   ██    ███████  ██████   █████  
                                          
         Certificate Chain TUI Viewer
                   %s
    `, ver)

	// Center the ASCII art
	style := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Foreground(lipgloss.Color("62")).
		Bold(true)

	return style.Render(asciiArt)
}
