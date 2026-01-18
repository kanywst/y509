package model

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/internal/version"
)

// Threshold constants for ASCII art display sizes
const (
	CompactArtWidthThreshold  = 45
	CompactArtHeightThreshold = 10

	MediumArtWidthThreshold  = 60
	MediumArtHeightThreshold = 12
)

// renderSplashScreen renders the y509 ASCII art splash screen with adaptive sizing
func (m Model) renderSplashScreen() string {
	// Get version dynamically
	ver := version.GetShortVersion()

	var asciiArt string

	// Adapt ASCII art based on terminal size
	if m.width < CompactArtWidthThreshold || m.height < CompactArtHeightThreshold {
		// Compact version for small terminals
		asciiArt = fmt.Sprintf(`
 ██   ██ ███████  ██████   █████  
  ████   ██       █████   ██   ██ 
   ██    ███████ ██    ██  █████  
                                 
   Certificate Chain TUI Viewer
                %s
    `, ver)
	} else if m.width < MediumArtWidthThreshold || m.height < MediumArtHeightThreshold {
		// Medium version
		asciiArt = fmt.Sprintf(`
██    ██ ███████  ██████   █████  
 ██  ██  ██      ██    ██ ██   ██ 
  ████   ███████ ██    ██  █████  
   ██         ██ ██    ██      ██ 
   ██    ███████  ██████   █████  
                                 
     Certificate Chain TUI Viewer
                 %s
    `, ver)
	} else {
		// Full version for larger terminals
		asciiArt = fmt.Sprintf(`
██    ██ ███████  ██████   █████  
 ██  ██  ██      ██    ██ ██   ██ 
  ████   ███████ ██    ██  █████  
   ██         ██ ██    ██      ██ 
   ██    ███████  ██████   █████  
                                          
         Certificate Chain TUI Viewer
                   %s
    `, ver)
	}

	// Center the ASCII art
	style := m.Styles.Title.
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Bold(true)

	return style.Render(asciiArt)
}
