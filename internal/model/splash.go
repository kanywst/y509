package model

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/internal/version"
)

// ASCIIアートの表示サイズ閾値の定数
const (
	// コンパクトバージョンの表示閾値（minimum screen requirements are 20x6）
	CompactArtWidthThreshold  = 45
	CompactArtHeightThreshold = 10
	
	// ミディアムバージョンの表示閾値
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
	style := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Foreground(lipgloss.Color("62")).
		Bold(true)

	return style.Render(asciiArt)
}
