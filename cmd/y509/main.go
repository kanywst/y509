package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kanywst/y509/internal/model"
	"github.com/kanywst/y509/pkg/certificate"
)

func main() {
	var filename string
	if len(os.Args) > 1 {
		filename = os.Args[1]
	}

	// Load certificates
	certs, err := certificate.LoadCertificates(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading certificates: %v\n", err)
		os.Exit(1)
	}

	// Create and run the TUI
	m := model.NewModel(certs)
	program := tea.NewProgram(m, tea.WithAltScreen())

	if _, err := program.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running program: %v\n", err)
		os.Exit(1)
	}
}
