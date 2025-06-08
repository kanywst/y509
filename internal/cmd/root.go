// Package cmd contains the command line interface for y509
package cmd

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/kanywst/y509/internal/model"
	"github.com/kanywst/y509/internal/version"
	"github.com/kanywst/y509/pkg/certificate"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "y509 [file]",
	Short: "Certificate Chain TUI Viewer",
	Long: `y509 is a terminal-based (TUI) certificate chain viewer.

It provides an interactive way to examine and validate X.509 certificate chains
with a user-friendly interface that adapts to the terminal size.`,
	Example: `  y509 certificate.pem         View certificates from a file
  cat certificate.pem | y509   Read certificates from stdin`,
	Run: func(cmd *cobra.Command, args []string) {
		// Get filename from args
		var filename string
		if len(args) > 0 {
			filename = args[0]
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
	},
	Version: version.GetVersion(),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// カスタムバージョン出力のフォーマットを設定
	RootCmd.SetVersionTemplate("y509 version {{.Version}}\nBuild: " + version.GetFullVersion() + "\n")

	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// フラグの追加などの初期化処理はここに記述
}
