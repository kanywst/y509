// Package cmd contains the command line interface for y509
package cmd

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kanywst/y509/internal/config"
	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/internal/model"
	"github.com/kanywst/y509/internal/version"
	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	// RootCmd represents the base command when called without any subcommands
	RootCmd = &cobra.Command{
		Use:   "y509",
		Short: "A certificate management tool",
		Long: `y509 is a certificate management tool that provides functionality for:
- Viewing certificate information
- Validating certificate chains
- Exporting certificates in various formats
- Managing certificate stores`,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			// Initialize logger
			logFile, err := cmd.Flags().GetString("log-file")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting log-file flag: %v\n", err)
				os.Exit(1)
			}
			debug, err := cmd.Flags().GetBool("debug")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting debug flag: %v\n", err)
				os.Exit(1)
			}
			if err := logger.Init(logFile, debug); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
				os.Exit(1)
			}
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	RootCmd.SetVersionTemplate("y509 version {{.Version}}\nBuild: " + version.GetFullVersion() + "\n")

	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Add flags
	RootCmd.PersistentFlags().StringP("input", "i", "", "Input file containing certificates (default: stdin)")
	RootCmd.PersistentFlags().String("log-file", "", "Path to the log file")
	RootCmd.PersistentFlags().Bool("debug", false, "Enable debug logging")

	// Add subcommands
	RootCmd.AddCommand(validateCmd)
	RootCmd.AddCommand(exportCmd)
	RootCmd.AddCommand(versionCmd)
	RootCmd.AddCommand(completionCmd)

	// Handle arguments
	RootCmd.Args = func(_ *cobra.Command, args []string) error {
		if len(args) > 1 {
			return fmt.Errorf("too many arguments")
		}
		return nil
	}
	// Set default behavior for no arguments
	RootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		// Load configuration
		cfg, err := config.LoadConfig()
		if err != nil {
			logger.Log.Error("Failed to load configuration", zap.Error(err))
			// We don't exit here, as we can run with default settings
		}
		var inputFile string
		if len(args) > 0 {
			inputFile = args[0]
		} else {
			var err error
			inputFile, err = cmd.Flags().GetString("input")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting input flag: %v\n", err)
				os.Exit(1)
			}
		}

		// Load certificates
		certs, err := certificate.LoadCertificates(inputFile)
		if err != nil {
			logger.Log.Error("Failed to load certificates", zap.Error(err))
			return err
		}

		// Create and run the TUI
		model := model.NewModel(certs, cfg)
		p := tea.NewProgram(
			model,
			tea.WithAltScreen(),
			tea.WithMouseCellMotion(),
		)

		if _, err := p.Run(); err != nil {
			logger.Log.Error("Failed to run TUI", zap.Error(err))
			return err
		}

		return nil
	}
}
