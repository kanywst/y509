// Package cmd contains the command line interface for y509
package cmd

import (
	"fmt"
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"
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
		Use:   "y509 [file | host:port]",
		Short: "A TUI for X.509 certificate chains",
		Long: `y509 opens a certificate chain in a terminal UI.

The chain can come from a file, from stdin, or from a live server:

  y509 chain.pem
  y509 example.com:443
  y509 smtp.example.com:587 --starttls smtp
  openssl s_client -connect example.com:443 -showcerts | y509

An argument that names an existing file is always read as a file. Otherwise it
is treated as an address; pass --connect to force that.`,
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
			certificate.SetLogger(logger.Log)
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	RootCmd.SetVersionTemplate("y509 version {{.Version}}\nBuild: " + version.GetFullVersion() + "\n")

	// Cobra prints the error itself and then dumps the usage text. For a
	// runtime failure -- an unreadable file, a chain that does not verify --
	// neither is wanted: the usage text is noise, and Execute below is the one
	// printer. Cobra still reports genuine usage errors (unknown flags) through
	// the returned error.
	RootCmd.SilenceErrors = true
	RootCmd.SilenceUsage = true

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

	// Persistent, so `validate` and `export` can read from a live server too.
	RootCmd.PersistentFlags().String("connect", "", "Fetch the chain from a live server (host[:port])")
	RootCmd.PersistentFlags().String("servername", "", "SNI server name to send (default: the host)")
	RootCmd.PersistentFlags().String("starttls", "", "Upgrade a plaintext protocol first: "+
		strings.Join(certificate.StartTLSProtocols, ", "))
	RootCmd.PersistentFlags().Duration("timeout", certificate.DefaultConnectTimeout, "Timeout for a live connection")

	// Subcommands register themselves in their own init().

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

		source, err := loadInput(cmd, args)
		if err != nil {
			logger.Log.Error("Failed to load certificates", zap.Error(err))
			return err
		}

		// Create and run the TUI
		model := model.NewModel(source.Certs, cfg)
		p := tea.NewProgram(model)

		if _, err := p.Run(); err != nil {
			logger.Log.Error("Failed to run TUI", zap.Error(err))
			return err
		}

		return nil
	}
}

// input is where a command's certificates came from.
type input struct {
	// Certs are the certificates, leaf first. When they came from a server this
	// is the order the server sent them in, which is not necessarily valid.
	Certs []*certificate.Info
	// Host is the server that was contacted, empty for a file or stdin. It
	// gives validate a hostname to check the leaf against, which is the whole
	// question when you are looking at a live endpoint.
	Host string
}

// loadInput decides where the certificates come from: a live server, a file, or
// stdin.
func loadInput(cmd *cobra.Command, args []string) (*input, error) {
	target, err := cmd.Flags().GetString("connect")
	if err != nil {
		return nil, err
	}
	explicitConnect := target != ""

	if target == "" && len(args) > 0 {
		target = args[0]
	}

	if explicitConnect || looksLikeHost(target) {
		result, err := connectFromFlags(cmd, target)
		if err != nil {
			return nil, err
		}
		return &input{Certs: result.Certificates, Host: result.ServerName}, nil
	}

	if target == "" {
		// Fall back to -i, then to stdin.
		target, err = cmd.Flags().GetString("input")
		if err != nil {
			return nil, err
		}
	}

	certs, err := certificate.LoadCertificates(target)
	if err != nil {
		return nil, err
	}
	return &input{Certs: certs}, nil
}

// connectFromFlags fetches a chain from a live server.
func connectFromFlags(cmd *cobra.Command, target string) (*certificate.ConnectResult, error) {
	var opts certificate.ConnectOptions
	var err error

	if opts.ServerName, err = cmd.Flags().GetString("servername"); err != nil {
		return nil, err
	}
	if opts.StartTLS, err = cmd.Flags().GetString("starttls"); err != nil {
		return nil, err
	}
	if opts.Timeout, err = cmd.Flags().GetDuration("timeout"); err != nil {
		return nil, err
	}

	return certificate.FetchChain(cmd.Context(), target, opts)
}

// looksLikeHost decides whether an argument names a server rather than a file.
//
// Getting this wrong is worse than it sounds: a mistyped path answered with a
// DNS failure tells the user nothing about what actually went wrong. So the
// rule leans towards "file", and only what unambiguously reads as an address
// goes to the network. --connect forces the issue either way.
func looksLikeHost(target string) bool {
	if target == "" {
		return false
	}

	// An existing file always wins, so a file genuinely named "example.com:443"
	// still opens as a file. A stat error that is not "no such file" -- a
	// permission problem, say -- means something is there, and the user meant
	// it; let the file path report the real error.
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		return false
	}

	if strings.Contains(target, "://") {
		return true
	}

	// localhost is the one bare word that is far likelier to be a host than a
	// file -- it is the obvious target for local development, and it carries
	// neither the dot nor the colon the fallback below looks for.
	if target == "localhost" {
		return true
	}

	// Anything shaped like a path is a path, even a missing one. "./chain.pem"
	// and "/etc/ssl/cert.pem" both contain a dot, and answering a typo in
	// either with a failed DNS lookup would be baffling.
	if strings.ContainsAny(target, `/\`) {
		return false
	}

	// A bare word like "certs" is far likelier to be a mistyped filename than a
	// hostname. Require a dot (a domain) or a colon (a port).
	return strings.ContainsAny(target, ".:")
}
