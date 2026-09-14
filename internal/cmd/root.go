// Package cmd contains the command line interface for y509
package cmd

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
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
	// Cobra only registers the --version flag when Version is non-empty.
	// Setting the template alone left --version and -v undefined, even though
	// the man page and the shell completions both advertised them.
	RootCmd.Version = version.GetVersion()
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
	RootCmd.PersistentFlags().String("log-file", "", logFileUsage())
	RootCmd.PersistentFlags().Bool("debug", false, "Enable debug logging")

	// Persistent, so `validate` and `export` can read from a live server too.
	RootCmd.PersistentFlags().String("connect", "", "Fetch the chain from a live server (host[:port])")
	RootCmd.PersistentFlags().String("servername", "", "SNI server name to send (default: the host)")
	RootCmd.PersistentFlags().String("starttls", "", "Upgrade a plaintext protocol first: "+
		strings.Join(certificate.StartTLSProtocols, ", "))
	RootCmd.PersistentFlags().Duration("timeout", certificate.DefaultConnectTimeout, "Timeout for a live connection")
	// Local rather than persistent: validate has its own --json, whose output
	// carries a trust verdict this one deliberately does not.
	RootCmd.Flags().Bool("json", false, "Print the chain as JSON instead of opening the TUI")
	RootCmd.PersistentFlags().String("password-file", "",
		"File holding the password for a PKCS#12 input (or set "+pkcs12PasswordEnv+")")

	// --starttls takes one of a fixed set, so offer them rather than leaving
	// the user to remember. The list is the same slice the help text and the
	// error message read from, so it cannot fall behind.
	if err := RootCmd.RegisterFlagCompletionFunc("starttls",
		func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			return certificate.StartTLSProtocols, cobra.ShellCompDirectiveNoFileComp
		}); err != nil {
		panic(err)
	}

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

		asJSON, err := cmd.Flags().GetBool("json")
		if err != nil {
			return err
		}
		if asJSON {
			// An inspection, not a verification: nothing here asserts trust,
			// and the exit status stays 0 for anything that parsed.
			return writeInspection(cmd.OutOrStdout(), source)
		}

		// Create and run the TUI
		model := model.NewModel(source.Certs, cfg)
		// The list can only show what parsed, so the header has to admit it
		// when that was not everything. Nothing may be printed here: stdout
		// belongs to the TUI.
		model.SetNotice(unparsedSummary(source.Unparsed))
		// And a row each, so the list accounts for everything the input held
		// rather than only what could be read.
		model.SetUnparsed(source.Unparsed)
		p := tea.NewProgram(model)

		if _, err := p.Run(); err != nil {
			logger.Log.Error("Failed to run TUI", zap.Error(err))
			return err
		}

		return nil
	}
}

func logFileUsage() string {
	if def := logger.DefaultLogFile(); def != "" {
		return "Path to the log file (default " + def + ")"
	}
	return "Path to the log file (no default without a user cache directory)"
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
	// Conn is the handshake the certificates arrived over, nil for a file or
	// stdin. It carries the negotiated version, the cipher suite and whether
	// OCSP was stapled, none of which the certificates themselves record.
	Conn *certificate.ConnectResult
	// Unparsed are the CERTIFICATE blocks that could not be read. They are
	// carried rather than dropped so a command can say the input held more
	// than it is showing.
	Unparsed []certificate.ParseFailure
}

// loadInput decides where the certificates come from: a live server, a file, or
// stdin.
func loadInput(cmd *cobra.Command, args []string) (*input, error) {
	target, err := cmd.Flags().GetString("connect")
	if err != nil {
		return nil, err
	}
	explicitConnect := target != ""

	// Both would name a source, and --connect would silently win. Rather than
	// quietly ignore the argument, say they conflict.
	if explicitConnect && len(args) > 0 {
		return nil, fmt.Errorf("give either --connect or a file/host argument, not both")
	}

	if target == "" && len(args) > 0 {
		target = args[0]
	}

	if explicitConnect || looksLikeHost(target) {
		result, err := connectFromFlags(cmd, target)
		if err != nil {
			return nil, err
		}
		return &input{Certs: result.Certificates, Host: result.ServerName, Conn: result}, nil
	}

	if target == "" {
		// Fall back to -i, then to stdin.
		target, err = cmd.Flags().GetString("input")
		if err != nil {
			return nil, err
		}
	}

	data, err := certificate.ReadInput(target)
	if err != nil {
		return nil, err
	}

	certs, unparsed, err := certificate.ParseCertificatesReport(data)
	if err == nil {
		return &input{Certs: certs, Unparsed: unparsed}, nil
	}

	// A PKCS#12 file reaches here because it is neither PEM nor a bare
	// certificate. It is tried last rather than first: it is the only format
	// that may need a password, and nothing else should provoke a prompt.
	p12, p12Err := loadPKCS12(cmd, data)
	if p12Err == nil {
		return &input{Certs: p12}, nil
	}
	// Report the PKCS#12 failure for anything shaped like one -- a password
	// problem, an encryption algorithm this cannot read, a truncated file.
	// Falling back to "not a certificate" would send the reader looking at the
	// wrong thing entirely.
	if errors.Is(p12Err, errPKCS12Needed) || certificate.LooksLikePKCS12(data) {
		return nil, p12Err
	}

	return nil, err
}

// writeInspection renders the chain as JSON instead of opening the TUI.
//
// This is the surface that makes a JSON view of a certificate possible at all:
// --json otherwise lives only on validate, where it is bound up with a trust
// verdict, so there was nowhere to put what the detail tabs show.
func writeInspection(w io.Writer, source *input) error {
	inputCerts := make([]*x509.Certificate, len(source.Certs))
	for i, c := range source.Certs {
		inputCerts[i] = c.Certificate
	}

	// Analyze what was presented, in the order it was presented.
	out := certificate.NewJSONInspection(source.Host, certificate.AnalyzeChain(inputCerts))
	out.Connection = certificate.NewJSONConnection(source.Conn)
	out.Unparsed = certificate.NewJSONUnparsed(source.Unparsed)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Subjects and SANs are attacker-controlled; Go's HTML escaping would
	// mangle them for no benefit outside a browser.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}
	return nil
}

// describeUnparsed summarises the blocks that could not be read, for a command
// that has to admit the input held more than it is showing. Empty when
// everything parsed.
func describeUnparsed(failures []certificate.ParseFailure) string {
	if len(failures) == 0 {
		return ""
	}

	noun := "certificates"
	if len(failures) == 1 {
		noun = "certificate"
	}
	positions := make([]string, 0, len(failures))
	for _, f := range failures {
		positions = append(positions, strconv.Itoa(f.Block))
	}

	return fmt.Sprintf("%d %s in the input could not be parsed (at %s): %v",
		len(failures), noun, strings.Join(positions, ", "), failures[0].Err)
}

// unparsedSummary is the short form for the TUI header, where there is one line
// and it sits beside the certificate count.
func unparsedSummary(failures []certificate.ParseFailure) string {
	if len(failures) == 0 {
		return ""
	}
	if len(failures) == 1 {
		return "1 unreadable certificate in the input"
	}
	return fmt.Sprintf("%d unreadable certificates in the input", len(failures))
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
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
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

	// A certificate extension means a file, even a mistyped one that does not
	// exist. "y509 chian.pem" should report "no such file", not a DNS failure
	// for a host called chian.pem.
	if hasCertExtension(target) {
		return false
	}

	// A bare word like "certs" is far likelier to be a mistyped filename than a
	// hostname. Require a dot (a domain) or a colon (a port).
	return strings.ContainsAny(target, ".:")
}

// certExtensions are the file suffixes that mean "this is a certificate file",
// so a missing one is reported as a missing file rather than dialled as a host.
var certExtensions = []string{".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".pfx", ".p12"}

func hasCertExtension(target string) bool {
	lower := strings.ToLower(target)
	for _, ext := range certExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
