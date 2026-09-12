// Package cmd contains the command line interface for y509
package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"strconv"

	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var exportCmd = &cobra.Command{
	Use:   "export [index] [format] [filename]",
	Short: "Export a certificate to a file",
	Long: `Export a certificate to a file in the specified format.
Format can be 'pem', 'der', 'crt', or 'cert' (crt and cert are written as PEM).
If no index is provided, the first certificate will be exported.
If no format is provided, 'pem' will be used.
If no filename is provided, a default name will be generated.

The chain comes from the same places as every other command: --connect for a
live server, -i/--input for a file, or stdin. The positional arguments select
what to write out, not where to read from.

  y509 export -i chain.pem 1                   # the second certificate, as PEM
  y509 export --connect example.com:443 0 der   # the leaf a server presented
  cat chain.pem | y509 export --all bundle.pem  # the whole chain, one file`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// nil args, not args: export's positional arguments select a
		// certificate, they do not name the source. Everything else -- the
		// --connect/--starttls/--servername/--timeout set, -i, stdin -- resolves
		// exactly as it does for the TUI and for validate.
		source, err := loadInput(cmd, nil)
		if err != nil {
			logger.Log.Error("Failed to load certificates", zap.Error(err))
			return err
		}
		certs := source.Certs

		if len(certs) == 0 {
			logger.Log.Error("No certificates available")
			return fmt.Errorf("no certificates available")
		}

		exportAll, err := cmd.Flags().GetBool("all")
		if err != nil {
			return err
		}

		if exportAll {
			return exportBundle(certs, args)
		}

		index, err := certificateIndex(args, len(certs))
		if err != nil {
			logger.Log.Error("Invalid certificate index", zap.Error(err))
			return err
		}

		format := "pem"
		if len(args) > 1 {
			format = args[1]
		}

		filename := fmt.Sprintf("certificate_%d.%s", index, format)
		if len(args) > 2 {
			filename = args[2]
		}

		// ExportCertificate creates the parent directory itself.
		if err := certificate.ExportCertificate(certs[index].Certificate, format, filename); err != nil {
			logger.Log.Error("Failed to export certificate", zap.Error(err))
			return fmt.Errorf("failed to export certificate: %v", err)
		}

		logger.Log.Info("Certificate exported successfully", zap.String("filename", filename))
		return nil
	},
}

// exportBundle writes the whole chain to one PEM file. With --all the first
// positional argument is the filename, since there is no certificate to select
// and no format to choose.
func exportBundle(certs []*certificate.Info, args []string) error {
	// Accepting and ignoring an index or a format here would be worse than
	// refusing them: `export --all 0 der out.pem` reads as if it would write
	// DER, and it cannot.
	if len(args) > 1 {
		return fmt.Errorf(
			"--all takes only a filename, got %d arguments: a bundle has no certificate to select and is always PEM",
			len(args))
	}

	filename := "chain.pem"
	if len(args) > 0 {
		filename = args[0]
	}

	chain := make([]*x509.Certificate, len(certs))
	for i, c := range certs {
		chain[i] = c.Certificate
	}

	if err := certificate.ExportChain(chain, filename); err != nil {
		logger.Log.Error("Failed to export chain", zap.Error(err))
		return fmt.Errorf("failed to export chain: %v", err)
	}

	logger.Log.Info("Chain exported successfully",
		zap.String("filename", filename), zap.Int("certificates", len(chain)))
	return nil
}

// certificateIndex reads the certificate to export from the positional
// arguments.
//
// A file path here is the mistake worth naming outright: `y509 export
// chain.pem` reads as "export this file" but the first argument is an index, so
// the old behaviour was a confusing parse error -- or, with --connect, a
// silently wrong export of whatever was on stdin.
func certificateIndex(args []string, count int) (int, error) {
	if len(args) == 0 {
		return 0, nil
	}

	index, err := strconv.Atoi(args[0])
	if err != nil {
		if looksLikeSource(args[0]) {
			return 0, fmt.Errorf(
				"%q names a source, not a certificate: pass a file with -i/--input or a server with --connect, "+
					"and use the positional arguments to choose what to write",
				args[0])
		}
		return 0, fmt.Errorf("invalid certificate index: %q is not a number", args[0])
	}

	if index < 0 || index >= count {
		return 0, fmt.Errorf("certificate index out of range: %d, the chain holds %d", index, count)
	}

	return index, nil
}

// looksLikeSource reports whether an argument reads as a file or a server
// rather than an index, so the error can say what to do about it.
func looksLikeSource(arg string) bool {
	if hasCertExtension(arg) || looksLikeHost(arg) {
		return true
	}
	_, err := os.Stat(arg)
	return err == nil
}

func init() {
	exportCmd.Flags().Bool("all", false, "Write the whole chain to one PEM bundle instead of a single certificate")
	RootCmd.AddCommand(exportCmd)
}
