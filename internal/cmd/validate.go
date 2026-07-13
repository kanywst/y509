// Package cmd contains the command line interface for y509
package cmd

import (
	"crypto/x509"
	"fmt"

	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate certificate chain",
	Long: `Validate the certificate chain in the specified file.

The chain is verified against the system trust store. A chain that links up but
terminates at a root which is not trusted -- an internal PKI, or a bundle that
is simply missing its root -- is reported as self-anchored rather than valid,
and exits non-zero. Pass --roots to supply your own trust anchors.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source, err := loadInput(cmd, args)
		if err != nil {
			logger.Log.Error("Error loading certificates", zap.Error(err))
			return err
		}

		inputCerts := make([]*x509.Certificate, len(source.Certs))
		for i, c := range source.Certs {
			inputCerts[i] = c.Certificate
		}

		chain, err := certificate.SortChain(inputCerts)
		if err != nil {
			logger.Log.Error("Failed to sort certificate chain", zap.Error(err))
			return err
		}

		opts, err := verifyOptionsFromFlags(cmd)
		if err != nil {
			return err
		}
		// When the chain came off the wire, check it is actually valid for the
		// host we talked to. That is the question a live endpoint raises, and
		// it is what a TLS client would ask. An explicit --host still wins.
		if opts.DNSName == "" {
			opts.DNSName = source.Host
		}

		result, err := certificate.VerifyChain(chain, opts)
		if err != nil {
			logger.Log.Error("Certificate chain verification failed", zap.Error(err))
			return err
		}

		fmt.Println(certificate.FormatVerifyResult(result))

		logger.Log.Info("Certificate chain validation result",
			zap.String("trust", result.Level.String()),
			zap.String("anchor", result.Anchor))

		// Only a chain that reaches a real trust anchor is a success. A
		// self-anchored chain gets reported, but a TLS client would not accept
		// it, so it must not exit 0 and quietly pass CI.
		if result.Level != certificate.TrustAnchored {
			return fmt.Errorf("certificate chain is %s", result.Level)
		}
		return nil
	},
}

// verifyOptionsFromFlags builds the verification options from the trust flags.
func verifyOptionsFromFlags(cmd *cobra.Command) (certificate.VerifyOptions, error) {
	var opts certificate.VerifyOptions

	skipSystem, err := cmd.Flags().GetBool("no-system-roots")
	if err != nil {
		return opts, err
	}
	opts.SkipSystemRoots = skipSystem

	hostname, err := cmd.Flags().GetString("host")
	if err != nil {
		return opts, err
	}
	opts.DNSName = hostname

	rootsFile, err := cmd.Flags().GetString("roots")
	if err != nil {
		return opts, err
	}
	if rootsFile != "" {
		roots, err := certificate.LoadCertificates(rootsFile)
		if err != nil {
			return opts, fmt.Errorf("failed to load trust anchors from %s: %w", rootsFile, err)
		}
		for _, root := range roots {
			opts.ExtraRoots = append(opts.ExtraRoots, root.Certificate)
		}
	}

	if opts.SkipSystemRoots && len(opts.ExtraRoots) == 0 {
		return opts, fmt.Errorf("--no-system-roots leaves no trust anchors; pass --roots as well")
	}

	return opts, nil
}

func init() {
	validateCmd.Flags().String("roots", "", "PEM file of additional trust anchors")
	validateCmd.Flags().Bool("no-system-roots", false, "Do not trust the system store; use only --roots")
	validateCmd.Flags().String("host", "", "Also check that the leaf is valid for this hostname")
	RootCmd.AddCommand(validateCmd)
}
