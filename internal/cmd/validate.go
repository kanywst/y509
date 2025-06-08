// Package cmd contains the command line interface for y509
package cmd

import (
	"fmt"
	"os"

	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
)

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a certificate chain",
	Long: `Validate a certificate chain in a file.
This command performs validation of the certificate chain and displays the results.
It can check for chain validity, expiration, and trust.`,
	Example: "  y509 validate certificate.pem",
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

		// Validate the certificate chain
		results := certificate.ValidateChain(certs)

		// Display validation results
		fmt.Println(certificate.FormatChainValidation(results))
	},
}

func init() {
	RootCmd.AddCommand(validateCmd)
}
