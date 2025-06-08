// Package cmd contains the command line interface for y509
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/kanywst/y509/pkg/certificate"
)

var (
	format    string
	certIndex int
)

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:   "export [input_file] [output_file]",
	Short: "Export a certificate",
	Long: `Export a certificate from a chain to a new file.
You can specify the format (PEM or DER) and which certificate in the chain to export.`,
	Example: `  y509 export cert.pem output.pem --format pem
  y509 export cert.pem output.der --format der --index 1`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: input and output file paths are required")
			fmt.Fprintln(os.Stderr, "Usage: y509 export [input_file] [output_file]")
			os.Exit(1)
		}

		inputFile := args[0]
		outputFile := args[1]

		// Load certificates
		certs, err := certificate.LoadCertificates(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading certificates: %v\n", err)
			os.Exit(1)
		}

		if len(certs) == 0 {
			fmt.Fprintln(os.Stderr, "Error: no certificates found in the input file")
			os.Exit(1)
		}

		if certIndex >= len(certs) {
			fmt.Fprintf(os.Stderr, "Error: certificate index %d is out of range, only %d certificates available\n",
				certIndex, len(certs))
			os.Exit(1)
		}

		// Export the certificate
		err = certificate.ExportCertificate(certs[certIndex].Certificate, format, outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting certificate: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Certificate exported successfully to %s in %s format\n", outputFile, format)
	},
}

func init() {
	RootCmd.AddCommand(exportCmd)

	// Add flags
	exportCmd.Flags().StringVarP(&format, "format", "f", "pem", "Output format (pem or der)")
	exportCmd.Flags().IntVarP(&certIndex, "index", "i", 0, "Certificate index in the chain (0-based)")
}
