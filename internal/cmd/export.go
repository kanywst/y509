// Package cmd contains the command line interface for y509
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var exportCmd = &cobra.Command{
	Use:   "export [index] [format] [filename]",
	Short: "Export a certificate to a file",
	Long: `Export a certificate to a file in the specified format.
Format can be either 'pem' or 'der'.
If no index is provided, the currently selected certificate will be exported.
If no format is provided, 'pem' will be used.
If no filename is provided, a default name will be generated.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get input file from flag or use stdin
		inputFile := ""
		if cmd.Flags().Changed("input") {
			inputFile, _ = cmd.Flags().GetString("input")
		}

		// Load certificates
		certs, err := certificate.LoadCertificates(inputFile)
		if err != nil {
			logger.Log.Error("Failed to load certificates", zap.Error(err))
			return err
		}

		if len(certs) == 0 {
			logger.Log.Error("No certificates available")
			return fmt.Errorf("no certificates available")
		}

		// Get certificate index
		index := 0
		if len(args) > 0 {
			_, err := fmt.Sscanf(args[0], "%d", &index)
			if err != nil {
				logger.Log.Error("Invalid certificate index", zap.Error(err))
				return fmt.Errorf("invalid certificate index: %v", err)
			}
			if index < 0 || index >= len(certs) {
				logger.Log.Error("Certificate index out of range")
				return fmt.Errorf("certificate index out of range")
			}
		}

		// Get format
		format := "pem"
		if len(args) > 1 {
			format = args[1]
		}

		// Get filename
		filename := fmt.Sprintf("certificate_%d.%s", index, format)
		if len(args) > 2 {
			filename = args[2]
		}

		// Create directory if it doesn't exist
		dir := filepath.Dir(filename)
		if dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				logger.Log.Error("Failed to create directory", zap.Error(err))
				return fmt.Errorf("failed to create directory: %v", err)
			}
		}

		// Export certificate
		if err := certificate.ExportCertificate(certs[index].Certificate, format, filename); err != nil {
			logger.Log.Error("Failed to export certificate", zap.Error(err))
			return fmt.Errorf("failed to export certificate: %v", err)
		}

		logger.Log.Info("Certificate exported successfully", zap.String("filename", filename))
		return nil
	},
}

func init() {
	RootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringP("input", "i", "", "Input file containing certificates (default: stdin)")
}
