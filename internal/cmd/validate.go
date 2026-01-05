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
	Long:  `Validate the certificate chain in the specified file.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var inputFile string
		if len(args) > 0 {
			inputFile = args[0]
		} else {
			inputFile, _ = cmd.Flags().GetString("input")
		}

		certs, err := certificate.LoadCertificates(inputFile)
		if err != nil {
			logger.Log.Error("Error loading certificates", zap.Error(err))
			return err
		}

		        		inputCerts := make([]*x509.Certificate, len(certs))
		        		for i, c := range certs {
		        			inputCerts[i] = c.Certificate
		        		}
		        
		        		chain, err := certificate.SortChain(inputCerts)
		        		if err != nil {
		        			logger.Log.Error("Failed to sort certificate chain", zap.Error(err))
		        			return err
		        		}
		        
		        		isValid, err := certificate.ValidateChain(chain)
		result := &certificate.ValidationResult{
			IsValid: isValid,
		}
		
		        if err != nil {
		            logger.Log.Error("Certificate chain validation failed", zap.Error(err))
		            result.Errors = append(result.Errors, err.Error())
		        }
		
		        // Print validation result
		        fmt.Println(certificate.FormatChainValidation(result))
		
		        logger.Log.Info("Certificate chain validation result", zap.Bool("isValid", isValid))
		
		        if !isValid || err != nil {
		            return fmt.Errorf("certificate chain validation failed")
		        }
		        return nil
		    },
		}
func init() {
	RootCmd.AddCommand(validateCmd)
}
