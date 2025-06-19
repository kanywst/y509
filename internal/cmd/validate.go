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
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		certs, err := certificate.LoadCertificates(args[0])
		if err != nil {
			logger.Log.Error("Error loading certificates", zap.Error(err))
			return err
		}

		// []*CertificateInfo から []*x509.Certificate へ変換
		chain := make([]*x509.Certificate, len(certs))
		for i, c := range certs {
			chain[i] = c.Certificate
		}

		isValid, err := certificate.ValidateChain(chain)
		result := &certificate.ValidationResult{
			IsValid: isValid,
		}

		if err != nil {
			logger.Log.Error("Certificate chain validation failed", zap.Error(err))
			result.Errors = append(result.Errors, err.Error())
		}

		// 検証結果を表示
		fmt.Println(certificate.FormatChainValidation(result))

		logger.Log.Info("Certificate chain validation result", zap.Bool("isValid", isValid))

		if !isValid || err != nil {
			return fmt.Errorf("certificate chain validation failed")
		}
		return nil
		return nil
	},
}

func init() {
	RootCmd.AddCommand(validateCmd)
}
