// Package cmd contains the command line interface for y509
package cmd

import (
	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/internal/version"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(_ *cobra.Command, _ []string) {
		logger.Log.Info("Version information",
			zap.String("version", version.GetVersion()),
			zap.String("build", version.GetFullVersion()))
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
