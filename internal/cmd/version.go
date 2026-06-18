// Package cmd contains the command line interface for y509
package cmd

import (
	"fmt"

	"github.com/kanywst/y509/internal/version"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "y509 version %s\nBuild: %s\n",
			version.GetVersion(), version.GetFullVersion())
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
