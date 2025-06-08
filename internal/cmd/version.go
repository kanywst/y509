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
	Short: "Display version information",
	Long:  `Display the version information for y509 including build details.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("y509 version %s\n", version.GetVersion())
		fmt.Printf("Build: %s\n", version.GetFullVersion())
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
