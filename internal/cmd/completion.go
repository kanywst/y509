package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// completionCmd represents the completion command
var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for y509.

To load completions:

Bash:
  $ source <(y509 completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ y509 completion bash > /etc/bash_completion.d/y509
  # macOS:
  $ y509 completion bash > $(brew --prefix)/etc/bash_completion.d/y509

Zsh:
  $ source <(y509 completion zsh)

  # To load completions for each session, execute once:
  $ y509 completion zsh > "${fpath[1]}/_y509"

Fish:
  $ y509 completion fish | source

  # To load completions for each session, execute once:
  $ y509 completion fish > ~/.config/fish/completions/y509.fish

PowerShell:
  PS> y509 completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> y509 completion powershell > y509.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	RootCmd.AddCommand(completionCmd)
}
