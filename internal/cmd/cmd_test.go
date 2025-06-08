package cmd

import (
	"bytes"
	"testing"
)

func TestRootCommandHelp(t *testing.T) {
	b := new(bytes.Buffer)
	oldOut := RootCmd.OutOrStdout()
	oldErr := RootCmd.ErrOrStderr()
	defer func() {
		RootCmd.SetOut(oldOut)
		RootCmd.SetErr(oldErr)
	}()

	RootCmd.SetOut(b)
	RootCmd.SetErr(b)

	RootCmd.Help()

	out := b.String()
	if len(out) == 0 {
		t.Error("Expected help output to not be empty")
	}
}

func TestCommandStructure(t *testing.T) {
	subcommands := []string{"validate", "export", "version", "completion"}

	for _, name := range subcommands {
		found := false
		for _, cmd := range RootCmd.Commands() {
			if cmd.Name() == name {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Expected subcommand '%s' to be registered", name)
		}
	}
}
