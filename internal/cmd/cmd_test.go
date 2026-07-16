package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

	_ = RootCmd.Help()

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

func TestLooksLikeHost(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"example.com:443", true},
		{"https://example.com", true},
		{"localhost", true},      // bare word, but the obvious local target
		{"localhost:8443", true}, // covered by the colon anyway
		{"certs", false},         // a bare word is likelier a mistyped file
		{"./chain.pem", false},   // path-shaped, even though it has a dot
		{"/etc/ssl/cert.pem", false},
		{"chain.pem", false},   // a cert extension, so a file even when missing
		{"MISSING.PEM", false}, // extension match is case-insensitive
		{"bundle.p12", false},
		{"sub.example.com", true}, // a plain domain is still a host
		{"", false},
	}
	for _, tt := range tests {
		if got := looksLikeHost(tt.in); got != tt.want {
			t.Errorf("looksLikeHost(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// TestLoadInputRejectsConnectPlusArg checks that supplying both --connect and a
// positional argument is an error rather than silently ignoring the argument.
func TestLoadInputRejectsConnectPlusArg(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("connect", "", "")
	cmd.Flags().String("input", "", "")
	cmd.Flags().String("servername", "", "")
	cmd.Flags().String("starttls", "", "")
	cmd.Flags().Duration("timeout", 0, "")
	if err := cmd.Flags().Set("connect", "example.com:443"); err != nil {
		t.Fatal(err)
	}

	_, err := loadInput(cmd, []string{"chain.pem"})
	if err == nil {
		t.Fatal("expected an error when both --connect and an argument are given")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("error = %q, want it to explain the conflict", err)
	}
}
