package cmd

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// newValidateFlags builds a command carrying the same flag set validate has, so
// verifyOptionsFromFlags can be exercised without going through cobra dispatch.
func newValidateFlags(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("roots", "", "")
	cmd.Flags().Bool("no-system-roots", false, "")
	cmd.Flags().String("host", "", "")
	return cmd
}

func set(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("setting --%s: %v", name, err)
	}
}

func TestVerifyOptionsFromFlagsDefaults(t *testing.T) {
	opts, err := verifyOptionsFromFlags(newValidateFlags(t))
	if err != nil {
		t.Fatalf("verifyOptionsFromFlags() error = %v", err)
	}

	if opts.SkipSystemRoots {
		t.Error("SkipSystemRoots is set without --no-system-roots")
	}
	if opts.DNSName != "" {
		t.Errorf("DNSName = %q, want empty so validate can fall back to the connected host", opts.DNSName)
	}
	if len(opts.ExtraRoots) != 0 {
		t.Errorf("ExtraRoots has %d entries, want none", len(opts.ExtraRoots))
	}
}

func TestVerifyOptionsFromFlagsHost(t *testing.T) {
	cmd := newValidateFlags(t)
	set(t, cmd, "host", "example.com")

	opts, err := verifyOptionsFromFlags(cmd)
	if err != nil {
		t.Fatalf("verifyOptionsFromFlags() error = %v", err)
	}
	if opts.DNSName != "example.com" {
		t.Errorf("DNSName = %q, want %q", opts.DNSName, "example.com")
	}
}

func TestVerifyOptionsFromFlagsLoadsRoots(t *testing.T) {
	chain := newTestChain(t)
	rootsPath := write(t, "roots.pem", chain.CAPEM)

	cmd := newValidateFlags(t)
	set(t, cmd, "roots", rootsPath)

	opts, err := verifyOptionsFromFlags(cmd)
	if err != nil {
		t.Fatalf("verifyOptionsFromFlags() error = %v", err)
	}
	if len(opts.ExtraRoots) != 1 {
		t.Fatalf("ExtraRoots has %d entries, want 1", len(opts.ExtraRoots))
	}
	if got := opts.ExtraRoots[0].Subject.CommonName; got != chain.CA.Subject.CommonName {
		t.Errorf("loaded anchor CN = %q, want %q", got, chain.CA.Subject.CommonName)
	}
}

func TestVerifyOptionsFromFlagsMissingRootsFileNamesThePath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")

	cmd := newValidateFlags(t)
	set(t, cmd, "roots", missing)

	_, err := verifyOptionsFromFlags(cmd)
	if err == nil {
		t.Fatal("verifyOptionsFromFlags() error = nil for an unreadable --roots file")
	}
	// The path is the one piece of information the user needs to fix it.
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error = %q, want it to name %q", err, missing)
	}
}

func TestVerifyOptionsFromFlagsRejectsNoSystemRootsAlone(t *testing.T) {
	cmd := newValidateFlags(t)
	set(t, cmd, "no-system-roots", "true")

	_, err := verifyOptionsFromFlags(cmd)
	if err == nil {
		t.Fatal("verifyOptionsFromFlags() error = nil; --no-system-roots alone leaves nothing to trust")
	}
	if !strings.Contains(err.Error(), "--roots") {
		t.Errorf("error = %q, want it to point at --roots", err)
	}
}

func TestVerifyOptionsFromFlagsNoSystemRootsWithRoots(t *testing.T) {
	chain := newTestChain(t)
	cmd := newValidateFlags(t)
	set(t, cmd, "no-system-roots", "true")
	set(t, cmd, "roots", write(t, "roots.pem", chain.CAPEM))

	opts, err := verifyOptionsFromFlags(cmd)
	if err != nil {
		t.Fatalf("verifyOptionsFromFlags() error = %v", err)
	}
	if !opts.SkipSystemRoots || len(opts.ExtraRoots) != 1 {
		t.Errorf("got SkipSystemRoots=%v ExtraRoots=%d, want true and 1",
			opts.SkipSystemRoots, len(opts.ExtraRoots))
	}
}

// newInputFlags mirrors the persistent flags loadInput reads off the root.
func newInputFlags(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("connect", "", "")
	cmd.Flags().String("input", "", "")
	cmd.Flags().String("servername", "", "")
	cmd.Flags().String("starttls", "", "")
	cmd.Flags().Duration("timeout", 5*time.Second, "")
	// cobra attaches a context during Execute; a hand-built command has none,
	// and connectFromFlags passes it straight to context.WithTimeout.
	cmd.SetContext(context.Background())
	return cmd
}

func TestLoadInputFromPositionalFile(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	got, err := loadInput(newInputFlags(t), []string{path})
	if err != nil {
		t.Fatalf("loadInput() error = %v", err)
	}
	if len(got.Certs) != 2 {
		t.Errorf("loaded %d certificates, want 2", len(got.Certs))
	}
	if got.Host != "" {
		t.Errorf("Host = %q, want empty for a file source", got.Host)
	}
}

func TestLoadInputFallsBackToInputFlag(t *testing.T) {
	chain := newTestChain(t)
	cmd := newInputFlags(t)
	set(t, cmd, "input", write(t, "leaf.pem", chain.LeafPEM))

	got, err := loadInput(cmd, nil)
	if err != nil {
		t.Fatalf("loadInput() error = %v", err)
	}
	if len(got.Certs) != 1 {
		t.Errorf("loaded %d certificates, want 1", len(got.Certs))
	}
}

func TestLoadInputPositionalWinsOverInputFlag(t *testing.T) {
	chain := newTestChain(t)
	cmd := newInputFlags(t)
	set(t, cmd, "input", write(t, "leaf.pem", chain.LeafPEM))

	// The argument names two certificates, the flag one, so the count says which
	// source was used.
	got, err := loadInput(cmd, []string{write(t, "chain.pem", chain.ChainPEM)})
	if err != nil {
		t.Fatalf("loadInput() error = %v", err)
	}
	if len(got.Certs) != 2 {
		t.Errorf("loaded %d certificates, want the positional argument's 2", len(got.Certs))
	}
}

func TestLoadInputMissingFileIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.pem")

	// A path-shaped target must stay a file lookup rather than being dialled,
	// otherwise a typo comes back as a DNS error.
	if _, err := loadInput(newInputFlags(t), []string{missing}); err == nil {
		t.Fatal("loadInput() error = nil for a missing file")
	}
}
