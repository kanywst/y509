package cmd

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// RootCmd is a package-level singleton, and cobra has no way to reset one. Each
// run therefore snapshots every flag value and restores it afterwards, or a
// --roots left over from one test would silently change the next.
func restoreFlags(t *testing.T) {
	t.Helper()

	type saved struct {
		flag    *pflag.Flag
		value   string
		changed bool
	}
	var all []saved

	record := func(f *pflag.Flag) {
		all = append(all, saved{flag: f, value: f.Value.String(), changed: f.Changed})
	}
	RootCmd.PersistentFlags().VisitAll(record)
	RootCmd.Flags().VisitAll(record)
	for _, sub := range RootCmd.Commands() {
		sub.Flags().VisitAll(record)
	}

	t.Cleanup(func() {
		for _, s := range all {
			_ = s.flag.Value.Set(s.value)
			s.flag.Changed = s.changed
		}
		RootCmd.SetArgs(nil)
	})
}

// runRoot dispatches through the real root command and returns whatever the
// subcommand printed to stdout. The subcommands print with fmt.Println rather
// than through cobra's writer, so stdout itself has to be swapped.
func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	restoreFlags(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	var cobraOut bytes.Buffer
	RootCmd.SetOut(&cobraOut)
	RootCmd.SetErr(&cobraOut)
	RootCmd.SetArgs(args)

	runErr := RootCmd.Execute()

	os.Stdout = oldStdout
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("closing the pipe: %v", closeErr)
	}
	out, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatalf("reading captured stdout: %v", readErr)
	}

	return string(out) + cobraOut.String(), runErr
}

func TestValidateRejectsAChainWithNoTrustedAnchor(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, err := runRoot(t, "validate", path)
	if err == nil {
		t.Fatal("validate exited 0 for a chain anchored at an untrusted root")
	}
	// The distinction matters: the chain links up fine, it just does not reach a
	// root the system trusts, and validate must not pass that in CI.
	if !strings.Contains(err.Error(), "chain is") {
		t.Errorf("error = %q, want it to report the trust level", err)
	}
	if out == "" {
		t.Error("validate printed nothing; the report is the point of the command")
	}
}

func TestValidateAcceptsTheChainWithItsOwnRoot(t *testing.T) {
	chain := newTestChain(t)
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.pem")
	rootsPath := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(chainPath, chain.ChainPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootsPath, chain.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runRoot(t, "validate", chainPath, "--roots", rootsPath, "--no-system-roots")
	if err != nil {
		t.Fatalf("validate failed with its own CA supplied as an anchor: %v\n%s", err, out)
	}
}

func TestValidateReportsAMissingFile(t *testing.T) {
	_, err := runRoot(t, "validate", filepath.Join(t.TempDir(), "absent.pem"))
	if err == nil {
		t.Fatal("validate exited 0 for a missing file")
	}
}

func TestExportWritesRequestedFormats(t *testing.T) {
	chain := newTestChain(t)
	src := write(t, "chain.pem", chain.ChainPEM)

	for _, format := range []string{"pem", "der", "crt", "cert"} {
		t.Run(format, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "cert."+format)

			if _, err := runRoot(t, "export", "0", format, out, "-i", src); err != nil {
				t.Fatalf("export failed: %v", err)
			}

			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("reading the exported file: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("exported file is empty")
			}
			// der is the only format written as raw bytes.
			isPEM := bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----"))
			if format == "der" && isPEM {
				t.Error("der output is PEM-encoded")
			}
			if format != "der" && !isPEM {
				t.Errorf("%s output is not PEM-encoded", format)
			}
		})
	}
}

func TestExportCreatesMissingDirectories(t *testing.T) {
	chain := newTestChain(t)
	src := write(t, "chain.pem", chain.ChainPEM)
	out := filepath.Join(t.TempDir(), "nested", "deeper", "cert.pem")

	if _, err := runRoot(t, "export", "0", "pem", out, "-i", src); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected %s to exist: %v", out, err)
	}
}

func TestExportRejectsBadIndexes(t *testing.T) {
	chain := newTestChain(t)
	src := write(t, "chain.pem", chain.ChainPEM)

	tests := []struct {
		name string
		// args are given in full because a negative index has to come after a
		// "--" separator, or pflag reads it as a shorthand flag.
		args func(out string) []string
		want string
	}{
		{
			name: "not a number",
			args: func(out string) []string { return []string{"export", "abc", "pem", out, "-i", src} },
			want: "invalid certificate index",
		},
		{
			name: "past the end",
			args: func(out string) []string { return []string{"export", "9", "pem", out, "-i", src} },
			want: "out of range",
		},
		{
			name: "negative",
			args: func(out string) []string { return []string{"export", "-i", src, "--", "-1", "pem", out} },
			want: "out of range",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "cert.pem")

			_, err := runRoot(t, tt.args(out)...)
			if err == nil {
				t.Fatal("export accepted a bad index")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestVersionSubcommandPrintsAVersion(t *testing.T) {
	out, err := runRoot(t, "version")
	if err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if !strings.Contains(out, "y509") {
		t.Errorf("version output = %q, want it to name the program", out)
	}
}

func TestCompletionSubcommandEmitsAScript(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			out, err := runRoot(t, "completion", shell)
			if err != nil {
				t.Fatalf("completion %s failed: %v", shell, err)
			}
			if len(out) == 0 {
				t.Errorf("completion %s produced no script", shell)
			}
		})
	}
}

// startTLSServer serves the test chain on 127.0.0.1 and returns host:port. It
// keeps the connect path hermetic: no DNS, no outbound traffic.
func startTLSServer(t *testing.T, chain *testChain) string {
	t.Helper()

	cert := tls.Certificate{
		Certificate: [][]byte{chain.Leaf.Raw, chain.CA.Raw},
		PrivateKey:  chain.LeafKey,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// The handshake is all y509 needs; reading once drives it to
			// completion, then the connection can go.
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	return ln.Addr().String()
}

func TestLoadInputFetchesFromAServer(t *testing.T) {
	chain := newTestChain(t, "localhost")
	addr := startTLSServer(t, chain)

	cmd := newInputFlags(t)
	set(t, cmd, "connect", addr)

	got, err := loadInput(cmd, nil)
	if err != nil {
		t.Fatalf("loadInput() error = %v", err)
	}
	if len(got.Certs) != 2 {
		t.Errorf("fetched %d certificates, want the 2 the server presented", len(got.Certs))
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		t.Fatal(splitErr)
	}
	if got.Host != host {
		t.Errorf("Host = %q, want %q so validate can check the leaf against it", got.Host, host)
	}
}

func TestLoadInputTreatsAHostPortArgumentAsAServer(t *testing.T) {
	chain := newTestChain(t, "localhost")
	addr := startTLSServer(t, chain)

	// No --connect: the colon alone should be enough to read this as an address.
	got, err := loadInput(newInputFlags(t), []string{addr})
	if err != nil {
		t.Fatalf("loadInput() error = %v", err)
	}
	if len(got.Certs) != 2 {
		t.Errorf("fetched %d certificates, want 2", len(got.Certs))
	}
}

func TestLoadInputRejectsAnUnknownStartTLSProtocol(t *testing.T) {
	cmd := newInputFlags(t)
	set(t, cmd, "connect", "127.0.0.1:1")
	set(t, cmd, "starttls", "gopher")

	_, err := loadInput(cmd, nil)
	if err == nil {
		t.Fatal("loadInput() error = nil for an unsupported --starttls protocol")
	}
	// Rejecting before dialling is the point: otherwise the typo surfaces as a
	// connection error instead.
	if !strings.Contains(err.Error(), "starttls") {
		t.Errorf("error = %q, want it to name the flag", err)
	}
}

func TestExecuteSetsUpVersionAndSilencing(t *testing.T) {
	restoreFlags(t)
	oldVersion, oldSilenceErr, oldSilenceUsage := RootCmd.Version, RootCmd.SilenceErrors, RootCmd.SilenceUsage
	t.Cleanup(func() {
		RootCmd.Version, RootCmd.SilenceErrors, RootCmd.SilenceUsage = oldVersion, oldSilenceErr, oldSilenceUsage
	})

	var out bytes.Buffer
	RootCmd.SetOut(&out)
	RootCmd.SetErr(&out)
	// A subcommand that cannot fail, so Execute does not reach its os.Exit(1).
	RootCmd.SetArgs([]string{"version"})

	Execute()

	if RootCmd.Version == "" {
		t.Error("Execute did not set Version, so cobra would not register --version")
	}
	if !RootCmd.SilenceErrors || !RootCmd.SilenceUsage {
		t.Error("Execute did not silence cobra's own error and usage printing")
	}
}
