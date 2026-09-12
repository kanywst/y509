package cmd

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pemOf returns the nth PEM block of a bundle, re-encoded on its own, so a test
// can compare an export against the certificate it should have picked.
func pemOf(t *testing.T, bundle []byte, n int) []byte {
	t.Helper()

	rest := bundle
	for i := 0; ; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			t.Fatalf("bundle holds fewer than %d certificates", n+1)
		}
		if i == n {
			return pem.EncodeToMemory(block)
		}
	}
}

func TestExportWritesTheSelectedCertificate(t *testing.T) {
	chain := newTestChain(t)
	src := write(t, "chain.pem", chain.ChainPEM)
	out := filepath.Join(t.TempDir(), "ca.pem")

	if _, err := runRoot(t, "export", "-i", src, "1", "pem", out); err != nil {
		t.Fatalf("export: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the export: %v", err)
	}
	if n := bytes.Count(got, []byte("BEGIN CERTIFICATE")); n != 1 {
		t.Errorf("export holds %d certificates, want the one that was asked for", n)
	}
	// Index 1 of a leaf-then-CA bundle is the CA, so picking the wrong one is
	// visible rather than silent.
	if !bytes.Equal(got, pemOf(t, chain.ChainPEM, 1)) {
		t.Error("export wrote a different certificate than index 1")
	}
}

// TestExportHonoursConnect is the bug this command had: export read only -i and
// stdin, so with --connect it ignored the server entirely and silently wrote
// whatever was on stdin instead.
func TestExportHonoursConnect(t *testing.T) {
	chain := newTestChain(t)
	src := write(t, "chain.pem", chain.ChainPEM)
	dir := t.TempDir()

	stdin, err := os.Open(src)
	if err != nil {
		t.Fatalf("opening the chain: %v", err)
	}
	defer func() { _ = stdin.Close() }()

	oldStdin := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = oldStdin })

	// Port 1 on the loopback refuses immediately, so the command has to fail
	// with a connection error. Succeeding here would mean it fell back to
	// stdin and exported a certificate the caller never asked for.
	_, err = runRoot(t, "export", "--connect", "127.0.0.1:1", "0", "pem",
		filepath.Join(dir, "leaf.pem"))
	if err == nil {
		t.Fatal("export succeeded with an unreachable --connect; it fell back to stdin")
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("export wrote %d file(s) despite failing to connect", len(entries))
	}
}

func TestExportRejectsASourceWhereAnIndexBelongs(t *testing.T) {
	chain := newTestChain(t)
	src := write(t, "chain.pem", chain.ChainPEM)

	_, err := runRoot(t, "export", "-i", src, src)
	if err == nil {
		t.Fatal("export treated a file path as a certificate index")
	}
	// The old message was "invalid certificate index: expected integer", which
	// says nothing about what to do instead.
	for _, want := range []string{"names a source", "--input"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

func TestExportRejectsAnIndexOutsideTheChain(t *testing.T) {
	chain := newTestChain(t)
	src := write(t, "chain.pem", chain.ChainPEM)

	_, err := runRoot(t, "export", "-i", src, "9")
	if err == nil {
		t.Fatal("export accepted an index past the end of the chain")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error = %q, want it to report the index as out of range", err)
	}
}

func TestExportAllWritesTheWholeChain(t *testing.T) {
	chain := newTestChain(t)
	src := write(t, "chain.pem", chain.ChainPEM)
	out := filepath.Join(t.TempDir(), "bundle.pem")

	if _, err := runRoot(t, "export", "-i", src, "--all", out); err != nil {
		t.Fatalf("export --all: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the bundle: %v", err)
	}
	want := bytes.Count(chain.ChainPEM, []byte("BEGIN CERTIFICATE"))
	if n := bytes.Count(got, []byte("BEGIN CERTIFICATE")); n != want {
		t.Errorf("bundle holds %d certificates, want %d", n, want)
	}
	// The bundle has to be readable by the tool that wrote it.
	if _, err := runRoot(t, "validate", out); err == nil {
		t.Log("validate accepted the bundle")
	} else if !strings.Contains(err.Error(), "chain is") {
		t.Errorf("the exported bundle does not parse back: %v", err)
	}
}
