package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runValidateJSON dispatches `validate --json` and returns stdout on its own.
//
// runRoot concatenates stdout with cobra's writer, which is fine for prose but
// useless here: the whole claim being tested is that the stream parses, and a
// helper that blends an error message into it would test the opposite.
func runValidateJSON(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	restoreFlags(t)

	var out, errOut bytes.Buffer
	RootCmd.SetOut(&out)
	RootCmd.SetErr(&errOut)
	// Otherwise cobra writes the returned error, and the usage text, to the
	// same writer the report goes to. Execute() sets both in production.
	silenceErrors, silenceUsage := RootCmd.SilenceErrors, RootCmd.SilenceUsage
	RootCmd.SilenceErrors, RootCmd.SilenceUsage = true, true
	t.Cleanup(func() {
		RootCmd.SilenceErrors, RootCmd.SilenceUsage = silenceErrors, silenceUsage
	})

	RootCmd.SetArgs(append([]string{"validate", "--json"}, args...))
	err := RootCmd.Execute()

	return out.String(), errOut.String(), err
}

// decode fails the test unless the output parses as the report.
func decode(t *testing.T, out string) map[string]any {
	t.Helper()

	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("stdout does not parse as JSON: %v\n%s", err, out)
	}
	return report
}

// TestValidateJSONStdoutIsOnlyJSON is the contract that makes the flag worth
// having: a consumer pipes stdout into jq, so nothing human-readable may share
// the stream -- not even on the failure path, which is the common case for a
// command whose job is to find problems.
func TestValidateJSONStdoutIsOnlyJSON(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	// This chain is anchored at its own untrusted root, so validate exits
	// non-zero. That is precisely when stdout must still parse.
	out, _, err := runValidateJSON(t, path)
	if err == nil {
		t.Fatal("validate exited 0 for a chain anchored at an untrusted root")
	}

	report := decode(t, out)

	// The emoji and the prose belong to the text renderer, and leaking either
	// one would mean the two output paths had been wired together.
	for _, leak := range []string{"✅", "⚠", "❌", "Certificate chain is", "Chain as presented"} {
		if strings.Contains(out, leak) {
			t.Errorf("the human-readable output leaked into the JSON stream: %q\n%s", leak, out)
		}
	}

	trust, ok := report["trust"].(map[string]any)
	if !ok {
		t.Fatalf("trust is missing: %#v", report)
	}
	if trust["level"] != "self-anchored" {
		t.Errorf("level = %#v, want \"self-anchored\"", trust["level"])
	}
	if trust["trusted"] != false {
		t.Errorf("trusted = %#v, want false", trust["trusted"])
	}
}

// TestValidateJSONDistinguishesSelfAnchoredFromBroken is the reason the flag
// exists. Both exit 1, so the exit code alone cannot tell an internal PKI apart
// from a chain that does not link up at all.
func TestValidateJSONDistinguishesSelfAnchoredFromBroken(t *testing.T) {
	chain := newTestChain(t)

	// The leaf on its own: no issuer was supplied, so the chain does not build.
	leafOnly := write(t, "leaf.pem", chain.LeafPEM)
	out, _, err := runValidateJSON(t, leafOnly)
	if err == nil {
		t.Fatal("validate exited 0 for a chain that does not link up")
	}
	broken := decode(t, out)["trust"].(map[string]any)["level"]

	// The same leaf with its root: links up, but the root is not trusted.
	full := write(t, "chain.pem", chain.ChainPEM)
	out, _, err = runValidateJSON(t, full)
	if err == nil {
		t.Fatal("validate exited 0 for a self-anchored chain")
	}
	selfAnchored := decode(t, out)["trust"].(map[string]any)["level"]

	if broken == selfAnchored {
		t.Fatalf("both chains reported %q; the exit code already collapses them, "+
			"so JSON that does the same adds nothing", broken)
	}
	if selfAnchored != "self-anchored" {
		t.Errorf("level = %#v, want \"self-anchored\"", selfAnchored)
	}
}

// TestValidateJSONOnATrustedChain checks the success path, including that the
// findings list is an array rather than null.
func TestValidateJSONOnATrustedChain(t *testing.T) {
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

	out, _, err := runValidateJSON(t, chainPath, "--roots", rootsPath, "--no-system-roots")
	if err != nil {
		t.Fatalf("validate failed with its own CA supplied as an anchor: %v\n%s", err, out)
	}

	report := decode(t, out)
	trust := report["trust"].(map[string]any)
	if trust["trusted"] != true {
		t.Errorf("trusted = %#v, want true", trust["trusted"])
	}

	presentation, ok := report["presentation"].(map[string]any)
	if !ok {
		t.Fatalf("presentation is missing: %#v", report)
	}
	if _, ok := presentation["findings"].([]any); !ok {
		t.Errorf("findings is %#v, want an array even when empty", presentation["findings"])
	}

	certs, ok := report["chain"].([]any)
	if !ok || len(certs) == 0 {
		t.Fatalf("chain is %#v, want the certificates", report["chain"])
	}
}

// TestValidateWithoutJSONStaysHumanReadable: the flag is additive, and the
// default output must not have changed shape.
func TestValidateWithoutJSONStaysHumanReadable(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, _ := runRoot(t, "validate", path)
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("validate emitted JSON without --json:\n%s", out)
	}
	if !strings.Contains(out, "Certificate chain is") {
		t.Errorf("the text report is missing:\n%s", out)
	}
}
