package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRootJSONPrintsTheChainWithoutAVerdict is the surface that was missing:
// --json lived only on validate, bound up with a trust verdict, so there was
// nowhere to put what the detail tabs show.
func TestRootJSONPrintsTheChainWithoutAVerdict(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, err := runRoot(t, path, "--json")
	if err != nil {
		t.Fatalf("y509 --json: %v", err)
	}

	var report map[string]any
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&report); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}

	// No trust verdict: this command was not asked to verify anything, and an
	// empty one would read as "verified, and untrusted".
	if _, ok := report["trust"]; ok {
		t.Error("an inspection carries a trust verdict it never computed")
	}

	// It does answer the question that needs no trust store.
	if _, ok := report["presentation"]; !ok {
		t.Error("the inspection omits how the chain was presented")
	}

	entries, ok := report["chain"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("chain = %v, want the two certificates in the bundle", report["chain"])
	}
	first, _ := entries[0].(map[string]any)
	if first["commonName"] != "y509 test leaf" {
		t.Errorf("chain[0].commonName = %v, want the leaf first", first["commonName"])
	}
}

// TestRootJSONExitsZeroForAnUntrustedChain separates the two commands: an
// inspection reports, validate judges. A chain anchored at its own root is
// perfectly inspectable.
func TestRootJSONExitsZeroForAnUntrustedChain(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	if _, err := runRoot(t, path, "--json"); err != nil {
		t.Errorf("inspecting an untrusted chain failed: %v", err)
	}

	// validate, given the same chain, still exits non-zero.
	if _, err := runRoot(t, "validate", path); err == nil {
		t.Error("validate passed a chain with no trusted anchor")
	}
}

func TestRootJSONIsTheOnlyThingOnStdout(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, err := runRoot(t, path, "--json")
	if err != nil {
		t.Fatalf("y509 --json: %v", err)
	}

	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Errorf("stdout is not a single JSON object:\n%s", out)
	}
}
