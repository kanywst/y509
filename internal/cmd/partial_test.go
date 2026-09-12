package cmd

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bundleWithAnUnreadableBlock writes a chain whose second CERTIFICATE block
// holds bytes crypto/x509 refuses. The armour is valid, so this is the shape of
// the real case: a well-formed block carrying something Go cannot read.
func bundleWithAnUnreadableBlock(t *testing.T) string {
	t.Helper()

	chain := newTestChain(t)
	corrupt := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00},
	})

	var bundle bytes.Buffer
	bundle.Write(chain.LeafPEM)
	bundle.Write(corrupt)
	bundle.Write(chain.ChainPEM[len(chain.LeafPEM):])

	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, bundle.Bytes(), 0o600); err != nil {
		t.Fatalf("writing the bundle: %v", err)
	}
	return path
}

// TestValidateReportsUnreadableBlocks is the visible half of the fix: skipping
// a block silently would leave a trusted verdict looking like the whole story.
func TestValidateReportsUnreadableBlocks(t *testing.T) {
	path := bundleWithAnUnreadableBlock(t)

	out, err := runRoot(t, "validate", path)
	// The chain is anchored at its own untrusted root, so a non-zero exit is
	// expected; the note is what this test is about.
	if err == nil {
		t.Log("validate exited 0")
	}

	if !strings.Contains(out, "could not be parsed") {
		t.Errorf("validate did not mention the unreadable block:\n%s", out)
	}
	if !strings.Contains(out, "Note:") {
		t.Errorf("the notice is not marked as one:\n%s", out)
	}
}

func TestValidateJSONCarriesUnreadableBlocks(t *testing.T) {
	path := bundleWithAnUnreadableBlock(t)

	out, _ := runRoot(t, "validate", path, "--json")

	var report struct {
		Chain    []map[string]any `json:"chain"`
		Unparsed []struct {
			Block int    `json:"block"`
			Bytes int    `json:"bytes"`
			Error string `json:"error"`
		} `json:"unparsed"`
	}
	// A decoder rather than Unmarshal: the chain is self-anchored, so validate
	// exits non-zero and cobra appends its error after the report. Reading one
	// value is what a consumer piping into jq does too.
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&report); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}

	if len(report.Unparsed) != 1 {
		t.Fatalf("report lists %d unparsed blocks, want 1:\n%s", len(report.Unparsed), out)
	}
	if report.Unparsed[0].Block != 1 {
		t.Errorf("unparsed block = %d, want 1", report.Unparsed[0].Block)
	}
	// The key must not be "index": chain[].index is a contiguous counter over
	// what parsed, so one name for two numbering spaces would mislead.
	if strings.Contains(out, `"index": 1,`) && !strings.Contains(out, `"block": 1`) {
		t.Error("the unparsed entry reuses the chain's index key")
	}
	if report.Unparsed[0].Bytes == 0 || report.Unparsed[0].Error == "" {
		t.Errorf("unparsed entry is missing its size or error: %+v", report.Unparsed[0])
	}
	// The readable certificates still have to be there.
	if len(report.Chain) != 2 {
		t.Errorf("report holds %d chain entries, want the 2 that parsed", len(report.Chain))
	}
}

// TestValidateJSONOmitsUnparsedWhenEverythingParsed keeps the common case
// byte-identical for existing consumers.
func TestValidateJSONOmitsUnparsedWhenEverythingParsed(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, _ := runRoot(t, "validate", path, "--json")

	if strings.Contains(out, "unparsed") {
		t.Errorf("the report carries an unparsed key for a clean bundle:\n%s", out)
	}
}
