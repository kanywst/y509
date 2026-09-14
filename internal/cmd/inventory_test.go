package cmd

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func TestInventoryListsEveryCertificate(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, err := runRoot(t, "inventory", path, "--json")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}

	var report struct {
		Certificates []map[string]any `json:"certificates"`
		Unreadable   []string         `json:"unreadable"`
	}
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&report); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}
	if len(report.Certificates) != 2 {
		t.Fatalf("inventory holds %d certificates, want 2", len(report.Certificates))
	}

	first := report.Certificates[0]
	for _, key := range []string{"keyAlgorithm", "signatureAlgorithm", "notAfter", "lifetimeDays", "fingerprintSha256"} {
		if _, ok := first[key]; !ok {
			t.Errorf("row has no %q: %v", key, first)
		}
	}
	// The position is what ties a row back to the chain it came from.
	if first["position"] != float64(0) {
		t.Errorf("first row is at position %v, want 0", first["position"])
	}
}

// TestInventoryExitsZeroForAnUntrustedChain keeps the command's question
// separate from validate's: an inventory says what is there, not whether it is
// acceptable.
func TestInventoryExitsZeroForAnUntrustedChain(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	if _, err := runRoot(t, "inventory", path); err != nil {
		t.Errorf("inventory of a self-anchored chain failed: %v", err)
	}
}

func TestInventoryCSVIsParseable(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, err := runRoot(t, "inventory", path, "--csv")
	if err != nil {
		t.Fatalf("inventory --csv: %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("the CSV does not parse: %v\n%s", err, out)
	}
	if len(records) != 3 {
		t.Fatalf("CSV holds %d rows, want a header and two certificates", len(records))
	}
	if records[0][0] != "target" || records[0][4] != "key_algorithm" {
		t.Errorf("header = %v", records[0])
	}
}

func TestInventoryRefusesTwoFormats(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	if _, err := runRoot(t, "inventory", path, "--json", "--csv"); err == nil {
		t.Error("inventory accepted both --json and --csv")
	}
}

// TestInventoryKeepsGoingPastAnUnreadableTarget matters most here: an
// inventory with a silent hole in it is worse than one that says where the
// hole is.
func TestInventoryKeepsGoingPastAnUnreadableTarget(t *testing.T) {
	chain := newTestChain(t)
	good := write(t, "good.pem", chain.ChainPEM)

	out, err := runRoot(t, "inventory", good+".missing", good, "--json")
	if err == nil {
		t.Fatal("a missing target exited 0")
	}

	var report struct {
		Certificates []map[string]any `json:"certificates"`
		Unreadable   []string         `json:"unreadable"`
	}
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&report); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}
	if len(report.Certificates) != 2 {
		t.Errorf("the readable target was not inventoried: %d rows", len(report.Certificates))
	}
	if len(report.Unreadable) != 1 {
		t.Errorf("the unreadable target is not reported: %v", report.Unreadable)
	}
}

func TestInventoryTextHasAHeader(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, err := runRoot(t, "inventory", path)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	for _, want := range []string{"TARGET", "SUBJECT", "KEY", "SIGNATURE", "EXPIRES"} {
		if !strings.Contains(out, want) {
			t.Errorf("output has no %q column:\n%s", want, out)
		}
	}
}
