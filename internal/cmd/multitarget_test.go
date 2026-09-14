package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestValidateOneTargetKeepsItsShape is the compatibility half: the GitHub
// Action and every existing jq expression are written against a single object.
func TestValidateOneTargetKeepsItsShape(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, _ := runRoot(t, "validate", path, "--json")

	var report map[string]any
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&report); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}
	if _, ok := report["targets"]; ok {
		t.Error("a single target was wrapped in a targets array")
	}
	if _, ok := report["trust"]; !ok {
		t.Error("the single-target report lost its trust verdict")
	}
}

func TestValidateSeveralTargetsReportsEach(t *testing.T) {
	first := newTestChain(t)
	second := newTestChain(t)
	a := write(t, "a.pem", first.ChainPEM)
	b := write(t, "b.pem", second.ChainPEM)

	out, err := runRoot(t, "validate", a, b, "--json")
	if err == nil {
		t.Fatal("two self-anchored chains exited 0")
	}

	var report struct {
		Targets []map[string]any `json:"targets"`
	}
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&report); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}
	if len(report.Targets) != 2 {
		t.Fatalf("report holds %d targets, want 2", len(report.Targets))
	}
	for i, target := range report.Targets {
		if _, ok := target["trust"]; !ok {
			t.Errorf("target %d has no trust verdict", i)
		}
	}
}

// TestValidateKeepsGoingPastAnUnreadableTarget is the point of checking a
// fleet: one unreachable host must not hide the rest.
func TestValidateKeepsGoingPastAnUnreadableTarget(t *testing.T) {
	chain := newTestChain(t)
	good := write(t, "good.pem", chain.ChainPEM)

	out, err := runRoot(t, "validate", good+".missing", good, "--json")
	if err == nil {
		t.Fatal("a missing target exited 0")
	}

	var report struct {
		Targets []map[string]any `json:"targets"`
	}
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&report); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}
	if len(report.Targets) != 2 {
		t.Fatalf("report holds %d targets, want the failed one to appear too", len(report.Targets))
	}
	// A target that could not be read has to appear, or a consumer counting
	// entries would see the fleet quietly shrink.
	if _, ok := report.Targets[0]["error"]; !ok {
		t.Errorf("the unreadable target carries no error: %v", report.Targets[0])
	}
	if _, ok := report.Targets[1]["trust"]; !ok {
		t.Error("the target after the failure was not checked")
	}
}

func TestValidateSeveralTargetsTextOutput(t *testing.T) {
	chain := newTestChain(t)
	a := write(t, "a.pem", chain.ChainPEM)
	b := write(t, "b.pem", chain.LeafPEM)

	out, _ := runRoot(t, "validate", a, b)

	for _, want := range []string{"=== " + a, "=== " + b} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not head the section %q:\n%s", want, out)
		}
	}
}

func TestValidateSummarisesFailuresAcrossTargets(t *testing.T) {
	chain := newTestChain(t)
	a := write(t, "a.pem", chain.ChainPEM)

	_, err := runRoot(t, "validate", a, a+".missing")
	if err == nil {
		t.Fatal("a fleet with a failure exited 0")
	}
	if !strings.Contains(err.Error(), "2 targets failed") && !strings.Contains(err.Error(), "of 2 targets") {
		t.Errorf("error = %q, want it to count the failures", err)
	}
}
