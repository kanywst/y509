package cmd

import (
	"strings"
	"testing"
)

func TestDiffReportsIdenticalChains(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	out, err := runRoot(t, "diff", path, path)
	if err != nil {
		t.Fatalf("diff of a file with itself exited non-zero: %v", err)
	}
	if !strings.Contains(out, "identical") {
		t.Errorf("output does not say the chains match:\n%s", out)
	}
}

// TestDiffExitsNonZeroWhenChainsDiffer follows diff(1), so a script can ask
// whether a rotation happened without parsing anything.
func TestDiffExitsNonZeroWhenChainsDiffer(t *testing.T) {
	first := newTestChain(t)
	second := newTestChain(t)
	a := write(t, "a.pem", first.ChainPEM)
	b := write(t, "b.pem", second.LeafPEM)

	out, err := runRoot(t, "diff", a, b)
	if err == nil {
		t.Fatal("diff of two different chains exited 0")
	}
	if !strings.Contains(out, "Chain differences") {
		t.Errorf("output does not describe the difference:\n%s", out)
	}
}

func TestDiffRefusesTheWrongNumberOfArguments(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	if _, err := runRoot(t, "diff", path); err == nil {
		t.Error("diff accepted a single argument")
	}
}

func TestDiffNamesTheSideThatFailed(t *testing.T) {
	chain := newTestChain(t)
	path := write(t, "chain.pem", chain.ChainPEM)

	_, err := runRoot(t, "diff", path, path+".missing")
	if err == nil {
		t.Fatal("diff accepted a file that does not exist")
	}
	// Which of the two failed is the first thing the reader needs.
	if !strings.Contains(err.Error(), ".missing") {
		t.Errorf("error = %q, want it to name the side that failed", err)
	}
}
