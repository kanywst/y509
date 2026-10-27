package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// fipsBreakingChain is a chain that verifies but breaks FIPS: its leaf carries
// an RSA key with public exponent 3, which every client accepts and a FIPS-mode
// client refuses. Only the CA signs anything, so the leaf's key needs no
// private half.
func fipsBreakingChain(t *testing.T) (chainPath, rootsPath string) {
	t.Helper()

	chain := newTestChain(t)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "fips leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"fips.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, chain.CA, &rsa.PublicKey{N: leafKey.N, E: 3}, chain.CAKey)
	if err != nil {
		t.Fatal(err)
	}

	pemChain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), chain.CAPEM...)
	return write(t, "chain.pem", pemChain), write(t, "roots.pem", chain.CAPEM)
}

func TestValidatePolicyFIPS(t *testing.T) {
	t.Run("clean chain passes and says so", func(t *testing.T) {
		chain := newTestChain(t)
		chainPath, rootsPath := write(t, "chain.pem", chain.ChainPEM), write(t, "roots.pem", chain.CAPEM)

		out, err := runRoot(t, "validate", chainPath, "--roots", rootsPath, "--no-system-roots", "--policy", "fips")
		if err != nil {
			t.Fatalf("a FIPS-clean trusted chain failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "FIPS 140-3: every certificate sent uses approved algorithms") {
			t.Errorf("a pass is not reported:\n%s", out)
		}
	})

	t.Run("trusted chain that breaks it exits non-zero", func(t *testing.T) {
		chainPath, rootsPath := fipsBreakingChain(t)

		out, err := runRoot(t, "validate", chainPath, "--roots", rootsPath, "--no-system-roots", "--policy", "fips")
		if err == nil || !strings.Contains(err.Error(), "fips policy") {
			t.Fatalf("err = %v, want the fips policy named\n%s", err, out)
		}
		if !strings.Contains(out, "unapproved key: fips leaf") {
			t.Errorf("the finding is missing:\n%s", out)
		}
	})

	t.Run("the same chain passes without the flag", func(t *testing.T) {
		chainPath, rootsPath := fipsBreakingChain(t)

		out, err := runRoot(t, "validate", chainPath, "--roots", rootsPath, "--no-system-roots")
		if err != nil {
			t.Fatalf("validate failed without --policy: %v\n%s", err, out)
		}
		if strings.Contains(out, "FIPS") {
			t.Errorf("FIPS reported unasked:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		chainPath, rootsPath := fipsBreakingChain(t)

		out, _, err := runValidateJSON(t, chainPath, "--roots", rootsPath, "--no-system-roots", "--policy", "fips")
		if err == nil {
			t.Fatal("validate --json passed a chain that breaks the policy")
		}
		policy, ok := decode(t, out)["policy"].(map[string]any)
		if !ok {
			t.Fatalf("policy is missing:\n%s", out)
		}
		findings, _ := policy["findings"].([]any)
		if policy["name"] != "fips" || policy["ok"] != false || len(findings) != 1 {
			t.Errorf("policy = %#v", policy)
		}
		// Conformance is about what every client rejects, and this chain
		// breaks nothing of it.
		if decode(t, out)["conformance"].(map[string]any)["ok"] != true {
			t.Errorf("a policy finding leaked into conformance:\n%s", out)
		}
	})

	t.Run("json without the flag has no policy key", func(t *testing.T) {
		chain := newTestChain(t)
		out, _, _ := runValidateJSON(t, write(t, "chain.pem", chain.ChainPEM))
		if _, ok := decode(t, out)["policy"]; ok {
			t.Errorf("policy present without --policy:\n%s", out)
		}
	})

	t.Run("unknown policy is an error", func(t *testing.T) {
		chain := newTestChain(t)
		_, err := runRoot(t, "validate", write(t, "chain.pem", chain.ChainPEM), "--policy", "fips-level-3")
		if err == nil || !strings.Contains(err.Error(), "unknown policy") {
			t.Errorf("err = %v, want unknown policy", err)
		}
	})
}
