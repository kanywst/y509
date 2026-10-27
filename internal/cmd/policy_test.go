package cmd

import (
	"crypto/mldsa"
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

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fipsBreakingChain verifies, but its leaf has an RSA key with exponent 3,
// which only a FIPS-mode client refuses.
func fipsBreakingChain(t *testing.T) (chainPath, rootsPath string) {
	t.Helper()
	chain := newTestChain(t)
	pemChain := append(pemCert(exponent3Leaf(t, chain)), chain.CAPEM...)
	return write(t, "chain.pem", pemChain), write(t, "roots.pem", chain.CAPEM)
}

// exponent3Leaf is a leaf signed by chain's CA with an RSA key of exponent 3.
func exponent3Leaf(t *testing.T, chain *testChain) []byte {
	t.Helper()
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

	return der
}

func TestValidatePolicyFIPS(t *testing.T) {
	t.Run("clean chain passes and says so", func(t *testing.T) {
		chain := newTestChain(t)
		chainPath, rootsPath := write(t, "chain.pem", chain.ChainPEM), write(t, "roots.pem", chain.CAPEM)

		out, err := runRoot(t, "validate", chainPath, "--roots", rootsPath, "--no-system-roots", "--policy", "fips")
		if err != nil {
			t.Fatalf("a FIPS-clean trusted chain failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "FIPS 140-3: met") {
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

	// A FIPS client verifies with the root's key whether or not it was sent.
	t.Run("weak root that was not sent fails", func(t *testing.T) {
		t.Setenv("GODEBUG", "rsa1024min=0")
		rootKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		root := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "weak root"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		chain := newTestChain(t)
		leaf := *chain.Leaf
		leaf.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
		leafDER, err := x509.CreateCertificate(rand.Reader, &leaf, root, &chain.LeafKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}

		out, err := runRoot(t, "validate", write(t, "leaf.pem", pemCert(leafDER)),
			"--roots", write(t, "roots.pem", pemCert(rootDER)), "--no-system-roots", "--policy", "fips")
		if err == nil || !strings.Contains(out, "unapproved key: weak root") {
			t.Fatalf("err = %v, want the unsent root reported\n%s", err, out)
		}
	})

	// A served certificate no path uses is not one a client checks.
	t.Run("stray certificate does not fail it", func(t *testing.T) {
		chain := newTestChain(t)
		served := append(append([]byte{}, chain.ChainPEM...), pemCert(exponent3Leaf(t, chain))...)

		out, err := runRoot(t, "validate", write(t, "chain.pem", served),
			"--roots", write(t, "roots.pem", chain.CAPEM), "--no-system-roots", "--policy", "fips")
		if err != nil || !strings.Contains(out, "FIPS 140-3: met") {
			t.Fatalf("err = %v, want a pass\n%s", err, out)
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

	t.Run("self-anchored chain still fails as self-anchored", func(t *testing.T) {
		chain := newTestChain(t)
		_, err := runRoot(t, "validate", write(t, "chain.pem", chain.ChainPEM), "--policy", "fips")
		if err == nil || !strings.Contains(err.Error(), "self-anchored") {
			t.Errorf("err = %v, want self-anchored", err)
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

func mldsaChain(t *testing.T) (chainPath, rootsPath string) {
	t.Helper()
	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pqc root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.PublicKey(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pqc leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"pqc.test"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, leafKey.PublicKey(), rootKey)
	if err != nil {
		t.Fatal(err)
	}

	return write(t, "chain.pem", append(pemCert(leafDER), pemCert(rootDER)...)), write(t, "roots.pem", pemCert(rootDER))
}

func TestValidatePolicyPQC(t *testing.T) {
	t.Run("ml-dsa chain passes", func(t *testing.T) {
		chainPath, rootsPath := mldsaChain(t)

		out, err := runRoot(t, "validate", chainPath, "--roots", rootsPath, "--no-system-roots", "--policy", "pqc")
		if err != nil {
			t.Fatalf("an ML-DSA chain failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "Post-quantum: met") {
			t.Errorf("a pass is not reported:\n%s", out)
		}
	})

	t.Run("ecdsa chain fails", func(t *testing.T) {
		chain := newTestChain(t)
		chainPath, rootsPath := write(t, "chain.pem", chain.ChainPEM), write(t, "roots.pem", chain.CAPEM)

		out, err := runRoot(t, "validate", chainPath, "--roots", rootsPath, "--no-system-roots", "--policy", "pqc")
		if err == nil || !strings.Contains(err.Error(), "pqc policy") {
			t.Fatalf("err = %v, want the pqc policy named\n%s", err, out)
		}
		for _, want := range []string{"unapproved signature: ", "unapproved key: y509 test CA"} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in:\n%s", want, out)
			}
		}
	})

	t.Run("json", func(t *testing.T) {
		chainPath, rootsPath := mldsaChain(t)

		out, _, err := runValidateJSON(t, chainPath, "--roots", rootsPath, "--no-system-roots", "--policy", "pqc")
		if err != nil {
			t.Fatalf("validate --json failed: %v\n%s", err, out)
		}
		policy, _ := decode(t, out)["policy"].(map[string]any)
		if policy["name"] != "pqc" || policy["ok"] != true {
			t.Errorf("policy = %#v", policy)
		}
	})
}

func TestPolicyFlagCompletes(t *testing.T) {
	out, err := runRoot(t, "__complete", "validate", "--policy", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fips\n", "pqc\n", ":4\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
