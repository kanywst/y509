package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// crlChain is a CA that signs CRLs, a leaf pointing at a CRL server, and that
// server serving a CRL which revokes the leaf when revoke is set. It returns
// the chain and roots files.
func crlChain(t *testing.T, revoke bool) (chainPath, rootsPath string) {
	t.Helper()
	// The CRL cache must not land in the real user cache directory.
	cache := t.TempDir()
	t.Setenv("HOME", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LocalAppData", cache)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "y509 CRL test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	crl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
	}
	if revoke {
		crl.RevokedCertificateEntries = []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(2), RevocationTime: time.Now().Add(-time.Minute)},
		}
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crl, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(crlDER)
	}))
	t.Cleanup(srv.Close)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "crl.test"},
		DNSNames:              []string{"crl.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CRLDistributionPoints: []string{srv.URL + "/ca.crl"},
	}, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return write(t, "chain.pem", append(pemCert(leafDER), pemCert(caDER)...)),
		write(t, "roots.pem", pemCert(caDER))
}

func TestValidateCheckCRLJSON(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		chain, roots := crlChain(t, revoke)
		out, _, err := runValidateJSON(t, chain, "--roots", roots, "--check-crl")
		// Revocation does not change the exit status, as with the staple.
		if err != nil {
			t.Fatalf("revoke=%v: validate failed: %v", revoke, err)
		}
		rev, ok := decode(t, out)["revocation"].(map[string]any)
		if !ok {
			t.Fatalf("revoke=%v: no revocation object for a file with --check-crl:\n%s", revoke, out)
		}
		checks := rev["crl"].([]any)
		if len(checks) != 1 {
			t.Fatalf("revoke=%v: %d CRL checks, want 1 (the anchor is not checked)", revoke, len(checks))
		}
		status := checks[0].(map[string]any)["status"]
		if revoke {
			if status != "revoked" || rev["ok"] != false {
				t.Errorf("revoked leaf: status=%v ok=%v", status, rev["ok"])
			}
		} else if status != "good" || rev["ok"] != true {
			t.Errorf("good leaf: status=%v ok=%v", status, rev["ok"])
		}
	}
}

func TestValidateWithoutCheckCRLLeavesFilesAlone(t *testing.T) {
	chain, roots := crlChain(t, true)
	out, _, err := runValidateJSON(t, chain, "--roots", roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := decode(t, out)["revocation"]; present {
		t.Error("a file target without --check-crl reports revocation; nothing was asked or fetched")
	}
}

func TestValidateCheckCRLText(t *testing.T) {
	chain, roots := crlChain(t, true)
	out, err := runRoot(t, "validate", chain, "--roots", roots, "--check-crl")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CRL check:", "crl.test: revoked", "revoked in CRL"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestValidateCheckCRLSkipsASelfAnchoredChain(t *testing.T) {
	chain, _ := crlChain(t, false)
	out, _, err := runValidateJSON(t, chain, "--check-crl")
	if err == nil {
		t.Fatal("a self-anchored chain passed")
	}
	rev := decode(t, out)["revocation"].(map[string]any)
	if checks := rev["crl"].([]any); len(checks) != 0 {
		t.Errorf("checked CRLs against a root nobody trusts: %v", checks)
	}
}
