package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// issue mints a certificate signed by parent, or a self-signed one when parent
// is nil.
func issue(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{cn}
	}

	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// TestVerifyChain_SelfSignedIsNotTrusted is the regression that matters: a lone
// self-signed certificate used to be reported as a valid chain, because the old
// ValidateChain promoted the last certificate of the input to a trust anchor.
// Nothing in the input may be trusted implicitly.
func TestVerifyChain_SelfSignedIsNotTrusted(t *testing.T) {
	selfSigned, _ := issue(t, "totally-self-signed", true, nil, nil)

	result, err := VerifyChain([]*x509.Certificate{selfSigned}, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain returned an error: %v", err)
	}
	if result.Level == TrustAnchored {
		t.Fatal("a self-signed certificate must never verify as trusted")
	}
	if result.Level != TrustSelfAnchored {
		t.Errorf("Level = %v, want %v", result.Level, TrustSelfAnchored)
	}
}

// TestVerifyChain_UntrustedRootIsSelfAnchored covers the everyday case: a chain
// whose root is present but is not a public CA. It links up, so it is not
// broken, but no TLS client would accept it.
func TestVerifyChain_UntrustedRootIsSelfAnchored(t *testing.T) {
	root, rootKey := issue(t, "Internal Root CA", true, nil, nil)
	leaf, _ := issue(t, "leaf.internal", false, root, rootKey)

	result, err := VerifyChain([]*x509.Certificate{leaf, root}, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain returned an error: %v", err)
	}
	if result.Level != TrustSelfAnchored {
		t.Fatalf("Level = %v, want %v", result.Level, TrustSelfAnchored)
	}
	if result.Anchor != "Internal Root CA" {
		t.Errorf("Anchor = %q, want %q", result.Anchor, "Internal Root CA")
	}
	if result.Err == nil {
		t.Error("a self-anchored result should carry the trust-store error explaining why")
	}
}

// TestVerifyChain_ExtraRootsMakesItTrusted checks that --roots turns the same
// internal chain into a trusted one.
func TestVerifyChain_ExtraRootsMakesItTrusted(t *testing.T) {
	root, rootKey := issue(t, "Internal Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Internal Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.internal", false, intermediate, intermediateKey)

	result, err := VerifyChain(
		[]*x509.Certificate{leaf, intermediate, root},
		VerifyOptions{ExtraRoots: []*x509.Certificate{root}},
	)
	if err != nil {
		t.Fatalf("VerifyChain returned an error: %v", err)
	}
	if result.Level != TrustAnchored {
		t.Fatalf("Level = %v (%v), want %v", result.Level, result.Err, TrustAnchored)
	}
	if result.Anchor != "Internal Root CA" {
		t.Errorf("Anchor = %q, want %q", result.Anchor, "Internal Root CA")
	}
}

// TestVerifyChain_MissingIssuerIsBroken checks that a chain which cannot reach
// any root at all is reported as broken rather than self-anchored.
func TestVerifyChain_MissingIssuerIsBroken(t *testing.T) {
	root, rootKey := issue(t, "Internal Root CA", true, nil, nil)
	intermediate, intermediateKey := issue(t, "Internal Issuing CA", true, root, rootKey)
	leaf, _ := issue(t, "leaf.internal", false, intermediate, intermediateKey)

	// The intermediate is missing, so the leaf cannot reach the root.
	result, err := VerifyChain([]*x509.Certificate{leaf, root}, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain returned an error: %v", err)
	}
	if result.Level != TrustBroken {
		t.Errorf("Level = %v, want %v", result.Level, TrustBroken)
	}
}

// TestVerifyChain_ExpiredIsBroken checks that an expired leaf is broken even
// though its signature is fine.
func TestVerifyChain_ExpiredIsBroken(t *testing.T) {
	root, rootKey := issue(t, "Internal Root CA", true, nil, nil)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "expired.internal"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyChain(
		[]*x509.Certificate{expired, root},
		VerifyOptions{ExtraRoots: []*x509.Certificate{root}},
	)
	if err != nil {
		t.Fatalf("VerifyChain returned an error: %v", err)
	}
	if result.Level != TrustBroken {
		t.Errorf("Level = %v, want %v (an expired leaf is not a valid chain)", result.Level, TrustBroken)
	}
}

// TestVerifyChain_HostnameMismatch checks the --host check.
func TestVerifyChain_HostnameMismatch(t *testing.T) {
	root, rootKey := issue(t, "Internal Root CA", true, nil, nil)
	leaf, _ := issue(t, "leaf.internal", false, root, rootKey)

	trusted := VerifyOptions{ExtraRoots: []*x509.Certificate{root}}

	matching := trusted
	matching.DNSName = "leaf.internal"
	result, err := VerifyChain([]*x509.Certificate{leaf, root}, matching)
	if err != nil {
		t.Fatalf("VerifyChain returned an error: %v", err)
	}
	if result.Level != TrustAnchored {
		t.Errorf("matching hostname: Level = %v (%v), want %v", result.Level, result.Err, TrustAnchored)
	}

	mismatched := trusted
	mismatched.DNSName = "evil.example.com"
	result, err = VerifyChain([]*x509.Certificate{leaf, root}, mismatched)
	if err != nil {
		t.Fatalf("VerifyChain returned an error: %v", err)
	}
	if result.Level == TrustAnchored {
		t.Error("a certificate must not verify as trusted for a hostname it is not valid for")
	}
}

// TestVerifyChain_EmptyChain checks the degenerate input.
func TestVerifyChain_EmptyChain(t *testing.T) {
	if _, err := VerifyChain(nil, VerifyOptions{}); err == nil {
		t.Error("expected an error for an empty chain")
	}
}

// TestVerifyChain_NilCertificates checks the exported entry point survives a
// malformed slice. x509.CertPool.AddCert panics on a nil certificate, so this
// must not reach it.
func TestVerifyChain_NilCertificates(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	leaf, _ := issue(t, "leaf.internal", false, root, rootKey)

	t.Run("nil leaf", func(t *testing.T) {
		if _, err := VerifyChain([]*x509.Certificate{nil, root}, VerifyOptions{}); err == nil {
			t.Error("expected an error for a nil leaf")
		}
	})

	t.Run("nil intermediate is skipped", func(t *testing.T) {
		result, err := VerifyChain(
			[]*x509.Certificate{leaf, nil, root},
			VerifyOptions{ExtraRoots: []*x509.Certificate{root}},
		)
		if err != nil {
			t.Fatalf("a nil intermediate should be skipped, got: %v", err)
		}
		if result.Level != TrustAnchored {
			t.Errorf("Level = %v (%v), want %v", result.Level, result.Err, TrustAnchored)
		}
	})

	t.Run("nil extra root is skipped", func(t *testing.T) {
		result, err := VerifyChain(
			[]*x509.Certificate{leaf, root},
			VerifyOptions{ExtraRoots: []*x509.Certificate{nil, root}},
		)
		if err != nil {
			t.Fatalf("a nil extra root should be skipped, got: %v", err)
		}
		if result.Level != TrustAnchored {
			t.Errorf("Level = %v (%v), want %v", result.Level, result.Err, TrustAnchored)
		}
	})
}
