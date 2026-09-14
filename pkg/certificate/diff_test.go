package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// diffCert signs a certificate with the given name and validity, so a renewal
// can be simulated by issuing the same name twice.
func diffCert(t *testing.T, cn string, notBefore time.Time, dns ...string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(90 * 24 * time.Hour),
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}

func TestDiffChainsReportsNoChange(t *testing.T) {
	leaf := diffCert(t, "leaf.example.com", time.Now().Add(-time.Hour))
	ca := diffCert(t, "Example CA", time.Now().Add(-time.Hour))
	chain := []*x509.Certificate{leaf, ca}

	diff := DiffChains(chain, chain)

	if !diff.Same() {
		t.Errorf("a chain compared with itself is not identical: %s", FormatChainDiff(diff))
	}
	if got := FormatChainDiff(diff); !strings.Contains(got, "identical") {
		t.Errorf("FormatChainDiff = %q", got)
	}
}

// TestDiffChainsIdentifiesByBytesNotName is the decision the whole comparison
// rests on: a renewed certificate keeps its subject and changes everything
// else, so matching on the name would report a rotation as no change at all.
func TestDiffChainsIdentifiesByBytesNotName(t *testing.T) {
	old := diffCert(t, "leaf.example.com", time.Now().Add(-90*24*time.Hour))
	renewed := diffCert(t, "leaf.example.com", time.Now().Add(-time.Hour))

	diff := DiffChains([]*x509.Certificate{old}, []*x509.Certificate{renewed})

	if diff.Same() {
		t.Fatal("a renewed certificate with the same subject reported as unchanged")
	}
	if len(diff.Entries) != 2 {
		t.Fatalf("diff holds %d entries, want the old one removed and the new one added", len(diff.Entries))
	}
	if diff.Entries[0].Change != ChangeRemoved || diff.Entries[1].Change != ChangeAdded {
		t.Errorf("changes = %v, %v; want removed then added",
			diff.Entries[0].Change, diff.Entries[1].Change)
	}
}

// TestDiffChainsDescribesALeafReplacement covers the common case: listing one
// certificate removed and another added is accurate and says nothing about what
// actually changed.
func TestDiffChainsDescribesALeafReplacement(t *testing.T) {
	old := diffCert(t, "leaf.example.com", time.Now().Add(-90*24*time.Hour), "leaf.example.com")
	renewed := diffCert(t, "leaf.example.com", time.Now().Add(-time.Hour), "leaf.example.com", "www.example.com")

	diff := DiffChains([]*x509.Certificate{old}, []*x509.Certificate{renewed})
	got := strings.Join(diff.LeafChanges, "\n")

	for _, want := range []string{"serial", "not after", "dns names", "www.example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("leaf changes do not mention %q:\n%s", want, got)
		}
	}
	// The subject did not change, so it must not be listed.
	if strings.Contains(got, "subject:") {
		t.Errorf("leaf changes list a subject that did not change:\n%s", got)
	}
}

// TestDiffChainsSeparatesAReorderFromAReplacement keeps a server that was
// merely reconfigured from reading like one whose certificate was rotated.
func TestDiffChainsSeparatesAReorderFromAReplacement(t *testing.T) {
	leaf := diffCert(t, "leaf.example.com", time.Now().Add(-time.Hour))
	ca := diffCert(t, "Example CA", time.Now().Add(-time.Hour))

	diff := DiffChains([]*x509.Certificate{leaf, ca}, []*x509.Certificate{ca, leaf})

	if diff.Same() {
		t.Fatal("a reordered chain reported as identical")
	}
	for _, e := range diff.Entries {
		if e.Change != ChangeMoved {
			t.Errorf("%s reported as %s, want moved", e.Subject, e.Change)
		}
	}
	if got := FormatChainDiff(diff); !strings.Contains(got, "position 0 -> 1") {
		t.Errorf("FormatChainDiff does not show the move:\n%s", got)
	}
}

func TestDiffChainsReportsAnAddedIntermediate(t *testing.T) {
	leaf := diffCert(t, "leaf.example.com", time.Now().Add(-time.Hour))
	ca := diffCert(t, "Example CA", time.Now().Add(-time.Hour))

	diff := DiffChains([]*x509.Certificate{leaf}, []*x509.Certificate{leaf, ca})

	if diff.Same() {
		t.Fatal("adding an intermediate reported as no change")
	}
	if len(diff.Entries) != 2 {
		t.Fatalf("diff holds %d entries, want 2", len(diff.Entries))
	}
	if diff.Entries[0].Change != ChangeUnchanged {
		t.Errorf("the leaf is %s, want unchanged", diff.Entries[0].Change)
	}
	if diff.Entries[1].Change != ChangeAdded || diff.Entries[1].Subject != "Example CA" {
		t.Errorf("second entry = %s %s, want the CA added", diff.Entries[1].Change, diff.Entries[1].Subject)
	}
	// No leaf replacement to describe: the leaf is the same certificate.
	if len(diff.LeafChanges) != 0 {
		t.Errorf("leaf changes reported for an unchanged leaf: %v", diff.LeafChanges)
	}
}

func TestDiffChainsHandlesEmptySides(t *testing.T) {
	leaf := diffCert(t, "leaf.example.com", time.Now().Add(-time.Hour))

	if diff := DiffChains(nil, []*x509.Certificate{leaf}); diff.Same() {
		t.Error("adding a certificate to an empty chain reported as no change")
	}
	if diff := DiffChains(nil, nil); !diff.Same() {
		t.Error("two empty chains reported as different")
	}
	// A nil entry must not panic or count as a certificate.
	if diff := DiffChains([]*x509.Certificate{nil}, nil); !diff.Same() {
		t.Error("a nil certificate was treated as a difference")
	}
}
