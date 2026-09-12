package model

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/y509/pkg/certificate"
)

// testChain builds a real three-level chain -- root CA, intermediate CA, leaf --
// so the findings under test are the ones AnalyzeChain actually produces rather
// than a hand-written fixture. createTestCertificates cannot be used here: it
// returns unrelated self-signed certificates, which is itself a finding.
func testChain(t *testing.T) (leaf, intermediate, root *certificate.Info) {
	t.Helper()

	sign := func(template, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		signer, signerKey := parent, parentKey
		if signer == nil {
			signer, signerKey = template, key // self-signed
		}
		der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
		if err != nil {
			t.Fatalf("create certificate %q: %v", template.Subject.CommonName, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse certificate %q: %v", template.Subject.CommonName, err)
		}
		return cert, key
	}

	ca := func(cn string, serial int64) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
	}

	rootCert, rootKey := sign(ca("Test Root CA", 1), nil, nil)
	intCert, intKey := sign(ca("Test Intermediate CA", 2), rootCert, rootKey)
	leafCert, _ := sign(&x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:              []string{"leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, intCert, intKey)

	return &certificate.Info{Certificate: leafCert},
		&certificate.Info{Certificate: intCert},
		&certificate.Info{Certificate: rootCert}
}

func TestRenderFindings(t *testing.T) {
	leaf, intermediate, root := testChain(t)
	cfg := loadTestConfig(t)

	tests := []struct {
		name     string
		certs    []*certificate.Info
		contains []string
		absent   []string
	}{
		{
			name:     "a correctly presented chain reports no problem",
			certs:    []*certificate.Info{leaf, intermediate},
			contains: []string{"Presented correctly"},
			absent:   []string{"problem"},
		},
		{
			name:     "a chain sent root-first is reported out of order",
			certs:    []*certificate.Info{intermediate, leaf},
			contains: []string{"1 problem", "out of order"},
		},
		{
			name:     "a root included in the chain is reported as redundant",
			certs:    []*certificate.Info{leaf, intermediate, root},
			contains: []string{"redundant root", "Test Root CA"},
		},
		{
			name:     "a leaf whose issuer was never sent is reported",
			certs:    []*certificate.Info{leaf},
			contains: []string{"missing issuer", "leaf.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := *NewModel(tt.certs, cfg)
			got := m.renderFindings()

			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("findings tab does not mention %q:\n%s", want, got)
				}
			}
			for _, unwanted := range tt.absent {
				if strings.Contains(got, unwanted) {
					t.Errorf("findings tab unexpectedly mentions %q:\n%s", unwanted, got)
				}
			}
		})
	}
}

// TestRenderFindingsAnalyzesBeforeSorting is the invariant the whole tab rests
// on. The list sorts the chain before drawing it, so if the report were built
// from the sorted slice an out-of-order chain would look perfect -- which is the
// bug the tab exists to surface.
func TestRenderFindingsAnalyzesBeforeSorting(t *testing.T) {
	leaf, intermediate, _ := testChain(t)

	m := *NewModel([]*certificate.Info{intermediate, leaf}, loadTestConfig(t))

	if !strings.Contains(m.renderFindings(), "out of order") {
		t.Fatalf("out-of-order chain reported clean; the report was built after sorting:\n%s", m.renderFindings())
	}

	// The list itself is still sorted leaf-first: the fix must not have been to
	// stop sorting.
	if cn := m.allCertificates[0].Certificate.Subject.CommonName; cn != "leaf.example.com" {
		t.Errorf("list is no longer sorted leaf-first, first row is %q", cn)
	}
}

func TestRenderFindingsWithoutCertificates(t *testing.T) {
	m := *NewModel(nil, loadTestConfig(t))

	if got := m.renderFindings(); !strings.Contains(got, "No chain to analyze") {
		t.Errorf("expected an empty-input message, got %q", got)
	}
}

func TestFindingsTabIsReachable(t *testing.T) {
	leaf, intermediate, _ := testChain(t)
	m := *NewModel([]*certificate.Info{intermediate, leaf}, loadTestConfig(t))

	idx := -1
	for i, tab := range m.tabs {
		if tab == "Findings" {
			idx = i
			break
		}
	}
	if idx == -1 {
		t.Fatalf("no Findings tab in %v", m.tabs)
	}

	m.activeTab = idx
	if got := m.renderTabContent(80); !strings.Contains(got, "out of order") {
		t.Errorf("Findings tab selected but its content is not rendered:\n%s", got)
	}
}
