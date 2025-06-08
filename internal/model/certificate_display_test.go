package model

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/y509/pkg/certificate"
)

// createTestCertificateWithDetails creates a test certificate with various fields populated
func createTestCertificateWithDetails() *x509.Certificate {
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)

	return &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:         "api.example.com",
			Organization:       []string{"Example Corp"},
			OrganizationalUnit: []string{"IT Department", "Security Team"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
		Issuer: pkix.Name{
			CommonName:   "Example CA",
			Organization: []string{"Example Authority"},
			Country:      []string{"US"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		DNSNames:  []string{"api.example.com", "www.api.example.com", "staging.api.example.com"},
		IPAddresses: []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("10.0.0.1"),
		},
		EmailAddresses: []string{"admin@example.com", "security@example.com"},
	}
}

func TestImprovedCertificateDisplay_MinimumWidth(t *testing.T) {
	// Test that improved display works even with minimum width constraints
	cert := createTestCertificateWithDetails()
	certInfo := &certificate.CertificateInfo{
		Certificate: cert,
		Index:       0,
		Label:       "1. api.example.com",
	}

	model := Model{
		certificates: []*certificate.CertificateInfo{certInfo},
		cursor:       0,
		width:        40, // Minimum practical width
		height:       20,
	}

	// Test that essential information is displayed even in constrained space
	details := model.renderCertificateDetails(35, 15)

	// Should contain essential information in compact form
	essentialFields := []string{
		"Subject:",
		"api.example.com",
		"Issuer:",
		"Example CA",
		"Expires:",
	}

	for _, field := range essentialFields {
		if !strings.Contains(details, field) {
			t.Errorf("Expected improved display to contain %q in minimum width, but it didn't.\nDetails: %s", field, details)
		}
	}
}

func TestImprovedCertificateDisplay_NormalWidth(t *testing.T) {
	// Test that improved display shows detailed information with normal width
	cert := createTestCertificateWithDetails()
	certInfo := &certificate.CertificateInfo{
		Certificate: cert,
		Index:       0,
		Label:       "1. api.example.com",
	}

	model := Model{
		certificates: []*certificate.CertificateInfo{certInfo},
		cursor:       0,
		width:        80, // Normal width
		height:       30,
	}

	details := model.renderCertificateDetails(75, 25)

	// Should contain comprehensive information
	comprehensiveFields := []string{
		"Subject:",
		"Common Name: api.example.com",
		"Organization: Example Corp",
		"Organizational Unit: IT Department, Security Team",
		"Issuer:",
		"Common Name: Example CA",
		"Organization: Example Authority",
		"Validity:",
		"Not Before:",
		"Not After:",
		"Status:",
		"Subject Alternative Names:",
		"DNS: api.example.com",
		"DNS: www.api.example.com",
		"DNS: staging.api.example.com",
		"IP: 192.168.1.1",
		"IP: 10.0.0.1",
		"Email: admin@example.com",
		"Email: security@example.com",
	}

	for _, field := range comprehensiveFields {
		if !strings.Contains(details, field) {
			t.Errorf("Expected improved display to contain %q in normal width, but it didn't.\nDetails: %s", field, details)
		}
	}
}

func TestImprovedCertificateDisplay_ExpiredCertificate(t *testing.T) {
	// Test display of expired certificate with proper status indication
	cert := createTestCertificateWithDetails()
	// Make it expired
	cert.NotAfter = time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)

	certInfo := &certificate.CertificateInfo{
		Certificate: cert,
		Index:       0,
		Label:       "1. api.example.com (EXPIRED)",
	}

	model := Model{
		certificates: []*certificate.CertificateInfo{certInfo},
		cursor:       0,
		width:        80,
		height:       30,
	}

	details := model.renderCertificateDetails(75, 25)

	// Should clearly indicate expired status
	expiredIndicators := []string{
		"Status: EXPIRED",
		"❌",
	}

	foundIndicator := false
	for _, indicator := range expiredIndicators {
		if strings.Contains(details, indicator) {
			foundIndicator = true
			break
		}
	}

	if !foundIndicator {
		t.Errorf("Expected improved display to contain expired status indicator, but it didn't.\nDetails: %s", details)
	}
}

func TestImprovedCertificateDisplay_ExpiringSoonCertificate(t *testing.T) {
	// Test display of certificate expiring soon
	cert := createTestCertificateWithDetails()
	// Make it expiring soon (within 30 days)
	cert.NotAfter = time.Now().AddDate(0, 0, 15) // 15 days from now

	certInfo := &certificate.CertificateInfo{
		Certificate: cert,
		Index:       0,
		Label:       "1. api.example.com",
	}

	model := Model{
		certificates: []*certificate.CertificateInfo{certInfo},
		cursor:       0,
		width:        80,
		height:       30,
	}

	details := model.renderCertificateDetails(75, 25)

	// Should clearly indicate expiring soon status
	expiringSoonIndicators := []string{
		"Status: EXPIRING SOON",
		"⚠️",
		"🟡",
	}

	foundIndicator := false
	for _, indicator := range expiringSoonIndicators {
		if strings.Contains(details, indicator) {
			foundIndicator = true
			break
		}
	}

	if !foundIndicator {
		t.Errorf("Expected improved display to contain expiring soon status indicator, but it didn't.\nDetails: %s", details)
	}
}

func TestImprovedCertificateDisplay_NoSANs(t *testing.T) {
	// Test display when certificate has no Subject Alternative Names
	cert := createTestCertificateWithDetails()
	cert.DNSNames = nil
	cert.IPAddresses = nil
	cert.EmailAddresses = nil

	certInfo := &certificate.CertificateInfo{
		Certificate: cert,
		Index:       0,
		Label:       "1. api.example.com",
	}

	model := Model{
		certificates: []*certificate.CertificateInfo{certInfo},
		cursor:       0,
		width:        80,
		height:       30,
	}

	details := model.renderCertificateDetails(75, 25)

	// Should handle absence of SANs gracefully
	if strings.Contains(details, "DNS:") || strings.Contains(details, "IP:") || strings.Contains(details, "Email:") {
		// If SANs section exists, it should indicate no SANs
		if !strings.Contains(details, "No Subject Alternative Names") && !strings.Contains(details, "None") {
			t.Errorf("Expected improved display to handle absence of SANs properly, but it didn't.\nDetails: %s", details)
		}
	}
}

func TestImprovedCertificateDisplay_ScrollingSupport(t *testing.T) {
	// Test that scrolling works properly with improved display
	cert := createTestCertificateWithDetails()
	certInfo := &certificate.CertificateInfo{
		Certificate: cert,
		Index:       0,
		Label:       "1. api.example.com",
	}

	model := Model{
		certificates:    []*certificate.CertificateInfo{certInfo},
		cursor:          0,
		width:           80,
		height:          30,
		rightPaneScroll: 5, // Simulate scrolling down
	}

	details := model.renderCertificateDetails(75, 25)

	// Should contain scroll indicators when content exceeds height
	lines := strings.Split(details, "\n")
	if len(lines) > 10 {
		// Check that scrolling information is present
		scrollIndicators := []string{"↑", "↓", "/"}
		foundIndicator := false
		for _, indicator := range scrollIndicators {
			if strings.Contains(details, indicator) {
				foundIndicator = true
				break
			}
		}
		if !foundIndicator {
			t.Errorf("Expected scroll indicators when content exceeds display height, but none found.\nDetails: %s", details)
		}
	}
}

func TestImprovedCertificateDisplay_UXConsistency(t *testing.T) {
	// Test that UX remains consistent between different widths
	cert := createTestCertificateWithDetails()
	certInfo := &certificate.CertificateInfo{
		Certificate: cert,
		Index:       0,
		Label:       "1. api.example.com",
	}

	// Test with narrow width
	modelNarrow := Model{
		certificates: []*certificate.CertificateInfo{certInfo},
		cursor:       0,
		width:        40,
		height:       20,
	}

	// Test with wide width
	modelWide := Model{
		certificates: []*certificate.CertificateInfo{certInfo},
		cursor:       0,
		width:        120,
		height:       40,
	}

	detailsNarrow := modelNarrow.renderCertificateDetails(35, 15)
	detailsWide := modelWide.renderCertificateDetails(75, 25)

	// Narrow: should contain 'Expires:'
	if !strings.Contains(detailsNarrow, "Expires:") {
		t.Errorf("Expected narrow display to contain 'Expires:', but it didn't.\nDetails: %s", detailsNarrow)
	}

	// Wide: should contain either 'Not After:' or 'Status:'
	if !strings.Contains(detailsWide, "Not After:") && !strings.Contains(detailsWide, "Status:") {
		t.Errorf("Expected wide display to contain 'Not After:' or 'Status:', but it didn't.\nDetails: %s", detailsWide)
	}

	// 共通の必須フィールド
	narrowFields := []string{"Subject:", "api.example.com", "Issuer:", "Example CA"}
	wideFields := []string{"Subject:", "api.example.com", "Issuer:", "Example CA"}

	for _, field := range narrowFields {
		if !strings.Contains(detailsNarrow, field) {
			t.Errorf("Expected narrow display to contain essential field %q, but it didn't.\nDetails: %s", field, detailsNarrow)
		}
	}
	for _, field := range wideFields {
		if !strings.Contains(detailsWide, field) {
			t.Errorf("Expected wide display to contain essential field %q, but it didn't.\nDetails: %s", field, detailsWide)
		}
	}
}
