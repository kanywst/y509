// Package model provides the core TUI application logic and view.
package model

import (
	"fmt"
	"strings"

	"crypto/x509"

	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
)

// handleValidateCommand processes the validate command for the SELECTED certificate
func (m Model) handleValidateCommand() Model {
	logger.Log.Debug("validating selected certificate")

	if len(m.certificates) == 0 {
		return m
	}

	target := m.certificates[m.cursor]
	leaf := target.Certificate

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	var rootCount int
	for _, c := range m.allCertificates {
		intermediates.AddCert(c.Certificate)
		if c.Certificate.Issuer.String() == c.Certificate.Subject.String() {
			// Verify that the certificate is actually self-signed.
			if err := c.Certificate.CheckSignature(c.Certificate.SignatureAlgorithm, c.Certificate.RawTBSCertificate, c.Certificate.Signature); err == nil {
				roots.AddCert(c.Certificate)
				rootCount++
			}
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leaf.Verify(opts)

	var sb strings.Builder
	if err == nil {
		sb.WriteString("✅  Certificate is VALID\n\n")
		sb.WriteString(fmt.Sprintf("Subject: %s\n", leaf.Subject.CommonName))
		sb.WriteString(fmt.Sprintf("Issuer:  %s\n", leaf.Issuer.CommonName))
		sb.WriteString(fmt.Sprintf("Roots:   %d trusted roots found in loaded file", rootCount))
	} else {
		sb.WriteString("❌  Certificate is INVALID\n\n")
		sb.WriteString(fmt.Sprintf("Error: %v\n", err))
		if rootCount == 0 {
			sb.WriteString("\nNote: No self-signed Root CA was found in the loaded certificates.\nVerification failed because no trust anchor could be established.")
		} else {
			sb.WriteString("\nNote: Chain verification failed despite presence of Root CAs.")
		}
	}

	m.popupMessage = sb.String()
	m.viewMode = ViewPopup
	m.popupType = PopupAlert
	return m
}

// searchCertificates searches certificates based on query
func (m Model) searchCertificates(query string) Model {
	query = strings.TrimSpace(query)
	if query == "" {
		return m.resetView()
	}

	m.searchQuery = query
	m.filterActive = true
	m.filterType = fmt.Sprintf("search: %s", query)

	return m.applyFilter()
}

// filterCertificates filters certificates based on criteria
func (m Model) filterCertificates(filterType string) Model {
	filterType = strings.ToLower(strings.TrimSpace(filterType))
	if filterType == "" {
		return m.resetView()
	}

	validFilters := []string{"expired", "expiring", "valid", "self-signed"}
	found := false
	for _, f := range validFilters {
		if f == filterType {
			found = true
			break
		}
	}

	if !found {
		m.popupMessage = fmt.Sprintf("❌ Invalid filter type: %s\n\nValid filters are:\n- expired\n- expiring\n- valid\n- self-signed", filterType)
		m.viewMode = ViewPopup
		m.popupType = PopupAlert
		return m
	}

	m.filterActive = true
	m.filterType = filterType

	return m.applyFilter()
}

// applyFilter applies the active filter/search to the certificate list
func (m Model) applyFilter() Model {
	var filtered []*certificate.Info
	query := strings.ToLower(m.searchQuery)

	for _, certInfo := range m.allCertificates {
		match := false
		if strings.HasPrefix(m.filterType, "search:") {
			if matchSearch(certInfo.Certificate, query) {
				match = true
			}
		} else {
			switch m.filterType {
			case "expired":
				if certificate.IsExpired(certInfo.Certificate) {
					match = true
				}
			case "expiring":
				if !certificate.IsExpired(certInfo.Certificate) && certificate.IsExpiringSoon(certInfo.Certificate) {
					match = true
				}
			case "valid":
				if !certificate.IsExpired(certInfo.Certificate) {
					match = true
				}
			case "self-signed":
				if certInfo.Certificate.Issuer.String() == certInfo.Certificate.Subject.String() {
					// Verify that the certificate is actually self-signed.
					if err := certInfo.Certificate.CheckSignature(certInfo.Certificate.SignatureAlgorithm, certInfo.Certificate.RawTBSCertificate, certInfo.Certificate.Signature); err == nil {
						match = true
					}
				}
			}
		}

		if match {
			filtered = append(filtered, certInfo)
		}
	}

	m.certificates = filtered
	m.cursor = 0
	m.viewMode = ViewNormal
	return m
}

// matchSearch checks if certificate matches search query
func matchSearch(cert *x509.Certificate, query string) bool {
	// Search in Subject fields
	if strings.Contains(strings.ToLower(cert.Subject.CommonName), query) {
		return true
	}
	for _, org := range cert.Subject.Organization {
		if strings.Contains(strings.ToLower(org), query) {
			return true
		}
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToLower(ou), query) {
			return true
		}
	}

	// Search in Issuer fields
	if strings.Contains(strings.ToLower(cert.Issuer.CommonName), query) {
		return true
	}
	for _, org := range cert.Issuer.Organization {
		if strings.Contains(strings.ToLower(org), query) {
			return true
		}
	}
	for _, ou := range cert.Issuer.OrganizationalUnit {
		if strings.Contains(strings.ToLower(ou), query) {
			return true
		}
	}

	// Search in DNS Names (SANs)
	for _, dns := range cert.DNSNames {
		if strings.Contains(strings.ToLower(dns), query) {
			return true
		}
	}
	return false
}

// resetView restores the full list of certificates and clears filters
func (m Model) resetView() Model {
	m = m.resetAllFields()
	m.certificates = m.allCertificates
	m.cursor = 0
	return m
}

// resetAllFields clears all relevant model fields
func (m Model) resetAllFields() Model {
	m.viewMode = ViewNormal
	m.detailField = ""
	m.detailValue = ""
	m.searchQuery = ""
	m.filterActive = false
	m.filterType = ""
	m.rightPaneScroll = 0
	return m
}

// handleExportCommand handles the export of the current certificate
func (m Model) handleExportCommand(filename string) Model {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return m
	}

	if len(m.certificates) == 0 {
		m.popupMessage = "❌ No certificate selected to export"
		m.viewMode = ViewPopup
		m.popupType = PopupAlert
		return m
	}

	cert := m.certificates[m.cursor].Certificate
	// Determine format from filename extension (.pem, .der, .crt, etc.)
	err := certificate.ExportCertificate(cert, "", filename)

	if err != nil {
		m.popupMessage = fmt.Sprintf("❌ Export failed: %v", err)
	} else {
		m.popupMessage = fmt.Sprintf("✅ Certificate exported successfully!\n\nFile: %s\nSubject: %s", filename, cert.Subject.CommonName)
	}

	m.viewMode = ViewPopup
	m.popupType = PopupAlert
	return m
}
