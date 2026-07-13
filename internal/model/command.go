// Package model provides the core TUI application logic and view.
package model

import (
	"fmt"
	"strings"

	"crypto/x509"
	"encoding/pem"

	tea "charm.land/bubbletea/v2"
	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
)

// handleValidateCommand verifies the chain the selected certificate sits in,
// against the system trust store. It deliberately shares VerifyChain with the
// validate subcommand so that `v` and `y509 validate` can never disagree.
func (m Model) handleValidateCommand() Model {
	logger.Log.Debug("validating selected certificate")

	if len(m.certificates) == 0 {
		return m
	}

	leaf := m.certificates[m.list.Index()].Certificate

	// Verify the selected certificate as the leaf, offering everything else
	// that was loaded as a possible intermediate.
	chain := []*x509.Certificate{leaf}
	for _, c := range m.allCertificates {
		if c.Certificate.Equal(leaf) {
			continue
		}
		chain = append(chain, c.Certificate)
	}

	result, err := certificate.VerifyChain(chain, certificate.VerifyOptions{})
	if err != nil {
		m.popupMessage = fmt.Sprintf("❌  Could not verify\n\n%v", err)
		m.viewMode = ViewPopup
		m.popupType = PopupAlert
		return m
	}

	var sb strings.Builder
	switch result.Level {
	case certificate.TrustAnchored:
		sb.WriteString("✅  Certificate is TRUSTED\n\n")
		fmt.Fprintf(&sb, "Subject: %s\n", leaf.Subject.CommonName)
		fmt.Fprintf(&sb, "Issuer:  %s\n", leaf.Issuer.CommonName)
		fmt.Fprintf(&sb, "Anchor:  %s (system trust store)", result.Anchor)

	case certificate.TrustSelfAnchored:
		sb.WriteString("⚠️   Certificate is SELF-ANCHORED\n\n")
		fmt.Fprintf(&sb, "Subject: %s\n", leaf.Subject.CommonName)
		fmt.Fprintf(&sb, "Issuer:  %s\n", leaf.Issuer.CommonName)
		fmt.Fprintf(&sb, "Anchor:  %s (from this file, not trusted)\n\n", result.Anchor)
		sb.WriteString("The chain links up, but its root is not in the system trust\nstore, so a TLS client would reject it.")

	default:
		sb.WriteString("❌  Certificate is INVALID\n\n")
		fmt.Fprintf(&sb, "Subject: %s\n", leaf.Subject.CommonName)
		fmt.Fprintf(&sb, "Issuer:  %s\n\n", leaf.Issuer.CommonName)
		fmt.Fprintf(&sb, "%v", result.Err)
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
				if !certificate.IsExpired(certInfo.Certificate) && certificate.IsExpiringSoonWithin(certInfo.Certificate, m.Config.ExpiryWarningDays) {
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
	m.list.SetItems(toListItems(filtered))
	m.list.Select(0)
	m.viewMode = ViewNormal
	m = m.refreshViewportContent()
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
	m.list.SetItems(toListItems(m.allCertificates))
	m.list.Select(0)
	m = m.refreshViewportContent()
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
	m.viewport.SetYOffset(0)
	return m
}

// handleYankCommand encodes the selected certificate as PEM and ships it
// to the system clipboard via OSC52, then opens an alert popup so the
// user knows the copy succeeded (or why it didn't).
func (m Model) handleYankCommand() (Model, tea.Cmd) {
	if len(m.certificates) == 0 {
		return m, nil
	}
	cert := m.certificates[m.list.Index()].Certificate
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if pemBytes == nil {
		m.popupMessage = "❌ Failed to encode certificate as PEM"
		m.viewMode = ViewPopup
		m.popupType = PopupAlert
		return m, nil
	}
	m.popupMessage = fmt.Sprintf("✅ Copied PEM to clipboard\n\nSubject: %s\nBytes:   %d", cert.Subject.CommonName, len(pemBytes))
	m.viewMode = ViewPopup
	m.popupType = PopupAlert
	return m, tea.SetClipboard(string(pemBytes))
}

// handleExportCommand handles the export of the current certificate
func (m Model) handleExportCommand(filename string) Model {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		// Defensive: the export form's required-validator should prevent
		// this, but if we're somehow asked to export an empty filename
		// while the export popup is open, close it instead of leaving
		// the user stranded with no form to interact with.
		if m.viewMode == ViewPopup && m.popupType == PopupExport {
			m.viewMode = ViewNormal
			m.popupType = PopupNone
		}
		return m
	}

	if len(m.certificates) == 0 {
		m.popupMessage = "❌ No certificate selected to export"
		m.viewMode = ViewPopup
		m.popupType = PopupAlert
		return m
	}

	cert := m.certificates[m.list.Index()].Certificate
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
