package certificate

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertificateInfo holds certificate data and metadata
type CertificateInfo struct {
	Certificate *x509.Certificate
	Index       int
	Label       string
}

// ChainValidationResult holds the result of chain validation
type ChainValidationResult struct {
	IsValid  bool
	Errors   []string
	Warnings []string
}

// LoadCertificates loads certificates from file or stdin
func LoadCertificates(filename string) ([]*CertificateInfo, error) {
	var data []byte
	var err error

	if filename == "" {
		// Read from stdin
		data, err = io.ReadAll(os.Stdin)
	} else {
		// Read from file
		data, err = os.ReadFile(filename)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	return ParseCertificates(data)
}

// ParseCertificates parses PEM blocks and extracts certificates
func ParseCertificates(data []byte) ([]*CertificateInfo, error) {
	var certs []*CertificateInfo
	rest := data
	index := 0

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate %d: %w", index, err)
			}

			label := generateCertificateLabel(cert, index)
			certs = append(certs, &CertificateInfo{
				Certificate: cert,
				Index:       index,
				Label:       label,
			})
			index++
		}

		rest = remaining
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in input")
	}

	return certs, nil
}

// generateCertificateLabel creates a display label for the certificate
func generateCertificateLabel(cert *x509.Certificate, index int) string {
	cn := cert.Subject.CommonName
	if cn == "" {
		cn = "Unknown"
	}

	// Truncate long common names
	if len(cn) > 30 {
		cn = cn[:27] + "..."
	}

	return fmt.Sprintf("%d. %s", index+1, cn)
}

// GetCertificateDetails returns formatted certificate details
func GetCertificateDetails(cert *x509.Certificate) string {
	var details strings.Builder

	// Subject
	details.WriteString("Subject:\n")
	details.WriteString(fmt.Sprintf("  CN: %s\n", cert.Subject.CommonName))
	if len(cert.Subject.Organization) > 0 {
		details.WriteString(fmt.Sprintf("  O:  %s\n", strings.Join(cert.Subject.Organization, ", ")))
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		details.WriteString(fmt.Sprintf("  OU: %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", ")))
	}
	if len(cert.Subject.Country) > 0 {
		details.WriteString(fmt.Sprintf("  C:  %s\n", strings.Join(cert.Subject.Country, ", ")))
	}
	details.WriteString("\n")

	// Issuer
	details.WriteString("Issuer:\n")
	details.WriteString(fmt.Sprintf("  CN: %s\n", cert.Issuer.CommonName))
	if len(cert.Issuer.Organization) > 0 {
		details.WriteString(fmt.Sprintf("  O:  %s\n", strings.Join(cert.Issuer.Organization, ", ")))
	}
	details.WriteString("\n")

	// Validity
	details.WriteString("Validity:\n")
	details.WriteString(fmt.Sprintf("  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST")))
	details.WriteString(fmt.Sprintf("  Not After:  %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST")))

	// Check if certificate is expired or expiring soon
	now := time.Now()
	if cert.NotAfter.Before(now) {
		details.WriteString("  Status: EXPIRED\n")
	} else if cert.NotAfter.Before(now.AddDate(0, 0, 30)) {
		details.WriteString("  Status: EXPIRING SOON\n")
	} else {
		details.WriteString("  Status: Valid\n")
	}
	details.WriteString("\n")

	// Subject Alternative Names
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 {
		details.WriteString("Subject Alternative Names:\n")
		for _, dns := range cert.DNSNames {
			details.WriteString(fmt.Sprintf("  DNS: %s\n", dns))
		}
		for _, ip := range cert.IPAddresses {
			details.WriteString(fmt.Sprintf("  IP:  %s\n", ip.String()))
		}
		for _, email := range cert.EmailAddresses {
			details.WriteString(fmt.Sprintf("  Email: %s\n", email))
		}
		details.WriteString("\n")
	}

	// Public Key Info
	details.WriteString("Public Key:\n")
	publicKeyInfo := FormatPublicKey(cert)
	for _, line := range strings.Split(publicKeyInfo, "\n") {
		if line != "" {
			details.WriteString(fmt.Sprintf("  %s\n", line))
		}
	}
	details.WriteString("\n")

	// Fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	details.WriteString("SHA256 Fingerprint:\n")
	details.WriteString(fmt.Sprintf("  %x\n", fingerprint))
	details.WriteString("\n")

	// Serial Number
	details.WriteString(fmt.Sprintf("Serial Number: %s\n", cert.SerialNumber.String()))

	return details.String()
}

// IsExpiringSoon checks if certificate expires within 30 days
func IsExpiringSoon(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now().AddDate(0, 0, 30))
}

// IsExpired checks if certificate is expired
func IsExpired(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now())
}

// FormatSubject formats certificate subject information
func FormatSubject(cert *x509.Certificate) string {
	var details strings.Builder

	details.WriteString(fmt.Sprintf("Common Name: %s\n", cert.Subject.CommonName))
	if len(cert.Subject.Organization) > 0 {
		details.WriteString(fmt.Sprintf("Organization: %s\n", strings.Join(cert.Subject.Organization, ", ")))
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		details.WriteString(fmt.Sprintf("Organizational Unit: %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", ")))
	}
	if len(cert.Subject.Country) > 0 {
		details.WriteString(fmt.Sprintf("Country: %s\n", strings.Join(cert.Subject.Country, ", ")))
	}
	if len(cert.Subject.Province) > 0 {
		details.WriteString(fmt.Sprintf("Province: %s\n", strings.Join(cert.Subject.Province, ", ")))
	}
	if len(cert.Subject.Locality) > 0 {
		details.WriteString(fmt.Sprintf("Locality: %s\n", strings.Join(cert.Subject.Locality, ", ")))
	}

	return details.String()
}

// FormatIssuer formats certificate issuer information
func FormatIssuer(cert *x509.Certificate) string {
	var details strings.Builder

	details.WriteString(fmt.Sprintf("Common Name: %s\n", cert.Issuer.CommonName))
	if len(cert.Issuer.Organization) > 0 {
		details.WriteString(fmt.Sprintf("Organization: %s\n", strings.Join(cert.Issuer.Organization, ", ")))
	}
	if len(cert.Issuer.OrganizationalUnit) > 0 {
		details.WriteString(fmt.Sprintf("Organizational Unit: %s\n", strings.Join(cert.Issuer.OrganizationalUnit, ", ")))
	}
	if len(cert.Issuer.Country) > 0 {
		details.WriteString(fmt.Sprintf("Country: %s\n", strings.Join(cert.Issuer.Country, ", ")))
	}

	return details.String()
}

// FormatValidity formats certificate validity information
func FormatValidity(cert *x509.Certificate) string {
	var details strings.Builder

	details.WriteString(fmt.Sprintf("Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST")))
	details.WriteString(fmt.Sprintf("Not After:  %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST")))

	now := time.Now()
	duration := cert.NotAfter.Sub(now)

	if cert.NotAfter.Before(now) {
		details.WriteString("Status: EXPIRED\n")
		details.WriteString(fmt.Sprintf("Expired: %s ago\n", (-duration).String()))
	} else if cert.NotAfter.Before(now.AddDate(0, 0, 30)) {
		details.WriteString("Status: EXPIRING SOON\n")
		details.WriteString(fmt.Sprintf("Expires in: %s\n", duration.String()))
	} else {
		details.WriteString("Status: Valid\n")
		details.WriteString(fmt.Sprintf("Expires in: %s\n", duration.String()))
	}

	return details.String()
}

// FormatSAN formats Subject Alternative Names
func FormatSAN(cert *x509.Certificate) string {
	var details strings.Builder

	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 && len(cert.EmailAddresses) == 0 {
		return "No Subject Alternative Names found"
	}

	if len(cert.DNSNames) > 0 {
		details.WriteString("DNS Names:\n")
		for _, dns := range cert.DNSNames {
			details.WriteString(fmt.Sprintf("  %s\n", dns))
		}
		details.WriteString("\n")
	}

	if len(cert.IPAddresses) > 0 {
		details.WriteString("IP Addresses:\n")
		for _, ip := range cert.IPAddresses {
			details.WriteString(fmt.Sprintf("  %s\n", ip.String()))
		}
		details.WriteString("\n")
	}

	if len(cert.EmailAddresses) > 0 {
		details.WriteString("Email Addresses:\n")
		for _, email := range cert.EmailAddresses {
			details.WriteString(fmt.Sprintf("  %s\n", email))
		}
	}

	return details.String()
}

// FormatFingerprint formats certificate fingerprint
func FormatFingerprint(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", fingerprint)
}

// FormatPublicKey formats public key information with detailed specifications
func FormatPublicKey(cert *x509.Certificate) string {
	var details strings.Builder

	details.WriteString(fmt.Sprintf("Algorithm: %s\n", cert.PublicKeyAlgorithm.String()))

	// Detailed key information based on type
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pub.Size() * 8
		details.WriteString(fmt.Sprintf("Type: RSA%d\n", keySize))
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", keySize))
		details.WriteString(fmt.Sprintf("Modulus Size: %d bytes\n", pub.Size()))
		details.WriteString(fmt.Sprintf("Public Exponent: %d\n", pub.E))

	case *ecdsa.PublicKey:
		curveName := pub.Curve.Params().Name
		keySize := pub.Curve.Params().BitSize
		details.WriteString(fmt.Sprintf("Type: ECDSA\n"))
		details.WriteString(fmt.Sprintf("Curve: %s\n", curveName))
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", keySize))

		// Add common curve information
		switch curveName {
		case "P-256":
			details.WriteString("Standard: NIST P-256 (secp256r1)\n")
		case "P-384":
			details.WriteString("Standard: NIST P-384 (secp384r1)\n")
		case "P-521":
			details.WriteString("Standard: NIST P-521 (secp521r1)\n")
		}

	default:
		details.WriteString(fmt.Sprintf("Type: %T\n", pub))
		details.WriteString("Key Size: Unknown\n")
	}

	return details.String()
}

// ValidateChain validates the certificate chain
func ValidateChain(certs []*CertificateInfo) *ChainValidationResult {
	result := &ChainValidationResult{
		IsValid:  true,
		Errors:   []string{},
		Warnings: []string{},
	}

	if len(certs) == 0 {
		result.IsValid = false
		result.Errors = append(result.Errors, "No certificates in chain")
		return result
	}

	// Check each certificate individually
	for i, certInfo := range certs {
		cert := certInfo.Certificate

		// Check if certificate is expired
		now := time.Now()
		if cert.NotAfter.Before(now) {
			result.Errors = append(result.Errors, fmt.Sprintf("Certificate %d is expired", i+1))
			result.IsValid = false
		}

		// Check if certificate is not yet valid
		if cert.NotBefore.After(now) {
			result.Errors = append(result.Errors, fmt.Sprintf("Certificate %d is not yet valid", i+1))
			result.IsValid = false
		}

		// Check if certificate expires soon
		if IsExpiringSoon(cert) && !IsExpired(cert) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Certificate %d expires within 30 days", i+1))
		}
	}

	// Check chain order and signatures
	if len(certs) > 1 {
		for i := 0; i < len(certs)-1; i++ {
			current := certs[i].Certificate
			next := certs[i+1].Certificate

			// Check if current certificate is signed by next certificate
			err := current.CheckSignatureFrom(next)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Certificate %d signature verification failed against certificate %d: %v", i+1, i+2, err))
			}
		}
	}

	return result
}

// FormatChainValidation formats chain validation results
func FormatChainValidation(result *ChainValidationResult) string {
	var details strings.Builder

	if result.IsValid {
		details.WriteString("✅ Certificate chain is VALID\n\n")
	} else {
		details.WriteString("❌ Certificate chain is INVALID\n\n")
	}

	if len(result.Errors) > 0 {
		details.WriteString("Errors:\n")
		for _, err := range result.Errors {
			details.WriteString(fmt.Sprintf("  • %s\n", err))
		}
		details.WriteString("\n")
	}

	if len(result.Warnings) > 0 {
		details.WriteString("Warnings:\n")
		for _, warning := range result.Warnings {
			details.WriteString(fmt.Sprintf("  • %s\n", warning))
		}
		details.WriteString("\n")
	}

	if len(result.Errors) == 0 && len(result.Warnings) == 0 {
		details.WriteString("No issues found in the certificate chain.\n")
	}

	return details.String()
}

// ExportCertificate exports a certificate in the specified format
func ExportCertificate(cert *x509.Certificate, format string, filename string) error {
	var data []byte
	var err error

	switch strings.ToLower(format) {
	case "pem":
		data = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	case "der":
		data = cert.Raw
	default:
		return fmt.Errorf("unsupported format: %s (supported: pem, der)", format)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if dir != "." {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// SearchCertificates searches certificates based on query
func SearchCertificates(certs []*CertificateInfo, query string) []*CertificateInfo {
	if query == "" {
		return certs
	}

	query = strings.ToLower(query)
	var results []*CertificateInfo

	for _, certInfo := range certs {
		cert := certInfo.Certificate

		// Search in common name
		if strings.Contains(strings.ToLower(cert.Subject.CommonName), query) {
			results = append(results, certInfo)
			continue
		}

		// Search in organization
		for _, org := range cert.Subject.Organization {
			if strings.Contains(strings.ToLower(org), query) {
				results = append(results, certInfo)
				goto next
			}
		}

		// Search in DNS names
		for _, dns := range cert.DNSNames {
			if strings.Contains(strings.ToLower(dns), query) {
				results = append(results, certInfo)
				goto next
			}
		}

		// Search in issuer
		if strings.Contains(strings.ToLower(cert.Issuer.CommonName), query) {
			results = append(results, certInfo)
			continue
		}

	next:
	}

	return results
}

// FilterCertificates filters certificates based on criteria
func FilterCertificates(certs []*CertificateInfo, filterType string) []*CertificateInfo {
	var results []*CertificateInfo

	for _, certInfo := range certs {
		cert := certInfo.Certificate

		switch filterType {
		case "expired":
			if IsExpired(cert) {
				results = append(results, certInfo)
			}
		case "expiring":
			if IsExpiringSoon(cert) && !IsExpired(cert) {
				results = append(results, certInfo)
			}
		case "valid":
			if !IsExpired(cert) && !IsExpiringSoon(cert) {
				results = append(results, certInfo)
			}
		case "self-signed":
			if cert.Subject.String() == cert.Issuer.String() {
				results = append(results, certInfo)
			}
		default:
			results = append(results, certInfo)
		}
	}

	return results
}
