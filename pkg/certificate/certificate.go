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
	"strings"
	"time"
)

// CertificateInfo holds certificate data and metadata
type CertificateInfo struct {
	Certificate *x509.Certificate
	Index       int
	Label       string
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
	details.WriteString(fmt.Sprintf("  Algorithm: %s\n", cert.PublicKeyAlgorithm.String()))
	switch pub := cert.PublicKey.(type) {
	case *x509.Certificate:
		// This shouldn't happen, but just in case
		details.WriteString("  Type: Certificate (unexpected)\n")
	default:
		details.WriteString(fmt.Sprintf("  Type: %T\n", pub))
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

// FormatPublicKey formats public key information
func FormatPublicKey(cert *x509.Certificate) string {
	var details strings.Builder

	details.WriteString(fmt.Sprintf("Algorithm: %s\n", cert.PublicKeyAlgorithm.String()))
	details.WriteString(fmt.Sprintf("Type: %T\n", cert.PublicKey))

	// Add key size information if available
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", pub.Size()*8))
	case *ecdsa.PublicKey:
		details.WriteString(fmt.Sprintf("Curve: %s\n", pub.Curve.Params().Name))
	}

	return details.String()
}
