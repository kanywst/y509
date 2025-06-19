package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}
}

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

// ValidationResult represents the result of certificate chain validation
type ValidationResult struct {
	IsValid  bool
	Errors   []string
	Warnings []string
}

// LoadCertificates loads certificates from a file or stdin
func LoadCertificates(filename string) ([]*CertificateInfo, error) {
	var input io.Reader
	if filename == "" {
		input = os.Stdin
	} else {
		file, err := os.Open(filename)
		if err != nil {
			logger.Error("Failed to open file", zap.Error(err))
			return nil, fmt.Errorf("failed to read input: %w", err)
		}
		defer file.Close()
		input = file
	}

	data, err := io.ReadAll(input)
	if err != nil {
		logger.Error("Failed to read input", zap.Error(err))
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	if len(data) == 0 {
		logger.Error("Empty input")
		return nil, fmt.Errorf("empty input")
	}

	// Try to parse as PEM first
	block, rest := pem.Decode(data)
	if block == nil {
		logger.Error("Failed to decode PEM data")
		return nil, fmt.Errorf("failed to parse certificate %d: %w", 0, err)
	}

	var certs []*CertificateInfo
	index := 0
	for block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Error("Failed to parse certificate", zap.Error(err))
			return nil, fmt.Errorf("failed to parse certificate %d: %w", index, err)
		}
		certs = append(certs, &CertificateInfo{
			Certificate: cert,
			Label:       cert.Subject.CommonName,
		})
		block, rest = pem.Decode(rest)
		index++
	}

	if len(certs) == 0 {
		logger.Error("No certificates found in input")
		return nil, fmt.Errorf("no certificates found in input")
	}

	return certs, nil
}

// FormatCertificateList formats a list of certificates for display
func FormatCertificateList(certs []*CertificateInfo) string {
	var result strings.Builder
	for i, cert := range certs {
		result.WriteString(formatCertificateListItem(i, cert))
	}
	return result.String()
}

func formatCertificateListItem(index int, cert *CertificateInfo) string {
	cn := cert.Certificate.Subject.CommonName
	if cn == "" {
		cn = "Unknown"
	}
	return fmt.Sprintf("%d. %s", index+1, cn)
}

// FormatCertificateDetails formats detailed certificate information
func FormatCertificateDetails(cert *CertificateInfo) string {
	var details strings.Builder

	// Subject
	details.WriteString("Subject:\n")
	details.WriteString(fmt.Sprintf("  CN: %s\n", cert.Certificate.Subject.CommonName))
	if len(cert.Certificate.Subject.Organization) > 0 {
		details.WriteString(fmt.Sprintf("  O:  %s\n", strings.Join(cert.Certificate.Subject.Organization, ", ")))
	}
	if len(cert.Certificate.Subject.OrganizationalUnit) > 0 {
		details.WriteString(fmt.Sprintf("  OU: %s\n", strings.Join(cert.Certificate.Subject.OrganizationalUnit, ", ")))
	}
	if len(cert.Certificate.Subject.Country) > 0 {
		details.WriteString(fmt.Sprintf("  C:  %s\n", strings.Join(cert.Certificate.Subject.Country, ", ")))
	}

	// Issuer
	details.WriteString("\nIssuer:\n")
	details.WriteString(fmt.Sprintf("  CN: %s\n", cert.Certificate.Issuer.CommonName))
	if len(cert.Certificate.Issuer.Organization) > 0 {
		details.WriteString(fmt.Sprintf("  O:  %s\n", strings.Join(cert.Certificate.Issuer.Organization, ", ")))
	}

	// Validity
	details.WriteString("\nValidity:\n")
	details.WriteString(fmt.Sprintf("  Not Before: %s\n", cert.Certificate.NotBefore.Format("2006-01-02 15:04:05 MST")))
	details.WriteString(fmt.Sprintf("  Not After:  %s\n", cert.Certificate.NotAfter.Format("2006-01-02 15:04:05 MST")))

	// Subject Alternative Names
	if len(cert.Certificate.DNSNames) > 0 || len(cert.Certificate.IPAddresses) > 0 || len(cert.Certificate.EmailAddresses) > 0 {
		details.WriteString("\nSubject Alternative Names:\n")
		for _, dns := range cert.Certificate.DNSNames {
			details.WriteString(fmt.Sprintf("  DNS: %s\n", dns))
		}
		for _, ip := range cert.Certificate.IPAddresses {
			details.WriteString(fmt.Sprintf("  IP:  %s\n", ip.String()))
		}
		for _, email := range cert.Certificate.EmailAddresses {
			details.WriteString(fmt.Sprintf("  Email: %s\n", email))
		}
	}

	// Key Usage
	if len(cert.Certificate.ExtKeyUsage) > 0 {
		details.WriteString("\nKey Usage:\n")
		for _, usage := range cert.Certificate.ExtKeyUsage {
			details.WriteString(fmt.Sprintf("  %s\n", formatExtKeyUsage(usage)))
		}
	}

	// Fingerprint
	details.WriteString("\nFingerprint:\n")
	fingerprint := make([]byte, len(cert.Certificate.Raw))
	copy(fingerprint, cert.Certificate.Raw)
	for i := 0; i < len(fingerprint); i += 16 {
		end := i + 16
		if end > len(fingerprint) {
			end = len(fingerprint)
		}
		line := fingerprint[i:end]
		details.WriteString(fmt.Sprintf("  %x\n", line))
	}

	return details.String()
}

// formatExtKeyUsage formats an ExtKeyUsage value as a string
func formatExtKeyUsage(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "Server Authentication"
	case x509.ExtKeyUsageClientAuth:
		return "Client Authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		return "Email Protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC End System"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC Tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC User"
	case x509.ExtKeyUsageTimeStamping:
		return "Time Stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP Signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft Server Gated Crypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "Netscape Server Gated Crypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "Microsoft Commercial Code Signing"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "Microsoft Kernel Code Signing"
	default:
		return fmt.Sprintf("Unknown (%d)", usage)
	}
}

// FormatCertificateSummary formats a summary of certificate information
func FormatCertificateSummary(cert *CertificateInfo) string {
	var details strings.Builder

	// Serial Number
	details.WriteString(fmt.Sprintf("Serial Number: %s\n", cert.Certificate.SerialNumber.String()))

	// Subject
	details.WriteString("\nSubject:\n")
	details.WriteString(fmt.Sprintf("Common Name: %s\n", cert.Certificate.Subject.CommonName))
	if len(cert.Certificate.Subject.Organization) > 0 {
		details.WriteString(fmt.Sprintf("Organization: %s\n", strings.Join(cert.Certificate.Subject.Organization, ", ")))
	}
	if len(cert.Certificate.Subject.OrganizationalUnit) > 0 {
		details.WriteString(fmt.Sprintf("Organizational Unit: %s\n", strings.Join(cert.Certificate.Subject.OrganizationalUnit, ", ")))
	}
	if len(cert.Certificate.Subject.Country) > 0 {
		details.WriteString(fmt.Sprintf("Country: %s\n", strings.Join(cert.Certificate.Subject.Country, ", ")))
	}

	// Issuer
	details.WriteString("\nIssuer:\n")
	details.WriteString(fmt.Sprintf("Common Name: %s\n", cert.Certificate.Issuer.CommonName))
	if len(cert.Certificate.Issuer.Organization) > 0 {
		details.WriteString(fmt.Sprintf("Organization: %s\n", strings.Join(cert.Certificate.Issuer.Organization, ", ")))
	}
	if len(cert.Certificate.Issuer.OrganizationalUnit) > 0 {
		details.WriteString(fmt.Sprintf("Organizational Unit: %s\n", strings.Join(cert.Certificate.Issuer.OrganizationalUnit, ", ")))
	}
	if len(cert.Certificate.Issuer.Country) > 0 {
		details.WriteString(fmt.Sprintf("Country: %s\n", strings.Join(cert.Certificate.Issuer.Country, ", ")))
	}

	// Validity
	details.WriteString("\nValidity:\n")
	details.WriteString(fmt.Sprintf("Not Before: %s\n", cert.Certificate.NotBefore.Format("2006-01-02 15:04:05 MST")))
	details.WriteString(fmt.Sprintf("Not After:  %s\n", cert.Certificate.NotAfter.Format("2006-01-02 15:04:05 MST")))

	// Expiration
	now := time.Now()
	duration := cert.Certificate.NotAfter.Sub(now)
	if duration < 0 {
		details.WriteString(fmt.Sprintf("Expired: %s ago\n", (-duration).String()))
	} else if duration < 30*24*time.Hour {
		details.WriteString(fmt.Sprintf("Expires in: %s\n", duration.String()))
	} else {
		details.WriteString(fmt.Sprintf("Expires in: %s\n", duration.String()))
	}

	// Subject Alternative Names
	if len(cert.Certificate.DNSNames) > 0 || len(cert.Certificate.IPAddresses) > 0 || len(cert.Certificate.EmailAddresses) > 0 {
		details.WriteString("\nSubject Alternative Names:\n")
		for _, dns := range cert.Certificate.DNSNames {
			details.WriteString(fmt.Sprintf("  %s\n", dns))
		}
		for _, ip := range cert.Certificate.IPAddresses {
			details.WriteString(fmt.Sprintf("  %s\n", ip.String()))
		}
		for _, email := range cert.Certificate.EmailAddresses {
			details.WriteString(fmt.Sprintf("  %s\n", email))
		}
	}

	// Fingerprint
	details.WriteString("\nFingerprint:\n")
	details.WriteString(fmt.Sprintf("%x", cert.Certificate.Raw))

	return details.String()
}

// FormatCertificateKeyInfo formats information about the certificate's public key
func FormatCertificateKeyInfo(cert *CertificateInfo) string {
	var details strings.Builder

	// Algorithm
	details.WriteString(fmt.Sprintf("Algorithm: %s\n", cert.Certificate.PublicKeyAlgorithm.String()))

	// Key details
	switch pub := cert.Certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pub.Size() * 8
		details.WriteString(fmt.Sprintf("Type: RSA%d\n", keySize))
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", keySize))
		details.WriteString(fmt.Sprintf("Modulus Size: %d bytes\n", pub.Size()))
		details.WriteString(fmt.Sprintf("Public Exponent: %d\n", pub.E))
	case *ecdsa.PublicKey:
		keySize := pub.Curve.Params().BitSize
		curveName := pub.Curve.Params().Name
		details.WriteString(fmt.Sprintf("Type: ECDSA\n"))
		details.WriteString(fmt.Sprintf("Curve: %s\n", curveName))
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", keySize))
	default:
		details.WriteString(fmt.Sprintf("Type: %T\n", pub))
	}

	return details.String()
}

// ValidateChain validates a certificate chain
func ValidateChain(certs []*x509.Certificate) (bool, error) {
	if len(certs) == 0 {
		return false, fmt.Errorf("empty certificate chain")
	}

	now := time.Now()
	for i, cert := range certs {
		// Check expiration
		if cert.NotAfter.Before(now) {
			return false, fmt.Errorf("certificate %d expired on %s", i, cert.NotAfter.Format(time.RFC3339))
		}

		// Check if not yet valid
		if cert.NotBefore.After(now) {
			return false, fmt.Errorf("certificate %d is not yet valid (valid from %s)", i, cert.NotBefore.Format(time.RFC3339))
		}

		// Check chain validity
		if i > 0 {
			parent := certs[i-1]
			if err := cert.CheckSignatureFrom(parent); err != nil {
				return false, fmt.Errorf("invalid signature for certificate %d: %v", i, err)
			}
		}
	}

	return true, nil
}

// FormatChainValidation formats the validation results
func FormatChainValidation(result *ValidationResult) string {
	if result.IsValid {
		return "✅️ Certificate chain is valid"
	}

	var sb strings.Builder
	sb.WriteString("❌️ Certificate chain validation failed:\n")

	if len(result.Errors) > 0 {
		sb.WriteString("Errors:\n")
		for _, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("  • %s\n", err))
		}
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("Warnings:\n")
		for _, warning := range result.Warnings {
			sb.WriteString(fmt.Sprintf("  • %s\n", warning))
		}
	}

	return strings.TrimSpace(sb.String())
}

// ExportCertificate exports a certificate to a file
func ExportCertificate(cert *x509.Certificate, format string, filename string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}

	// Open file for writing
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	// Export based on format
	switch filepath.Ext(filename) {
	case ".pem":
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(file, block); err != nil {
			return fmt.Errorf("failed to encode PEM: %v", err)
		}
	case ".der":
		if _, err := file.Write(cert.Raw); err != nil {
			return fmt.Errorf("failed to write DER: %v", err)
		}
	default:
		return fmt.Errorf("unsupported format: %s (supported: pem, der)", filepath.Ext(filename))
	}

	return nil
}

// GenerateSelfSignedCert generates a self-signed certificate
func GenerateSelfSignedCert(host string, certFile, keyFile string) error {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Error("Failed to generate private key", zap.Error(err))
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Error("Failed to generate serial number", zap.Error(err))
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Y509"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年間有効
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Set IP address or hostname
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		logger.Error("Failed to create certificate", zap.Error(err))
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		logger.Error("Failed to open cert file for writing", zap.Error(err))
		return fmt.Errorf("failed to open cert file for writing: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		logger.Error("Failed to write cert data", zap.Error(err))
		return fmt.Errorf("failed to write cert data: %w", err)
	}
	if err := certOut.Close(); err != nil {
		logger.Error("Failed to close cert file", zap.Error(err))
		return fmt.Errorf("failed to close cert file: %w", err)
	}

	// Write private key to file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		logger.Error("Failed to open key file for writing", zap.Error(err))
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		logger.Error("Failed to marshal private key", zap.Error(err))
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		logger.Error("Failed to write key data", zap.Error(err))
		return fmt.Errorf("failed to write key data: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		logger.Error("Failed to close key file", zap.Error(err))
		return fmt.Errorf("failed to close key file: %w", err)
	}

	logger.Info("Self-signed certificate generated successfully",
		zap.String("certFile", certFile),
		zap.String("keyFile", keyFile))
	return nil
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
				logger.Error("Failed to parse certificate", zap.Error(err))
				return nil, fmt.Errorf("failed to parse certificate %d: %w", index, err)
			}

			label := generateCertificateLabel(cert, index)
			certs = append(certs, &CertificateInfo{
				Certificate: cert,
				Index:       index,
				Label:       label,
			})
		}

		rest = remaining
		index++
	}

	if len(certs) == 0 {
		logger.Error("No certificates found in input")
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

// IsExpired checks if certificate is expired
func IsExpired(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now())
}

// IsExpiringSoon checks if certificate expires within 30 days
func IsExpiringSoon(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now().AddDate(0, 0, 30))
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

	// Algorithm
	details.WriteString(fmt.Sprintf("Algorithm: %s\n", cert.PublicKeyAlgorithm.String()))

	// Key details
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pub.N.BitLen()
		details.WriteString(fmt.Sprintf("Type: RSA%d\n", keySize))
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", keySize))
		details.WriteString(fmt.Sprintf("Modulus Size: %d bytes\n", pub.Size()))
		details.WriteString(fmt.Sprintf("Public Exponent: %d\n", pub.E))
	case *ecdsa.PublicKey:
		keySize := pub.Curve.Params().BitSize
		curveName := pub.Curve.Params().Name
		details.WriteString(fmt.Sprintf("Type: ECDSA\n"))
		details.WriteString(fmt.Sprintf("Curve: %s\n", curveName))
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", keySize))

		// Add common curve information
		switch curveName {
		case "P-256":
			details.WriteString("Standard: NIST P-256\n")
		case "P-384":
			details.WriteString("Standard: NIST P-384\n")
		case "P-521":
			details.WriteString("Standard: NIST P-521\n")
		}
	default:
		details.WriteString(fmt.Sprintf("Type: %T\n", pub))
	}

	return details.String()
}
