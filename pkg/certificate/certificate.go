// Package certificate provides functionality for loading, parsing, and validating X.509 certificates and chains.
package certificate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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

// ValidationStatus represents the validation status of a single certificate in the chain.
type ValidationStatus int

const (
	// StatusUnknown represents an uninitialized or unknown status
	StatusUnknown ValidationStatus = iota
	// StatusValid represents a verified valid certificate
	StatusValid
	// StatusGood represents a certificate that is syntactically correct and not expired
	StatusGood
	// StatusWarning represents a potential issue (e.g., expiring soon)
	StatusWarning
	// StatusExpired represents an expired certificate
	StatusExpired
	// StatusRevoked represents a revoked certificate
	StatusRevoked
	// StatusMismatchedIssuer represents a chain link error where issuer doesn't match
	StatusMismatchedIssuer
	// StatusInvalidSignature represents a failed signature verification
	StatusInvalidSignature
)

// Info holds certificate data and metadata
type Info struct {
	Certificate      *x509.Certificate
	Index            int
	Label            string
	ValidationStatus ValidationStatus
	ValidationError  error
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
func LoadCertificates(filename string) ([]*Info, error) {
	var input io.Reader
	if filename == "" {
		input = os.Stdin
	} else {
		file, err := os.Open(filename)
		if err != nil {
			logger.Error("Failed to open file", zap.Error(err))
			return nil, fmt.Errorf("failed to read input: %w", err)
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				logger.Error("Failed to close input file", zap.String("filename", filename), zap.Error(closeErr))
			}
		}()
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

	return ParseCertificates(data)
}

// FormatCertificateList formats a list of certificates for display
func FormatCertificateList(certs []*Info) string {
	var result strings.Builder
	for i, cert := range certs {
		result.WriteString(formatCertificateListItem(i, cert))
	}
	return result.String()
}

func formatCertificateListItem(index int, cert *Info) string {
	cn := cert.Certificate.Subject.CommonName
	if cn == "" {
		cn = "Unknown"
	}
	return fmt.Sprintf("%d. %s", index+1, cn)
}

// FormatCertificateDetails formats detailed certificate information
func FormatCertificateDetails(cert *Info) string {
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

	// Basic Constraints
	if cert.Certificate.BasicConstraintsValid {
		details.WriteString("\nBasic Constraints:\n")
		details.WriteString(fmt.Sprintf("  CA: %v\n", cert.Certificate.IsCA))
		if cert.Certificate.MaxPathLen > 0 || (cert.Certificate.MaxPathLen == 0 && cert.Certificate.MaxPathLenZero) {
			details.WriteString(fmt.Sprintf("  Max Path Len: %d\n", cert.Certificate.MaxPathLen))
		}
	}

	// Authority Information Access
	if len(cert.Certificate.IssuingCertificateURL) > 0 || len(cert.Certificate.OCSPServer) > 0 {
		details.WriteString("\nAuthority Information Access:\n")
		for _, url := range cert.Certificate.IssuingCertificateURL {
			details.WriteString(fmt.Sprintf("  Issuer: %s\n", url))
		}
		for _, url := range cert.Certificate.OCSPServer {
			details.WriteString(fmt.Sprintf("  OCSP:   %s\n", url))
		}
	}

	// CRL Distribution Points
	if len(cert.Certificate.CRLDistributionPoints) > 0 {
		details.WriteString("\nCRL Distribution Points:\n")
		for _, url := range cert.Certificate.CRLDistributionPoints {
			details.WriteString(fmt.Sprintf("  %s\n", url))
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
func FormatCertificateSummary(cert *Info) string {
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
func FormatCertificateKeyInfo(cert *Info) string {
	var details strings.Builder

	// Algorithm
	// Key details
	switch pub := cert.Certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pub.N.BitLen()
		details.WriteString("Type: RSA\n")
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", keySize))
		details.WriteString(fmt.Sprintf("Modulus Size: %d bytes\n", pub.Size()))
		details.WriteString(fmt.Sprintf("Public Exponent: %d\n", pub.E))
	case *ecdsa.PublicKey:
		keySize := pub.Curve.Params().BitSize
		curveName := pub.Curve.Params().Name
		details.WriteString("Type: ECDSA\n")
		details.WriteString(fmt.Sprintf("Curve: %s\n", curveName))
		details.WriteString(fmt.Sprintf("Key Size: %d bits\n", keySize))
	case ed25519.PublicKey:
		details.WriteString("Type: Ed25519\n")
		details.WriteString("Key Size: 256 bits\n")
	default:
		details.WriteString(fmt.Sprintf("Type: %T\n", pub))
	}

	return details.String()
}

// SortChain sorts certificates into valid chains [Leaf, Intermediate, Root]
func SortChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, nil
	}

	// 1. Build parent-child relationships
	parentOf := make(map[int]int) // child index -> parent index
	isParent := make(map[int]bool)

	for childIdx, child := range certs {
		for parentIdx, parent := range certs {
			if childIdx == parentIdx {
				continue
			}

			// Name check first
			if child.Issuer.String() != parent.Subject.String() {
				continue
			}

			// Signature check
			if err := child.CheckSignatureFrom(parent); err == nil {
				parentOf[childIdx] = parentIdx
				isParent[parentIdx] = true
			}
		}
	}

	// 2. Identify all possible Leaf nodes (certs that are not parents of anyone in this set)
	var leafIndices []int
	for i := range certs {
		if !isParent[i] {
			leafIndices = append(leafIndices, i)
		}
	}

	// If everything is a parent (cycle?), just use all indices
	if len(leafIndices) == 0 {
		for i := range certs {
			leafIndices = append(leafIndices, i)
		}
	}

	// 3. Build all possible disjoint chains
	var sortedCerts []*x509.Certificate
	seenInChain := make(map[int]bool)
	chainCount := 0

	for _, lIdx := range leafIndices {
		if seenInChain[lIdx] {
			continue
		}
		chainCount++

		// Build chain upwards from this leaf
		var currentChain []*x509.Certificate
		curr := lIdx
		for {
			if seenInChain[curr] {
				break
			}
			currentChain = append(currentChain, certs[curr])
			seenInChain[curr] = true

			pIdx, ok := parentOf[curr]
			if !ok {
				break
			}
			curr = pIdx
		}

		// Add currentChain to result [Leaf, ..., Root]
		sortedCerts = append(sortedCerts, currentChain...)
	}

	if chainCount > 1 {
		logger.Warn(fmt.Sprintf("Detected %d disjoint certificate chains; they will be displayed sequentially.", chainCount))
	}

	// 4. Append any certificates that were not included in any chain
	for i, cert := range certs {
		if !seenInChain[i] {
			sortedCerts = append(sortedCerts, cert)
		}
	}

	return sortedCerts, nil
}

// ValidateChainLinks performs a detailed validation of each link in the certificate chain.
// It no longer assumes the certs are sorted.
func ValidateChainLinks(certs []*Info) {
	// Create a map of subjects for quick parent lookup
	subjectMap := make(map[string]*x509.Certificate)
	for _, c := range certs {
		subjectMap[c.Certificate.Subject.String()] = c.Certificate
	}

	for _, certInfo := range certs {
		cert := certInfo.Certificate

		// Reset status
		certInfo.ValidationStatus = StatusGood
		certInfo.ValidationError = nil

		// 1. Check expiration
		now := time.Now()
		if now.After(cert.NotAfter) {
			certInfo.ValidationStatus = StatusExpired
			certInfo.ValidationError = fmt.Errorf("certificate is expired")
			continue // Don't bother with other checks if expired
		}
		if now.Before(cert.NotBefore) {
			certInfo.ValidationStatus = StatusWarning
			certInfo.ValidationError = fmt.Errorf("certificate is not yet valid")
		}

		// 2. Check signature link
		// Is it a self-signed root?
		if cert.Issuer.String() == cert.Subject.String() {
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				certInfo.ValidationStatus = StatusInvalidSignature
				certInfo.ValidationError = fmt.Errorf("self-signed certificate has an invalid signature: %w", err)
			}
			// If self-signed and valid, its status remains StatusGood (or StatusWarning if not yet valid)
			continue
		}

		// It's not self-signed, so it must have a parent.
		parentCert, found := subjectMap[cert.Issuer.String()]

		if !found {
			// Parent is not in the provided list, it's an orphan.
			certInfo.ValidationStatus = StatusMismatchedIssuer
			certInfo.ValidationError = fmt.Errorf("issuer ('%s') not found in provided certificates", cert.Issuer.CommonName)
			continue
		}

		// Parent is found, check the signature.
		if err := cert.CheckSignatureFrom(parentCert); err != nil {
			certInfo.ValidationStatus = StatusInvalidSignature
			certInfo.ValidationError = fmt.Errorf("invalid signature from parent '%s': %w", parentCert.Subject.CommonName, err)
		}
	}
}

// ValidateChain validates a certificate chain using x509.Verify
func ValidateChain(certs []*x509.Certificate) (bool, error) {
	if len(certs) == 0 {
		return false, fmt.Errorf("empty certificate chain")
	}

	// certs is expected to be [Leaf, Intermediate, ..., Root]
	leaf := certs[0]
	root := certs[len(certs)-1]

	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs)-1; i++ {
		intermediates.AddCert(certs[i])
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leaf.Verify(opts); err != nil {
		return false, fmt.Errorf("certificate verification failed: %w", err)
	}

	return true, nil
}

// FormatChainValidation formats the validation results
func FormatChainValidation(result *ValidationResult) string {
	if result.IsValid {
		return "✅ Certificate chain is valid."
	}

	var sb strings.Builder
	sb.WriteString("Certificate chain validation failed:\n")

	if len(result.Errors) > 0 {
		sb.WriteString("Errors:\n")
		for _, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("- %s\n", err))
		}
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("Warnings:\n")
		for _, warning := range result.Warnings {
			sb.WriteString(fmt.Sprintf("- %s\n", warning))
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
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("Failed to close file after writing", zap.String("filename", filename), zap.Error(closeErr))
		}
	}()

	// Determine format from argument or extension
	f := strings.ToLower(format)
	if f == "" {
		ext := filepath.Ext(filename)
		if ext != "" {
			f = ext[1:] // remove dot
		}
	}

	// Export based on format
	switch f {
	case "pem":
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(file, block); err != nil {
			return fmt.Errorf("failed to encode PEM: %v", err)
		}
	case "der":
		if _, err := file.Write(cert.Raw); err != nil {
			return fmt.Errorf("failed to write DER: %v", err)
		}
	default:
		return fmt.Errorf("unsupported format: %s (supported: pem, der)", f)
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
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
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
		if closeErr := certOut.Close(); closeErr != nil {
			logger.Error("Failed to close cert file after write error", zap.String("filename", certFile), zap.Error(closeErr))
		}
		return fmt.Errorf("failed to write cert data: %w", err)
	}
	if err := certOut.Close(); err != nil {
		logger.Error("Failed to close cert file", zap.String("filename", certFile), zap.Error(err))
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
		if closeErr := keyOut.Close(); closeErr != nil {
			logger.Error("Failed to close key file after error", zap.String("filename", keyFile), zap.Error(closeErr))
		}
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		logger.Error("Failed to write key data", zap.Error(err))
		if closeErr := keyOut.Close(); closeErr != nil {
			logger.Error("Failed to close key file after write error", zap.String("filename", keyFile), zap.Error(closeErr))
		}
		return fmt.Errorf("failed to write key data: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		logger.Error("Failed to close key file", zap.String("filename", keyFile), zap.Error(err))
		return fmt.Errorf("failed to close key file: %w", err)
	}

	logger.Info("Self-signed certificate generated successfully",
		zap.String("certFile", certFile),
		zap.String("keyFile", keyFile))
	return nil
}

// ParseCertificates parses PEM blocks and extracts certificates
func ParseCertificates(data []byte) ([]*Info, error) {
	var certs []*Info
	rest := data
	index := 0

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			crt, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logger.Error("Failed to parse certificate", zap.Error(err))
				return nil, fmt.Errorf("failed to parse certificate %d: %w", index, err)
			}

			label := generateCertificateLabel(crt, index)
			certs = append(certs, &Info{
				Certificate: crt,
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
		details.WriteString("Type: ECDSA\n")
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
	case ed25519.PublicKey:
		details.WriteString("Type: Ed25519\n")
		details.WriteString("Key Size: 256 bits\n")
	default:
		details.WriteString(fmt.Sprintf("Type: %T\n", pub))
	}

	return details.String()
}
