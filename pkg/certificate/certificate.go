// Package certificate provides functionality for loading, parsing, and validating X.509 certificates and chains.
package certificate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// safeLogger holds the package logger behind an atomic pointer so SetLogger
// can be called concurrently with the logging calls without a data race.
type safeLogger struct {
	l atomic.Pointer[zap.Logger]
}

func (s *safeLogger) Debug(msg string, fields ...zap.Field) { s.l.Load().Debug(msg, fields...) }
func (s *safeLogger) Info(msg string, fields ...zap.Field)  { s.l.Load().Info(msg, fields...) }
func (s *safeLogger) Warn(msg string, fields ...zap.Field)  { s.l.Load().Warn(msg, fields...) }
func (s *safeLogger) Error(msg string, fields ...zap.Field) { s.l.Load().Error(msg, fields...) }

// logger defaults to a no-op so the package stays quiet (and never writes
// to stderr, which would corrupt the TUI). The application wires in its own
// logger via SetLogger.
var logger = func() *safeLogger {
	s := &safeLogger{}
	s.l.Store(zap.NewNop())
	return s
}()

// SetLogger routes the package's diagnostics through the given logger.
// Passing nil resets it to a no-op logger.
func SetLogger(l *zap.Logger) {
	if l == nil {
		l = zap.NewNop()
	}
	logger.l.Store(l)
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

// ExportCertificate exports a certificate to a file
func ExportCertificate(cert *x509.Certificate, format string, filename string) error {
	if cert == nil || len(cert.Raw) == 0 {
		return fmt.Errorf("certificate has no raw data to export")
	}

	// Determine format from argument or extension
	f := strings.ToLower(format)
	if f == "" {
		ext := filepath.Ext(filename)
		if ext != "" {
			f = strings.ToLower(ext[1:]) // remove dot, normalize case
		}
	}

	// Build the file contents before touching the filesystem so an
	// unsupported format doesn't leave an empty file behind.
	var data []byte
	switch f {
	case "pem", "crt", "cert":
		data = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	case "der":
		data = cert.Raw
	default:
		return fmt.Errorf("unsupported format: %s (supported: pem, der, crt, cert)", f)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("Failed to close file after writing", zap.String("filename", filename), zap.Error(closeErr))
		}
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write %s: %v", f, err)
	}

	return nil
}

// ParseCertificates extracts certificates from a PEM bundle or from raw DER.
//
// PEM is tried first. If the input holds no PEM armour at all it is treated as
// DER, which is what Windows and most CAs hand out as .der / .cer, and what
// y509's own export writes when asked for DER.
func ParseCertificates(data []byte) ([]*Info, error) {
	certs, sawPEM, err := parsePEMCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 {
		return certs, nil
	}

	if sawPEM {
		// The input is PEM, it just holds no certificates -- a lone private key
		// file, say. Saying "no certificates found" is right, but say why.
		logger.Error("PEM input contains no CERTIFICATE blocks")
		return nil, fmt.Errorf("no certificates found in input: the PEM data contains no CERTIFICATE blocks")
	}

	return parseDERCertificates(data)
}

// parsePEMCertificates walks the PEM blocks in data. sawPEM reports whether any
// PEM block at all was present, which tells ParseCertificates whether it is
// worth retrying the input as DER.
func parsePEMCertificates(data []byte) (certs []*Info, sawPEM bool, err error) {
	rest := data
	index := 0

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true

		if block.Type == "CERTIFICATE" {
			crt, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logger.Error("Failed to parse certificate", zap.Error(err))
				return nil, sawPEM, fmt.Errorf("failed to parse certificate %d: %w", index, err)
			}

			certs = append(certs, &Info{
				Certificate: crt,
				Index:       index,
				Label:       generateCertificateLabel(crt, index),
			})
			// Count certificates, not PEM blocks: a bundle may also carry a
			// private key, DH parameters, or a CRL, and those must not consume
			// a number. Index has to stay equal to the slice position.
			index++
		}

		rest = remaining
	}

	return certs, sawPEM, nil
}

// parseDERCertificates reads the input as raw DER. x509.ParseCertificates
// handles several certificates concatenated together, which is how a DER chain
// is usually shipped.
func parseDERCertificates(data []byte) ([]*Info, error) {
	parsed, err := x509.ParseCertificates(data)
	if err != nil {
		// Failing to parse is the ordinary outcome for anything that is not a
		// certificate, so log it at debug rather than spamming the log on every
		// bad input.
		logger.Debug("input did not parse as DER certificates", zap.Error(err))

		switch {
		case isCompleteDERSequence(data):
			// A well-formed ASN.1 SEQUENCE that is not a certificate is almost
			// always a container y509 cannot open yet. Testing the first byte
			// alone would misfire on any text starting with '0' (0x30).
			return nil, fmt.Errorf("input is a DER structure but not a certificate "+
				"(PKCS#7 and PKCS#12 bundles are not supported): %w", err)
		case len(data) > 0 && data[0] == derSequenceTag:
			// Begins like DER but does not form a complete SEQUENCE: a
			// truncated or corrupt certificate rather than a container.
			return nil, fmt.Errorf("input could not be parsed as a certificate: %w", err)
		default:
			return nil, fmt.Errorf("no certificates found in input: not PEM, and not valid DER")
		}
	}

	// x509.ParseCertificates accepts empty input and returns no certificates
	// and no error, so the empty case has to be caught here.
	if len(parsed) == 0 {
		logger.Error("No certificates found in input")
		return nil, fmt.Errorf("no certificates found in input")
	}

	certs := make([]*Info, len(parsed))
	for i, crt := range parsed {
		certs[i] = &Info{
			Certificate: crt,
			Index:       i,
			Label:       generateCertificateLabel(crt, i),
		}
	}
	return certs, nil
}

// derSequenceTag is the ASN.1 universal SEQUENCE tag, the first byte of any
// DER-encoded certificate, PKCS#7 blob or PKCS#12 bundle.
const derSequenceTag = 0x30

// isCompleteDERSequence reports whether data is exactly one DER-encoded ASN.1
// SEQUENCE with no trailing bytes. That is the shape of a certificate, a PKCS#7
// blob or a PKCS#12 bundle, and -- unlike testing the first byte -- text that
// merely happens to start with '0' (0x30) does not satisfy it.
func isCompleteDERSequence(data []byte) bool {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	return err == nil && len(rest) == 0 &&
		raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence
}

// generateCertificateLabel creates a display label for the certificate
func generateCertificateLabel(cert *x509.Certificate, index int) string {
	cn := cert.Subject.CommonName
	if cn == "" {
		cn = "Unknown"
	}

	// Truncate long common names by rune so multibyte names aren't cut
	// mid-character.
	if r := []rune(cn); len(r) > 30 {
		cn = string(r[:27]) + "..."
	}

	return fmt.Sprintf("%d. %s", index+1, cn)
}

// IsExpired checks if certificate is expired
func IsExpired(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now())
}

// defaultExpiryWarningDays is the fallback "expiring soon" window in days,
// used when no caller-supplied threshold is available.
const defaultExpiryWarningDays = 30

// CABMaxSubscriberValidityDays is the CA/Browser Forum maximum lifetime for
// publicly-trusted subscriber (leaf) certificates effective 2026-03-15. CA
// certificates are exempt, so this is only applied to non-CA certs.
const CABMaxSubscriberValidityDays = 200

// ValidityPeriodDays returns the certificate's total validity window in days,
// rounded to the nearest day (avoids DST / sub-day truncation).
func ValidityPeriodDays(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	// Use Unix seconds rather than Time.Sub: time.Duration is int64 nanoseconds
	// and caps at ~292 years, which overflows on certs with a far-future
	// NotAfter (e.g. the 9999-12-31 "no expiry" convention).
	const secsPerDay = 24 * 60 * 60
	secs := cert.NotAfter.Unix() - cert.NotBefore.Unix()
	if secs <= 0 {
		// Malformed certs (NotAfter <= NotBefore) have no meaningful period.
		return 0
	}
	// Round to the nearest day.
	return int((secs + secsPerDay/2) / secsPerDay)
}

// ExceedsCABMaxLifetime reports whether a subscriber (non-CA) certificate's
// validity period exceeds the CA/Browser Forum maximum. CA certs are exempt.
func ExceedsCABMaxLifetime(cert *x509.Certificate) bool {
	if cert == nil || cert.IsCA {
		return false
	}
	return ValidityPeriodDays(cert) > CABMaxSubscriberValidityDays
}

// IsExpiringSoon checks if a certificate expires within the default window.
func IsExpiringSoon(cert *x509.Certificate) bool {
	return IsExpiringSoonWithin(cert, defaultExpiryWarningDays)
}

// IsExpiringSoonWithin checks if a certificate expires within the given number
// of days. Non-positive values fall back to the default window.
func IsExpiringSoonWithin(cert *x509.Certificate, days int) bool {
	if cert == nil {
		return false
	}
	if days <= 0 {
		days = defaultExpiryWarningDays
	}
	return cert.NotAfter.Before(time.Now().AddDate(0, 0, days))
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

	// Total validity period, plus a flag for subscriber certs that exceed the
	// CA/Browser Forum maximum lifetime (CA certs are exempt).
	details.WriteString(fmt.Sprintf("Validity Period: %d days\n", ValidityPeriodDays(cert)))
	if ExceedsCABMaxLifetime(cert) {
		details.WriteString(fmt.Sprintf("Note: exceeds CA/Browser Forum max subscriber lifetime (%d days)\n", CABMaxSubscriberValidityDays))
	}

	now := time.Now()
	duration := cert.NotAfter.Sub(now)

	if cert.NotAfter.Before(now) {
		details.WriteString("Status: EXPIRED\n")
		details.WriteString(fmt.Sprintf("Expired: %s ago\n", (-duration).String()))
	} else if IsExpiringSoon(cert) {
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
		// Unrecognized key type. This is the path post-quantum algorithms
		// (ML-DSA, SLH-DSA) take today: the Go standard library does not yet
		// expose them through crypto/x509, so PublicKey is typically nil.
		// Surface the SPKI algorithm OID so the cert isn't shown blank.
		details.WriteString(describeUnknownPublicKey(cert, pub))
	}

	return details.String()
}

// pqcAlgorithmNames maps NIST post-quantum signature OIDs to friendly names so
// PQC / hybrid certificates render meaningfully even before crypto/x509 support
// lands (expected in Go 1.27).
var pqcAlgorithmNames = map[string]string{
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
	"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	"2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
	"2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
}

// describeUnknownPublicKey renders details for a key type the type switch did
// not recognize, extracting the SubjectPublicKeyInfo algorithm OID.
func describeUnknownPublicKey(cert *x509.Certificate, pub any) string {
	var details strings.Builder

	if cert == nil {
		details.WriteString(fmt.Sprintf("Type: %T\n", pub))
		return details.String()
	}

	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err == nil {
		oid := spki.Algorithm.Algorithm.String()
		if name, ok := pqcAlgorithmNames[oid]; ok {
			details.WriteString(fmt.Sprintf("Type: %s (post-quantum)\n", name))
		} else {
			details.WriteString("Type: Unrecognized\n")
		}
		details.WriteString(fmt.Sprintf("Algorithm OID: %s\n", oid))
		return details.String()
	}

	// Fall back to the concrete Go type if the SPKI cannot be parsed.
	details.WriteString(fmt.Sprintf("Type: %T\n", pub))
	return details.String()
}
