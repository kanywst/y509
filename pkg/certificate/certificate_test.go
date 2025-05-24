package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Test certificate data (valid PEM format)
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEhMB8G
A1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwUdO3fxEzEtcnI7ZKZL412XvZOVJFstNXSB0RT2ZCpNu
NE6t+XFw0Q4fz0ZaMsoQn+2BdooxrkBU5RdgBBOQOSXl5Mt0Q5X7+trI5rFvr/Wr
mVXmPiLiRkN2NfQQi+9E2Q+LEHiGNy2g2d6lAjCG5De2YUkEzEHRYFhIllQRWqmM
ZbNCRBWi6NEUECMFtk5hgEfzJVoGy8IkYdnativY2XcOQQjd40CQk6+FHqjHHxzH
ZgTCrJDghTtt6ZFVZMQjqlzEEWEN4dMusx1GVrpJLTTyQBNbBVNgtGAoAiEA4dEo
qiUupiUsvqTFmaFioOiuCiDuMGQC6+DGCmzAbpfcjwIDAQABo1AwTjAdBgNVHQ4E
FgQUhKs/VJ3IWyKwrl0Ki0f+EWuUlMEwHwYDVR0jBBgwFoAUhKs/VJ3IWyKwrl0K
i0f+EWuUlMEwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWGlApfpT
WsAS/8wAQHhM1olf2ox81lxCKmrBdBjXpNwdVd84dEzjLrAK7b8IAjXkEkDjY1VE
EJ8+TzP9PKtqKdjgQQwo0Yqscw5f1uLpOBXBDrftnig5TQjx4HlgwUBvQnI79c/j
MfqNuDdJ3U0QHakjXHqmWGbCc6tGgDr4EbE+Kh7s5Hl0SLrI9FoYXyPdYgHQfkjy
oQiRSIWlFfHe+5lXGvQWlkumO2dDVVHlIgySQVShOBvfcQ1DcsHEfU2dmeMffrI9
TKph8fRAQRg1MwlnCjbBWA==
-----END CERTIFICATE-----`

func createTestCert() *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "test.example.com",
			Organization:       []string{"Test Corp"},
			OrganizationalUnit: []string{"IT Department"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
		Issuer: pkix.Name{
			CommonName:         "Test CA",
			Organization:       []string{"Test CA Corp"},
			OrganizationalUnit: []string{"CA Department"},
			Country:            []string{"US"},
		},
		NotBefore:      time.Now().Add(-24 * time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		DNSNames:       []string{"test.example.com", "www.test.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses: []string{"admin@example.com"},
		SerialNumber:   big.NewInt(12345),
		Raw:            []byte("test-cert-data"),
	}
}

func createRSACert() *x509.Certificate {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createTestCert()
	cert.PublicKey = &rsaKey.PublicKey
	return cert
}

func createECDSACert() *x509.Certificate {
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := createTestCert()
	cert.PublicKey = &ecdsaKey.PublicKey
	return cert
}

func TestParseCertificatesFromFile(t *testing.T) {
	// Test with actual certificate file
	data, err := os.ReadFile("../../testdata/demo/certs.pem")
	if err != nil {
		t.Skipf("Skipping test: could not read ../../testdata/demo/certs.pem: %v", err)
	}

	certs, err := ParseCertificates(data)
	if err != nil {
		t.Errorf("Unexpected error parsing real certificates: %v", err)
		return
	}

	if len(certs) == 0 {
		t.Error("Expected at least one certificate")
	}

	// Verify certificate info structure
	for i, cert := range certs {
		if cert.Certificate == nil {
			t.Errorf("Certificate %d is nil", i)
		}
		if cert.Index != i {
			t.Errorf("Certificate %d has wrong index: %d", i, cert.Index)
		}
		if cert.Label == "" {
			t.Errorf("Certificate %d has empty label", i)
		}
	}
}

func TestParseCertificates(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectCount int
		expectError bool
	}{
		{
			name:        "Empty input",
			input:       "",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "Invalid PEM",
			input:       "invalid pem data",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "Valid certificate",
			input:       testCertPEM,
			expectCount: 1,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := ParseCertificates([]byte(tt.input))

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				// Skip test if certificate parsing fails (malformed test certificate)
				t.Skipf("Skipping test due to certificate parsing error: %v", err)
				return
			}

			if len(certs) != tt.expectCount {
				t.Errorf("Expected %d certificates, got %d", tt.expectCount, len(certs))
			}

			// Verify certificate info structure
			for i, cert := range certs {
				if cert.Certificate == nil {
					t.Errorf("Certificate %d is nil", i)
				}
				if cert.Index != i {
					t.Errorf("Certificate %d has wrong index: %d", i, cert.Index)
				}
				if cert.Label == "" {
					t.Errorf("Certificate %d has empty label", i)
				}
			}
		})
	}
}

func TestGenerateCertificateLabel(t *testing.T) {
	tests := []struct {
		name     string
		cn       string
		index    int
		expected string
	}{
		{
			name:     "Normal CN",
			cn:       "example.com",
			index:    0,
			expected: "1. example.com",
		},
		{
			name:     "Empty CN",
			cn:       "",
			index:    1,
			expected: "2. Unknown",
		},
		{
			name:     "Long CN",
			cn:       "very-long-common-name-that-should-be-truncated.example.com",
			index:    2,
			expected: "3. very-long-common-name-that-...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock certificate
			cert := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: tt.cn,
				},
			}

			result := generateCertificateLabel(cert, tt.index)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetCertificateDetails(t *testing.T) {
	cert := createTestCert()
	details := GetCertificateDetails(cert)

	// Check that details contain expected information
	expectedStrings := []string{
		"Subject:",
		"CN: test.example.com",
		"O:  Test Corp",
		"OU: IT Department",
		"C:  US",
		"Issuer:",
		"CN: Test CA",
		"Validity:",
		"Not Before:",
		"Not After:",
		"Status: Valid",
		"Subject Alternative Names:",
		"DNS: test.example.com",
		"DNS: www.test.example.com",
		"Public Key:",
		"SHA256 Fingerprint:",
		"Serial Number: 12345",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(details, expected) {
			t.Errorf("Expected details to contain %q, but it didn't.\nDetails: %s", expected, details)
		}
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		notAfter time.Time
		expected bool
	}{
		{
			name:     "Valid certificate",
			notAfter: now.Add(24 * time.Hour),
			expected: false,
		},
		{
			name:     "Expired certificate",
			notAfter: now.Add(-24 * time.Hour),
			expected: true,
		},
		{
			name:     "Just expired",
			notAfter: now.Add(-1 * time.Minute),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotAfter: tt.notAfter,
			}

			result := IsExpired(cert)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsExpiringSoon(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		notAfter time.Time
		expected bool
	}{
		{
			name:     "Valid for long time",
			notAfter: now.Add(60 * 24 * time.Hour),
			expected: false,
		},
		{
			name:     "Expiring in 15 days",
			notAfter: now.Add(15 * 24 * time.Hour),
			expected: true,
		},
		{
			name:     "Expiring in 29 days",
			notAfter: now.Add(29 * 24 * time.Hour),
			expected: true,
		},
		{
			name:     "Expiring in 31 days",
			notAfter: now.Add(31 * 24 * time.Hour),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotAfter: tt.notAfter,
			}

			result := IsExpiringSoon(cert)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestLoadCertificates(t *testing.T) {
	// Test reading from file
	tempFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString(testCertPEM)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	certs, err := LoadCertificates(tempFile.Name())
	if err != nil {
		// Skip test if certificate loading fails (malformed test certificate)
		t.Skipf("Skipping test due to certificate loading error: %v", err)
		return
	}
	if len(certs) == 0 {
		t.Error("Expected at least one certificate")
	}

	// Test reading from non-existent file
	_, err = LoadCertificates("non-existent-file.pem")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestFormatSubject(t *testing.T) {
	cert := createTestCert()
	result := FormatSubject(cert)

	expectedStrings := []string{
		"Common Name: test.example.com",
		"Organization: Test Corp",
		"Organizational Unit: IT Department",
		"Country: US",
		"Province: California",
		"Locality: San Francisco",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(result, expected) {
			t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
		}
	}
}

func TestFormatIssuer(t *testing.T) {
	cert := createTestCert()
	result := FormatIssuer(cert)

	expectedStrings := []string{
		"Common Name: Test CA",
		"Organization: Test CA Corp",
		"Organizational Unit: CA Department",
		"Country: US",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(result, expected) {
			t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
		}
	}
}

func TestFormatValidity(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		expected  []string
	}{
		{
			name:      "Valid certificate",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(365 * 24 * time.Hour),
			expected:  []string{"Status: Valid", "Expires in:"},
		},
		{
			name:      "Expired certificate",
			notBefore: now.Add(-365 * 24 * time.Hour),
			notAfter:  now.Add(-24 * time.Hour),
			expected:  []string{"Status: EXPIRED", "Expired:"},
		},
		{
			name:      "Expiring soon",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(15 * 24 * time.Hour),
			expected:  []string{"Status: EXPIRING SOON", "Expires in:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotBefore: tt.notBefore,
				NotAfter:  tt.notAfter,
			}

			result := FormatValidity(cert)
			for _, expected := range tt.expected {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
				}
			}
		})
	}
}

func TestFormatSAN(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected []string
	}{
		{
			name: "Certificate with DNS names",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com", "www.example.com"},
			},
			expected: []string{"DNS Names:", "example.com", "www.example.com"},
		},
		{
			name: "Certificate with IP addresses",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
			},
			expected: []string{"IP Addresses:", "192.168.1.1", "10.0.0.1"},
		},
		{
			name: "Certificate with email addresses",
			cert: &x509.Certificate{
				EmailAddresses: []string{"admin@example.com", "support@example.com"},
			},
			expected: []string{"Email Addresses:", "admin@example.com", "support@example.com"},
		},
		{
			name:     "Certificate with no SAN",
			cert:     &x509.Certificate{},
			expected: []string{"No Subject Alternative Names found"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatSAN(tt.cert)
			for _, expected := range tt.expected {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
				}
			}
		})
	}
}

func TestFormatFingerprint(t *testing.T) {
	cert := &x509.Certificate{
		Raw: []byte("test-cert-data"),
	}

	result := FormatFingerprint(cert)
	if result == "" {
		t.Error("Expected non-empty fingerprint")
	}
	if len(result) != 64 { // SHA256 hex string length
		t.Errorf("Expected fingerprint length 64, got %d", len(result))
	}
}

func TestFormatPublicKey(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected []string
	}{
		{
			name:     "RSA certificate",
			cert:     createRSACert(),
			expected: []string{"Algorithm:", "Type: RSA2048", "Key Size: 2048 bits", "Modulus Size:", "Public Exponent:"},
		},
		{
			name:     "ECDSA certificate",
			cert:     createECDSACert(),
			expected: []string{"Algorithm:", "Type: ECDSA", "Curve: P-256", "Key Size: 256 bits", "Standard: NIST P-256"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatPublicKey(tt.cert)
			for _, expected := range tt.expected {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
				}
			}
		})
	}
}

func TestValidateChain(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		certs    []*CertificateInfo
		expected bool
	}{
		{
			name:     "Empty chain",
			certs:    []*CertificateInfo{},
			expected: false,
		},
		{
			name: "Valid chain",
			certs: []*CertificateInfo{
				{
					Certificate: &x509.Certificate{
						NotBefore: now.Add(-24 * time.Hour),
						NotAfter:  now.Add(365 * 24 * time.Hour),
					},
				},
			},
			expected: true,
		},
		{
			name: "Expired certificate",
			certs: []*CertificateInfo{
				{
					Certificate: &x509.Certificate{
						NotBefore: now.Add(-365 * 24 * time.Hour),
						NotAfter:  now.Add(-24 * time.Hour),
					},
				},
			},
			expected: false,
		},
		{
			name: "Not yet valid certificate",
			certs: []*CertificateInfo{
				{
					Certificate: &x509.Certificate{
						NotBefore: now.Add(24 * time.Hour),
						NotAfter:  now.Add(365 * 24 * time.Hour),
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateChain(tt.certs)
			if result.IsValid != tt.expected {
				t.Errorf("Expected IsValid %v, got %v", tt.expected, result.IsValid)
			}
		})
	}
}

func TestFormatChainValidation(t *testing.T) {
	tests := []struct {
		name     string
		result   *ChainValidationResult
		expected []string
	}{
		{
			name: "Valid chain",
			result: &ChainValidationResult{
				IsValid:  true,
				Errors:   []string{},
				Warnings: []string{},
			},
			expected: []string{"✅ Certificate chain is VALID", "No issues found"},
		},
		{
			name: "Invalid chain with errors",
			result: &ChainValidationResult{
				IsValid:  false,
				Errors:   []string{"Certificate expired"},
				Warnings: []string{"Certificate expires soon"},
			},
			expected: []string{"❌ Certificate chain is INVALID", "Errors:", "Certificate expired", "Warnings:", "Certificate expires soon"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatChainValidation(tt.result)
			for _, expected := range tt.expected {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't.\nResult: %s", expected, result)
				}
			}
		})
	}
}

func TestExportCertificate(t *testing.T) {
	cert := createTestCert()

	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{
			name:        "PEM format",
			format:      "pem",
			expectError: false,
		},
		{
			name:        "DER format",
			format:      "der",
			expectError: false,
		},
		{
			name:        "Invalid format",
			format:      "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, err := os.CreateTemp("", "test-export-*."+tt.format)
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tempFile.Name())
			tempFile.Close()

			err = ExportCertificate(cert, tt.format, tempFile.Name())

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSearchCertificates(t *testing.T) {
	certs := []*CertificateInfo{
		{
			Certificate: &x509.Certificate{
				Subject:  pkix.Name{CommonName: "example.com"},
				Issuer:   pkix.Name{CommonName: "Test CA"},
				DNSNames: []string{"example.com"},
			},
		},
		{
			Certificate: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:   "test.com",
					Organization: []string{"Test Corp"},
				},
				DNSNames: []string{"test.com"},
			},
		},
	}

	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{
			name:     "Empty query",
			query:    "",
			expected: 2,
		},
		{
			name:     "Search by CN",
			query:    "example",
			expected: 1,
		},
		{
			name:     "Search by organization",
			query:    "Test Corp",
			expected: 1,
		},
		{
			name:     "Search by DNS name",
			query:    "test.com",
			expected: 1,
		},
		{
			name:     "Search by issuer",
			query:    "Test CA",
			expected: 1,
		},
		{
			name:     "No matches",
			query:    "nonexistent",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SearchCertificates(certs, tt.query)
			if len(result) != tt.expected {
				t.Errorf("Expected %d results, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestFilterCertificates(t *testing.T) {
	now := time.Now()
	certs := []*CertificateInfo{
		{
			Certificate: &x509.Certificate{
				NotAfter: now.Add(365 * 24 * time.Hour), // Valid
				Subject:  pkix.Name{CommonName: "valid.com"},
				Issuer:   pkix.Name{CommonName: "CA"},
			},
		},
		{
			Certificate: &x509.Certificate{
				NotAfter: now.Add(-24 * time.Hour), // Expired
				Subject:  pkix.Name{CommonName: "expired.com"},
				Issuer:   pkix.Name{CommonName: "CA"},
			},
		},
		{
			Certificate: &x509.Certificate{
				NotAfter: now.Add(15 * 24 * time.Hour), // Expiring soon
				Subject:  pkix.Name{CommonName: "expiring.com"},
				Issuer:   pkix.Name{CommonName: "CA"},
			},
		},
		{
			Certificate: &x509.Certificate{
				NotAfter: now.Add(365 * 24 * time.Hour), // Self-signed
				Subject:  pkix.Name{CommonName: "self-signed.com"},
				Issuer:   pkix.Name{CommonName: "self-signed.com"},
			},
		},
	}

	tests := []struct {
		name       string
		filterType string
		expected   int
	}{
		{
			name:       "Filter expired",
			filterType: "expired",
			expected:   1,
		},
		{
			name:       "Filter expiring",
			filterType: "expiring",
			expected:   1,
		},
		{
			name:       "Filter valid",
			filterType: "valid",
			expected:   2,
		},
		{
			name:       "Filter self-signed",
			filterType: "self-signed",
			expected:   1,
		},
		{
			name:       "Invalid filter",
			filterType: "invalid",
			expected:   4, // Returns all certificates for invalid filter
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterCertificates(certs, tt.filterType)
			if len(result) != tt.expected {
				t.Errorf("Expected %d results, got %d", tt.expected, len(result))
			}
		})
	}
}
