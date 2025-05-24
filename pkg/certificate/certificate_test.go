package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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

const expiredCertPEM = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOvMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
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
				t.Errorf("Unexpected error: %v", err)
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
	// Create a test certificate with known values
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "test.example.com",
			Organization:       []string{"Test Corp"},
			OrganizationalUnit: []string{"IT Department"},
			Country:            []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Corp"},
		},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com", "www.test.example.com"},
		SerialNumber: big.NewInt(12345),
		Raw:          []byte("test-cert-data"),
	}

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
