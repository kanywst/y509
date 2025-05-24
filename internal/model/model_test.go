package model

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/kanywst/y509/pkg/certificate"
)

// createTestCertificates creates test certificates for testing
func createTestCertificates() []*certificate.CertificateInfo {
	// Create a simple test certificate
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		SerialNumber: nil,
	}

	return []*certificate.CertificateInfo{
		{
			Certificate: cert,
			Label:       "test.example.com",
		},
	}
}

func TestNewModel(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)

	if len(model.certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(model.certificates))
	}

	if len(model.allCertificates) != 1 {
		t.Errorf("Expected 1 certificate in allCertificates, got %d", len(model.allCertificates))
	}

	if model.cursor != 0 {
		t.Errorf("Expected cursor to be 0, got %d", model.cursor)
	}

	if model.focus != FocusLeft {
		t.Errorf("Expected focus to be FocusLeft, got %v", model.focus)
	}

	if model.viewMode != ViewNormal {
		t.Errorf("Expected viewMode to be ViewNormal, got %v", model.viewMode)
	}
}

func TestHasValidCertificatesForCommand(t *testing.T) {
	tests := []struct {
		name        string
		cmd         string
		hasCerts    bool
		expected    bool
		description string
	}{
		{
			name:        "search command without certificates",
			cmd:         "search test",
			hasCerts:    false,
			expected:    true,
			description: "search command should work without certificates",
		},
		{
			name:        "filter command without certificates",
			cmd:         "filter expired",
			hasCerts:    false,
			expected:    true,
			description: "filter command should work without certificates",
		},
		{
			name:        "reset command without certificates",
			cmd:         "reset",
			hasCerts:    false,
			expected:    true,
			description: "reset command should work without certificates",
		},
		{
			name:        "validate command without certificates",
			cmd:         "validate",
			hasCerts:    false,
			expected:    true,
			description: "validate command should work without certificates",
		},
		{
			name:        "help command without certificates",
			cmd:         "help",
			hasCerts:    false,
			expected:    true,
			description: "help command should work without certificates",
		},
		{
			name:        "subject command without certificates",
			cmd:         "subject",
			hasCerts:    false,
			expected:    false,
			description: "subject command requires certificates",
		},
		{
			name:        "subject command with certificates",
			cmd:         "subject",
			hasCerts:    true,
			expected:    true,
			description: "subject command should work with certificates",
		},
		{
			name:        "goto command with certificates",
			cmd:         "goto 1",
			hasCerts:    true,
			expected:    true,
			description: "goto command should work with certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var model Model
			if tt.hasCerts {
				model = NewModel(createTestCertificates())
			} else {
				model = NewModel([]*certificate.CertificateInfo{})
			}

			result := model.hasValidCertificatesForCommand(tt.cmd)
			if result != tt.expected {
				t.Errorf("hasValidCertificatesForCommand(%q) = %v, expected %v. %s",
					tt.cmd, result, tt.expected, tt.description)
			}
		})
	}
}

func TestHandleGlobalCommands(t *testing.T) {
	tests := []struct {
		name        string
		cmd         string
		expected    bool
		description string
	}{
		{
			name:        "search command",
			cmd:         "search test",
			expected:    true,
			description: "search command should be handled as global",
		},
		{
			name:        "reset command",
			cmd:         "reset",
			expected:    true,
			description: "reset command should be handled as global",
		},
		{
			name:        "filter command",
			cmd:         "filter expired",
			expected:    true,
			description: "filter command should be handled as global",
		},
		{
			name:        "validate command",
			cmd:         "validate",
			expected:    true,
			description: "validate command should be handled as global",
		},
		{
			name:        "val shortcut",
			cmd:         "val",
			expected:    true,
			description: "val shortcut should be handled as global",
		},
		{
			name:        "help command",
			cmd:         "help",
			expected:    true,
			description: "help command should be handled as global",
		},
		{
			name:        "h shortcut",
			cmd:         "h",
			expected:    true,
			description: "h shortcut should be handled as global",
		},
		{
			name:        "quit command",
			cmd:         "quit",
			expected:    true,
			description: "quit command should be handled as global",
		},
		{
			name:        "q shortcut",
			cmd:         "q",
			expected:    true,
			description: "q shortcut should be handled as global",
		},
		{
			name:        "subject command",
			cmd:         "subject",
			expected:    false,
			description: "subject command should not be handled as global",
		},
		{
			name:        "unknown command",
			cmd:         "unknown",
			expected:    false,
			description: "unknown command should not be handled as global",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := NewModel(createTestCertificates())
			result := model.handleGlobalCommands(tt.cmd)
			if result != tt.expected {
				t.Errorf("handleGlobalCommands(%q) = %v, expected %v. %s",
					tt.cmd, result, tt.expected, tt.description)
			}
		})
	}
}

func TestHandleGotoCommand(t *testing.T) {
	tests := []struct {
		name           string
		cmd            string
		numCerts       int
		expectedError  bool
		expectedCursor int
		description    string
	}{
		{
			name:           "valid goto command",
			cmd:            "goto 1",
			numCerts:       2,
			expectedError:  false,
			expectedCursor: 0,
			description:    "goto 1 should set cursor to 0",
		},
		{
			name:           "valid g shortcut",
			cmd:            "g 2",
			numCerts:       2,
			expectedError:  false,
			expectedCursor: 1,
			description:    "g 2 should set cursor to 1",
		},
		{
			name:           "invalid certificate number - too high",
			cmd:            "goto 5",
			numCerts:       2,
			expectedError:  true,
			expectedCursor: 0,
			description:    "goto 5 with 2 certs should error",
		},
		{
			name:           "invalid certificate number - zero",
			cmd:            "goto 0",
			numCerts:       2,
			expectedError:  true,
			expectedCursor: 0,
			description:    "goto 0 should error",
		},
		{
			name:           "invalid certificate number - negative",
			cmd:            "goto -1",
			numCerts:       2,
			expectedError:  true,
			expectedCursor: 0,
			description:    "goto -1 should error",
		},
		{
			name:           "invalid format - no number",
			cmd:            "goto",
			numCerts:       2,
			expectedError:  true,
			expectedCursor: 0,
			description:    "goto without number should error",
		},
		{
			name:           "invalid format - non-numeric",
			cmd:            "goto abc",
			numCerts:       2,
			expectedError:  true,
			expectedCursor: 0,
			description:    "goto abc should error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test certificates
			certs := make([]*certificate.CertificateInfo, tt.numCerts)
			for i := 0; i < tt.numCerts; i++ {
				cert := &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "test.example.com",
					},
				}
				certs[i] = &certificate.CertificateInfo{
					Certificate: cert,
					Label:       "test.example.com",
				}
			}

			model := NewModel(certs)
			model.commandError = "" // Clear any existing error

			model.handleGotoCommand(tt.cmd)

			hasError := model.commandError != ""
			if hasError != tt.expectedError {
				t.Errorf("handleGotoCommand(%q) error state = %v, expected %v. Error: %s. %s",
					tt.cmd, hasError, tt.expectedError, model.commandError, tt.description)
			}

			if !tt.expectedError && model.cursor != tt.expectedCursor {
				t.Errorf("handleGotoCommand(%q) cursor = %d, expected %d. %s",
					tt.cmd, model.cursor, tt.expectedCursor, tt.description)
			}

			if !tt.expectedError {
				if model.viewMode != ViewNormal {
					t.Errorf("handleGotoCommand(%q) should set viewMode to ViewNormal", tt.cmd)
				}
				if model.focus != FocusLeft {
					t.Errorf("handleGotoCommand(%q) should set focus to FocusLeft", tt.cmd)
				}
			}
		})
	}
}

func TestResetView(t *testing.T) {
	model := NewModel(createTestCertificates())

	// Set up some state to reset
	model.searchQuery = "test"
	model.filterActive = true
	model.filterType = "expired"
	model.cursor = 1
	model.certificates = []*certificate.CertificateInfo{} // Empty filtered list

	model.resetView()

	if model.searchQuery != "" {
		t.Errorf("Expected searchQuery to be empty after reset, got %q", model.searchQuery)
	}

	if model.filterActive {
		t.Errorf("Expected filterActive to be false after reset, got %v", model.filterActive)
	}

	if model.filterType != "" {
		t.Errorf("Expected filterType to be empty after reset, got %q", model.filterType)
	}

	if model.cursor != 0 {
		t.Errorf("Expected cursor to be 0 after reset, got %d", model.cursor)
	}

	if model.viewMode != ViewNormal {
		t.Errorf("Expected viewMode to be ViewNormal after reset, got %v", model.viewMode)
	}

	if model.focus != FocusLeft {
		t.Errorf("Expected focus to be FocusLeft after reset, got %v", model.focus)
	}

	if len(model.certificates) != len(model.allCertificates) {
		t.Errorf("Expected certificates to be restored to allCertificates after reset")
	}
}

func TestShowDetail(t *testing.T) {
	model := NewModel(createTestCertificates())

	field := "Test Field"
	value := "Test Value"

	model.showDetail(field, value)

	if model.viewMode != ViewDetail {
		t.Errorf("Expected viewMode to be ViewDetail, got %v", model.viewMode)
	}

	if model.detailField != field {
		t.Errorf("Expected detailField to be %q, got %q", field, model.detailField)
	}

	if model.detailValue != value {
		t.Errorf("Expected detailValue to be %q, got %q", value, model.detailValue)
	}
}

func TestSearchCertificates(t *testing.T) {
	model := NewModel(createTestCertificates())

	// Test empty query
	model.searchCertificates("")
	if model.commandError == "" {
		t.Error("Expected error for empty search query")
	}

	// Test valid query
	model.commandError = "" // Clear error
	model.searchCertificates("test")

	if model.searchQuery != "test" {
		t.Errorf("Expected searchQuery to be 'test', got %q", model.searchQuery)
	}

	if !model.filterActive {
		t.Error("Expected filterActive to be true after search")
	}

	if model.filterType != "search: test" {
		t.Errorf("Expected filterType to be 'search: test', got %q", model.filterType)
	}

	if model.cursor != 0 {
		t.Errorf("Expected cursor to be reset to 0, got %d", model.cursor)
	}

	if model.viewMode != ViewNormal {
		t.Errorf("Expected viewMode to be ViewNormal, got %v", model.viewMode)
	}

	if model.focus != FocusLeft {
		t.Errorf("Expected focus to be FocusLeft, got %v", model.focus)
	}
}

func TestFilterCertificates(t *testing.T) {
	model := NewModel(createTestCertificates())

	// Test invalid filter
	model.filterCertificates("invalid")
	if model.commandError == "" {
		t.Error("Expected error for invalid filter type")
	}

	// Test valid filter
	model.commandError = "" // Clear error
	model.filterCertificates("valid")

	if !model.filterActive {
		t.Error("Expected filterActive to be true after filter")
	}

	if model.filterType != "valid" {
		t.Errorf("Expected filterType to be 'valid', got %q", model.filterType)
	}

	if model.cursor != 0 {
		t.Errorf("Expected cursor to be reset to 0, got %d", model.cursor)
	}

	if model.viewMode != ViewNormal {
		t.Errorf("Expected viewMode to be ViewNormal, got %v", model.viewMode)
	}

	if model.focus != FocusLeft {
		t.Errorf("Expected focus to be FocusLeft, got %v", model.focus)
	}
}
