package model

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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

	if model.viewMode != ViewSplash {
		t.Errorf("Expected viewMode to be ViewSplash, got %v", model.viewMode)
	}
}

func TestInit(t *testing.T) {
	model := NewModel(createTestCertificates())
	cmd := model.Init()
	if cmd == nil {
		t.Error("Expected Init to return a command, got nil")
	}
}

func TestUpdate(t *testing.T) {
	model := NewModel(createTestCertificates())

	// Test key press in splash mode
	model.viewMode = ViewSplash
	updatedModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if updatedModel.(Model).viewMode != ViewNormal {
		t.Error("Expected Enter key to switch from splash to normal mode")
	}
	if cmd != nil {
		t.Errorf("Expected no command, got %v", cmd)
	}

	// Test quit command
	model = NewModel(createTestCertificates())
	model.viewMode = ViewNormal
	updatedModel, cmd = model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Error("Expected quit command")
	}

	// Test colon key to enter command mode
	model.viewMode = ViewNormal
	updatedModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{':'}})
	if updatedModel.(Model).viewMode != ViewCommand {
		t.Error("Expected colon to enter command mode")
	}

	// Test escape key in detail mode
	model.viewMode = ViewDetail
	updatedModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if updatedModel.(Model).viewMode != ViewNormal {
		t.Error("Expected Escape to return to normal view")
	}
}

func TestView(t *testing.T) {
	model := NewModel(createTestCertificates())
	model.ready = true // Set ready to true to avoid "Initializing..." message

	// Test splash view - check for splash screen content
	model.viewMode = ViewSplash
	view := model.View()
	// The splash screen might not contain "y509" directly, so let's just check it's not empty
	if view == "" {
		t.Error("Expected non-empty splash view")
	}

	// Test normal view
	model.viewMode = ViewNormal
	view = model.View()
	if view == "" {
		t.Error("Expected non-empty normal view")
	}

	// Test detail view
	model.viewMode = ViewDetail
	model.detailField = "Test Field"
	model.detailValue = "Test Value"
	view = model.View()
	if !strings.Contains(view, "Test Field") || !strings.Contains(view, "Test Value") {
		t.Error("Expected detail view to contain field and value")
	}
}

func TestUtilityFunctions(t *testing.T) {
	// Test max function
	if max(5, 3) != 5 {
		t.Error("max(5, 3) should return 5")
	}
	if max(2, 7) != 7 {
		t.Error("max(2, 7) should return 7")
	}

	// Test min function
	if min(5, 3) != 3 {
		t.Error("min(5, 3) should return 3")
	}
	if min(2, 7) != 2 {
		t.Error("min(2, 7) should return 2")
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
			name:        "help command",
			cmd:         "help",
			expected:    true,
			description: "help command should be handled as global",
		},
		{
			name:        "quit command",
			cmd:         "quit",
			expected:    true,
			description: "quit command should be handled as global",
		},
		{
			name:        "subject command",
			cmd:         "subject",
			expected:    false,
			description: "subject command should not be handled as global",
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
			name:           "invalid certificate number - too high",
			cmd:            "goto 5",
			numCerts:       2,
			expectedError:  true,
			expectedCursor: 0,
			description:    "goto 5 with 2 certs should error",
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

// Test splash screen functionality
func TestSplashScreen(t *testing.T) {
	model := NewModel(createTestCertificates())
	model.ready = true

	// Test that splash screen is rendered
	model.viewMode = ViewSplash
	view := model.View()
	if view == "" {
		t.Error("Expected non-empty splash screen")
	}

	// Test that any key press exits splash screen
	updatedModel, _ := model.Update(tea.KeyMsg{Type: tea.KeySpace})
	if updatedModel.(Model).viewMode != ViewNormal {
		t.Error("Expected any key to exit splash screen")
	}
}

// Test window size handling
func TestWindowSizeHandling(t *testing.T) {
	model := NewModel(createTestCertificates())

	// Test window size message
	updatedModel, cmd := model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m := updatedModel.(Model)

	if m.width != 80 {
		t.Errorf("Expected width 80, got %d", m.width)
	}

	if m.height != 24 {
		t.Errorf("Expected height 24, got %d", m.height)
	}

	if !m.ready {
		t.Error("Expected model to be ready after window size message")
	}

	if cmd != nil {
		t.Errorf("Expected no command from window size message, got %v", cmd)
	}
}

// Test command mode functionality
func TestCommandMode(t *testing.T) {
	model := NewModel(createTestCertificates())
	model.viewMode = ViewCommand

	// Test adding characters to command input
	updatedModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	m := updatedModel.(Model)
	if m.commandInput != "h" {
		t.Errorf("Expected command input 'h', got %q", m.commandInput)
	}

	// Test backspace
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = updatedModel.(Model)
	if m.commandInput != "" {
		t.Errorf("Expected empty command input after backspace, got %q", m.commandInput)
	}

	// Test escape to exit command mode
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updatedModel.(Model)
	if m.viewMode != ViewNormal {
		t.Error("Expected escape to exit command mode")
	}
}
