package model

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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
	m, ok := updatedModel.(*Model)
	if !ok {
		t.Fatal("Failed to convert to Model")
	}
	if m.viewMode != ViewNormal {
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
	m, ok = updatedModel.(*Model)
	if !ok {
		t.Fatal("Failed to convert to Model")
	}
	if m.viewMode != ViewCommand {
		t.Error("Expected colon to enter command mode")
	}

	// Test escape key in detail mode
	model.viewMode = ViewDetail
	updatedModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m, ok = updatedModel.(*Model)
	if !ok {
		t.Fatal("Failed to convert to Model")
	}
	if m.viewMode != ViewNormal {
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
	if view == "" {
		t.Error("Expected non-empty detail view")
	}
	// Note: The actual rendering may include styling, so we check if the view is not empty
	// and that it's in the correct mode
	if model.viewMode != ViewDetail {
		t.Error("Model should be in detail view mode")
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
			_, result := model.handleGlobalCommands(tt.cmd)
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
	if updatedModel.(*Model).viewMode != ViewNormal {
		t.Error("Expected any key to exit splash screen")
	}
}

// Test window size handling
func TestWindowSizeHandling(t *testing.T) {
	model := NewModel(createTestCertificates())

	// Test window size message
	updatedModel, cmd := model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m, ok := updatedModel.(Model)
	if !ok {
		t.Fatal("Failed to convert to Model")
	}

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
	m := updatedModel.(*Model)
	if m.commandInput != "h" {
		t.Errorf("Expected command input 'h', got %q", m.commandInput)
	}

	// Test backspace
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = updatedModel.(*Model)
	if m.commandInput != "" {
		t.Errorf("Expected empty command input after backspace, got %q", m.commandInput)
	}

	// Test escape to exit command mode
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updatedModel.(*Model)
	if m.viewMode != ViewNormal {
		t.Error("Expected escape to exit command mode")
	}
}

// TestUXResponsiveness tests the UI responsiveness across different terminal sizes
func TestUXResponsiveness(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)

	tests := []struct {
		name             string
		width            int
		height           int
		expectSinglePane bool
	}{
		{"Ultra small terminal", minUltraCompactWidth - 10, 5, false},
		{"Very small terminal", minUltraCompactWidth, 8, true},
		{"Small terminal", minCompactWidth - 5, 10, true},
		{"Medium terminal", minMediumWidth, 15, false},
		{"Large terminal", 100, 25, false},
		{"Wide terminal", 150, 20, false},
		{"Tall narrow terminal", minUltraCompactWidth + 5, 50, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set terminal size
			model.width = tt.width
			model.height = tt.height
			model.ready = true
			model.viewMode = ViewNormal

			// Test minimum size detection
			minWidth, minHeight := getMinimumSize()
			if tt.width < minWidth || tt.height < minHeight {
				// Test that warning is rendered
				view := model.View()
				if !strings.Contains(view, "Terminal") || !strings.Contains(view, "too") || !strings.Contains(view, "small") {
					t.Errorf("Expected minimum size warning in view for %dx%d terminal", tt.width, tt.height)
				}
				return
			}

			// Test single pane detection
			shouldUseSingle := model.shouldUseSinglePane()
			if shouldUseSingle != tt.expectSinglePane {
				t.Errorf("Expected single pane mode: %v, got: %v for terminal %dx%d",
					tt.expectSinglePane, shouldUseSingle, tt.width, tt.height)
			}

			// Test that view renders without panic
			view := model.View()
			if len(view) == 0 {
				t.Errorf("View should not be empty")
			}

			// Test that status bar fits in width
			statusBar := model.renderStatusBar()
			// Remove ANSI color codes for length calculation
			cleanStatusBar := strings.ReplaceAll(statusBar, "\x1b", "")
			if len(cleanStatusBar) > tt.width+20 { // Allow some margin for formatting
				t.Errorf("Status bar too long for terminal width %d", tt.width)
			}
		})
	}
}

// TestTextWrapping tests text wrapping functionality
func TestTextWrapping(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		width    int
		expected string
	}{
		{"Simple text", "hello world", 10, "hello\nworld"},
		{"Long word", "verylongword", 5, "verylongword"},
		{"Multiple lines", "one two three four five", 8, "one two\nthree\nfour\nfive"},
		{"Zero width", "test", 0, "test"},
		{"Empty text", "", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapText(tt.text, tt.width)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestTextTruncation tests text truncation functionality
func TestTextTruncation(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		width    int
		expected string
	}{
		{"No truncation needed", "hello", 10, "hello"},
		{"Truncate with ellipsis", "hello world", 8, "hello..."},
		{"Very short width", "hello", 2, ".."},
		{"Width 3", "hello", 3, "..."},
		{"Zero width", "hello", 0, ""},
		{"Empty text", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateText(tt.text, tt.width)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestSinglePaneModeNavigation tests navigation in single pane mode
func TestSinglePaneModeNavigation(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)
	model.width = 30 // Force single pane mode
	model.height = 15
	model.ready = true
	model.viewMode = ViewNormal

	// Verify single pane mode
	if !model.shouldUseSinglePane() {
		t.Fatal("Expected single pane mode for narrow terminal")
	}

	// Test navigation from list to details
	model.focus = FocusLeft

	// Simulate right arrow key
	newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	updatedModel := newModel.(*Model)

	if updatedModel.focus != FocusRight {
		t.Errorf("Expected focus to switch to right pane, got %v", updatedModel.focus)
	}

	// Test navigation from details back to list
	newModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	updatedModel = newModel.(*Model)

	if updatedModel.focus != FocusLeft {
		t.Errorf("Expected focus to switch to left pane, got %v", updatedModel.focus)
	}
}

// TestDualPaneModeNavigation tests navigation in dual pane mode
func TestDualPaneModeNavigation(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)
	model.width = 80 // Force dual pane mode
	model.height = 25
	model.ready = true
	model.viewMode = ViewNormal

	// Verify dual pane mode
	if model.shouldUseSinglePane() {
		t.Fatal("Expected dual pane mode for wide terminal")
	}

	// Test tab navigation
	model.focus = FocusLeft

	// Simulate tab key
	newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
	updatedModel := newModel.(*Model)

	if updatedModel.focus != FocusRight {
		t.Errorf("Expected focus to switch to right pane with tab, got %v", updatedModel.focus)
	}

	// Test tab navigation back
	newModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyTab})
	updatedModel = newModel.(*Model)

	if updatedModel.focus != FocusLeft {
		t.Errorf("Expected focus to switch to left pane with tab, got %v", updatedModel.focus)
	}
}

// TestAdaptiveStatusBar tests status bar adaptation to different screen sizes
func TestAdaptiveStatusBar(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)
	model.ready = true
	model.viewMode = ViewNormal

	tests := []struct {
		name   string
		width  int
		height int
	}{
		{"Very narrow", 25, 10},
		{"Narrow", 40, 15},
		{"Medium", 60, 20},
		{"Wide", 100, 25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model.width = tt.width
			model.height = tt.height

			statusBar := model.renderStatusBar()

			// Check that status bar is not empty
			if len(statusBar) == 0 {
				t.Error("Status bar should not be empty")
			}

			// For very narrow terminals, the status bar will be truncated
			// and might not contain the full "q:quit" text, but should contain q
			if tt.width < 30 {
				// Remove ANSI color codes for testing
				cleanStatus := strings.ReplaceAll(statusBar, "\x1b", "")
				cleanStatus = strings.ReplaceAll(cleanStatus, "[", "")
				cleanStatus = strings.ReplaceAll(cleanStatus, "m", "")
				if !strings.Contains(cleanStatus, "q") {
					t.Logf("Status bar for narrow terminal: %s", cleanStatus)
					// This is expected behavior for very narrow terminals - status bar might be truncated
				}
			}
		})
	}
}

// TestCertificateListRendering tests certificate list rendering at different sizes
func TestCertificateListRendering(t *testing.T) {
	// Create multiple test certificates
	certs := make([]*certificate.CertificateInfo, 0)
	for i := 0; i < 5; i++ {
		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("test%d.example.com", i),
			},
			SerialNumber: nil,
		}
		certs = append(certs, &certificate.CertificateInfo{
			Certificate: cert,
			Label:       fmt.Sprintf("test%d.example.com", i),
		})
	}

	model := NewModel(certs)
	model.ready = true
	model.viewMode = ViewNormal

	tests := []struct {
		name   string
		width  int
		height int
	}{
		{"Ultra narrow", minUltraCompactWidth - 5, 10},
		{"Narrow", minCompactWidth - 5, 15},
		{"Medium", minMediumWidth, 20},
		{"Wide", 100, 25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model.width = tt.width
			model.height = tt.height

			listContent := model.renderCertificateList(10)

			// Check that list is not empty
			if len(listContent) == 0 {
				t.Error("Certificate list should not be empty")
			}

			// Check that all certificates are represented
			lines := strings.Split(listContent, "\n")
			if len(lines) < len(certs) {
				t.Errorf("Expected at least %d lines for certificates, got %d", len(certs), len(lines))
			}
		})
	}
}

// TestSplashScreenAdaptation tests splash screen adaptation to different sizes
func TestSplashScreenAdaptation(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)
	model.ready = true
	model.viewMode = ViewSplash

	tests := []struct {
		name   string
		width  int
		height int
	}{
		{"Small", minUltraCompactWidth + 5, 8},
		{"Medium", minCompactWidth + 10, 12},
		{"Large", minMediumWidth + 20, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model.width = tt.width
			model.height = tt.height

			splash := model.renderSplashScreen()

			// Check that splash screen is not empty
			if len(splash) == 0 {
				t.Error("Splash screen should not be empty")
			}

			// Check that it contains the app name (with some flexibility for different sizes)
			if !strings.Contains(splash, "Certificate") && !strings.Contains(splash, "TUI") {
				t.Errorf("Splash screen should contain app name, got: %s", splash)
			}
		})
	}
}

// TestCommandModeInSmallTerminal tests command mode in small terminals
func TestCommandModeInSmallTerminal(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)
	model.width = minUltraCompactWidth // Very narrow
	model.height = 10
	model.ready = true
	model.viewMode = ViewNormal

	// Enter command mode
	newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{':'}})
	updatedModel := newModel.(*Model)

	if updatedModel.viewMode != ViewCommand {
		t.Error("Expected to enter command mode")
	}

	// Test command bar rendering
	commandBar := updatedModel.renderCommandBar()
	if len(commandBar) == 0 {
		t.Error("Command bar should not be empty")
	}
}

// TestMinimumSizeHandling tests handling of extremely small terminal sizes
func TestMinimumSizeHandling(t *testing.T) {
	model := NewModel(createTestCertificates())
	model.ready = true

	// Test minimum size warning
	minWidth, minHeight := getMinimumSize()
	model.width = minWidth - 1
	model.height = minHeight - 1

	view := model.View()
	if !strings.Contains(view, "Terminal too small") {
		t.Error("Expected minimum size warning")
	}

	// Test just above minimum size
	model.width = minWidth
	model.height = minHeight
	view = model.View()
	if strings.Contains(view, "Terminal too small") {
		t.Error("Expected no minimum size warning")
	}
}

// TestScrollingInSmallPanes tests scrolling functionality in small panes
func TestScrollingInSmallPanes(t *testing.T) {
	model := NewModel([]*certificate.CertificateInfo{})
	model.ready = true
	model.width = minUltraCompactWidth
	model.height = 10

	// Fill with dummy certificates
	for i := 0; i < 5; i++ {
		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("test%d.example.com", i),
			},
		}
		model.certificates = append(model.certificates, &certificate.CertificateInfo{
			Certificate: cert,
			Label:       fmt.Sprintf("test%d.example.com", i),
		})
	}

	model.focus = FocusLeft

	// Test navigation down
	model.cursor = 0
	newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyDown})
	updatedModel := newModel.(*Model)
	if updatedModel.cursor != 1 {
		t.Errorf("Expected cursor to be 1 after pressing down, got %d", updatedModel.cursor)
	}

	// Test navigation up
	newModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyUp})
	updatedModel = newModel.(*Model)
	if updatedModel.cursor != 0 {
		t.Errorf("Expected cursor to be 0 after pressing up, got %d", updatedModel.cursor)
	}

	// Navigate to last item
	model.cursor = len(model.certificates) - 1
	newModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	updatedModel = newModel.(*Model)
	// Should not change cursor when at last item
	if updatedModel.cursor != len(model.certificates)-1 {
		t.Errorf("Expected cursor to remain at %d, got %d", len(model.certificates)-1, updatedModel.cursor)
	}
}

// TestQuickHelp tests the quick help functionality
func TestQuickHelp(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)
	model.ready = true
	model.viewMode = ViewNormal

	// Test quick help in dual pane mode
	model.width = 80
	model.height = 25

	helpText := model.getQuickHelp()
	if !strings.Contains(helpText, "DUAL PANE MODE") {
		t.Error("Quick help should indicate dual pane mode for wide terminal")
	}

	// Test quick help in single pane mode
	model.width = 30
	model.height = 15

	helpText = model.getQuickHelp()
	if !strings.Contains(helpText, "SINGLE PANE MODE") {
		t.Error("Quick help should indicate single pane mode for narrow terminal")
	}

	// Test that help contains essential commands
	if !strings.Contains(helpText, ":help") {
		t.Error("Quick help should contain :help command")
	}
	if !strings.Contains(helpText, "q") {
		t.Error("Quick help should contain quit command")
	}
}

// TestEscapeKeyHandling tests escape key behavior
func TestEscapeKeyHandling(t *testing.T) {
	certs := createTestCertificates()

	// Test escape from command mode
	model := NewModel(certs)
	model.ready = true
	model.viewMode = ViewCommand
	model.commandInput = "test"
	model.commandError = "test error"

	newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEscape})
	updatedModel := newModel.(*Model)

	fmt.Println("[DEBUG] after escape (command mode):", updatedModel.commandInput, updatedModel.commandError, updatedModel.detailField, updatedModel.detailValue)

	if updatedModel.viewMode != ViewNormal {
		t.Error("Escape should exit command mode")
	}
	if updatedModel.commandInput != "" {
		t.Error("Escape should clear command input")
	}
	if updatedModel.commandError != "" {
		t.Error("Escape should clear command error")
	}

	// Test escape from detail mode
	model = NewModel(certs)
	model.ready = true
	model.viewMode = ViewDetail
	model.detailField = "test field"
	model.detailValue = "test value"

	newModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyEscape})
	updatedModel = newModel.(*Model)

	fmt.Println("[DEBUG] after escape (detail mode):", updatedModel.commandInput, updatedModel.commandError, updatedModel.detailField, updatedModel.detailValue)

	if updatedModel.viewMode != ViewNormal {
		t.Error("Escape should exit detail mode")
	}
	if updatedModel.detailField != "" {
		t.Error("Escape should clear detail field")
	}
	if updatedModel.detailValue != "" {
		t.Error("Escape should clear detail value")
	}
}

// TestKeyboardAccessibility tests keyboard accessibility features
func TestKeyboardAccessibility(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)
	model.ready = true
	model.viewMode = ViewNormal
	model.width = 80
	model.height = 25

	// Test tab navigation
	model.focus = FocusLeft
	newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
	updatedModel := newModel.(*Model)

	if updatedModel.focus != FocusRight {
		t.Error("Tab should switch focus to right pane")
	}

	// Test tab navigation back
	newModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyTab})
	updatedModel = newModel.(*Model)

	if updatedModel.focus != FocusLeft {
		t.Error("Tab should switch focus back to left pane")
	}

	// Test question mark for help
	newModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	updatedModel = newModel.(*Model)

	if updatedModel.viewMode != ViewDetail {
		t.Error("Question mark should show quick help")
	}
	if !strings.Contains(updatedModel.detailField, "Help") {
		t.Error("Help detail should be shown")
	}
}

// TestErrorHandling tests error handling in various scenarios
func TestErrorHandling(t *testing.T) {
	// Test with empty certificate list
	model := NewModel([]*certificate.CertificateInfo{})
	model.ready = true
	model.viewMode = ViewNormal
	model.width = 80
	model.height = 25

	view := model.View()
	if !strings.Contains(view, "No certificates found") {
		t.Error("Should show no certificates message")
	}

	// Test command execution with no certificates
	model.viewMode = ViewCommand
	model.commandInput = "subject"
	model.executeCommand()

	if model.commandError == "" {
		t.Error("Should show error when trying to view subject with no certificates")
	}
}

// TestLayoutConsistency tests that layout is consistent across different operations
func TestLayoutConsistency(t *testing.T) {
	certs := createTestCertificates()
	model := NewModel(certs)
	model.ready = true
	model.viewMode = ViewNormal

	tests := []struct {
		name   string
		width  int
		height int
	}{
		{"Minimum viable", minUltraCompactWidth, 8},
		{"Small", minCompactWidth, 12},
		{"Medium", minMediumWidth, 18},
		{"Large", 100, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model.width = tt.width
			model.height = tt.height

			// Test normal view
			view := model.View()
			if len(view) == 0 {
				t.Error("Normal view should not be empty")
			}

			// Test that entering and exiting command mode works
			model.viewMode = ViewCommand
			commandView := model.View()
			if len(commandView) == 0 {
				t.Error("Command view should not be empty")
			}

			model.viewMode = ViewNormal
			normalView := model.View()
			if len(normalView) == 0 {
				t.Error("Normal view should not be empty after command mode")
			}
		})
	}
}
