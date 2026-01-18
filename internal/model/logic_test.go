package model

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFilterLogic(t *testing.T) {
	cfg := loadTestConfig(t)
	certs := createTestCertificates(5)

	// Manually set some statuses for testing
	now := time.Now()
	certs[0].Certificate.NotAfter = now.Add(-time.Hour)     // Expired
	certs[1].Certificate.NotAfter = now.Add(24 * time.Hour) // Expiring soon

	m := *NewModel(certs, cfg)
	m.ready = true

	t.Run("Filter_Expired", func(t *testing.T) {
		m = m.filterCertificates("expired")
		if len(m.certificates) != 1 {
			t.Errorf("Expected 1 expired certificate, got %d", len(m.certificates))
		}
	})

	t.Run("Filter_Invalid", func(t *testing.T) {
		m = m.filterCertificates("invalid-type")
		if m.viewMode != ViewPopup || m.popupType != PopupAlert {
			t.Errorf("Expected PopupAlert for invalid filter, got viewMode=%v, popupType=%v", m.viewMode, m.popupType)
		}
		if !strings.Contains(m.popupMessage, "Invalid filter type") {
			t.Errorf("Expected error message, got %q", m.popupMessage)
		}
	})

	t.Run("Filter_Reset", func(t *testing.T) {
		m = m.resetView()
		if len(m.certificates) != 5 {
			t.Errorf("Expected 5 certificates after reset, got %d", len(m.certificates))
		}
	})

	t.Run("Filter_Valid", func(t *testing.T) {
		m = m.filterCertificates("valid")
		// certs[0] is expired, others are valid
		if len(m.certificates) != 4 {
			t.Errorf("Expected 4 valid certificates, got %d", len(m.certificates))
		}
	})
}

func TestSearchLogic(t *testing.T) {
	cfg := loadTestConfig(t)
	certs := createTestCertificates(3)
	certs[0].Certificate.Subject.CommonName = "FindMe"
	certs[1].Certificate.Issuer.CommonName = "IssuerSearch"
	certs[2].Certificate.Subject.Organization = []string{"OrgSearch"}

	m := *NewModel(certs, cfg)

	t.Run("Search_Subject_CN", func(t *testing.T) {
		m = m.searchCertificates("FindMe")
		if len(m.certificates) != 1 {
			t.Errorf("Expected 1 match for 'FindMe', got %d", len(m.certificates))
		}
	})

	t.Run("Search_Issuer_CN", func(t *testing.T) {
		m = m.resetView()
		m = m.searchCertificates("IssuerSearch")
		if len(m.certificates) != 1 {
			t.Errorf("Expected 1 match for 'IssuerSearch', got %d", len(m.certificates))
		}
	})

	t.Run("Search_Organization", func(t *testing.T) {
		m = m.resetView()
		m = m.searchCertificates("OrgSearch")
		if len(m.certificates) != 1 {
			t.Errorf("Expected 1 match for 'OrgSearch', got %d", len(m.certificates))
		}
	})
}

func TestTabNavigation(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel(createTestCertificates(1), cfg)
	m.viewMode = ViewNormal
	m.focus = FocusRight
	m.activeTab = 0

	// Press Tab
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = newModel.(Model)
	if m.activeTab != 1 {
		t.Errorf("Expected activeTab to be 1 after Tab, got %d", m.activeTab)
	}
}

func TestPopupTransitions(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel(createTestCertificates(1), cfg)
	m.viewMode = ViewNormal

	// Press '/' to search
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updatedModel.(Model)
	if m.viewMode != ViewPopup || m.popupType != PopupSearch {
		t.Errorf("Failed to enter Search popup")
	}

	// Press Esc to cancel
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updatedModel.(Model)
	if m.viewMode != ViewNormal {
		t.Errorf("Expected return to Normal mode after Esc")
	}

	// Enter search again
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updatedModel.(Model)

	// Type 'test' and press Enter
	m.textInput.SetValue("test")
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updatedModel.(Model)
	if m.viewMode != ViewNormal {
		t.Errorf("Expected return to ViewNormal after popup Enter")
	}
	if m.searchQuery != "test" {
		t.Errorf("Expected searchQuery to be 'test', got '%s'", m.searchQuery)
	}
}

func TestAutoScrolling(t *testing.T) {
	cfg := loadTestConfig(t)
	// Create enough certs to force scrolling
	m := *NewModel(createTestCertificates(20), cfg)
	m.height = 10 // Small height
	m.ready = true
	m.viewMode = ViewNormal
	m.focus = FocusLeft
	m.listScroll = 0
	m.cursor = 0

	// Move cursor down multiple times to trigger scroll
	for i := 0; i < 15; i++ {
		m = m.moveCursorDown()
	}

	if m.cursor != 15 {
		t.Errorf("Cursor position mismatch: %d", m.cursor)
	}
	if m.listScroll == 0 {
		t.Errorf("List should have scrolled, but listScroll is 0")
	}

	// Move cursor up multiple times to trigger scroll up
	for i := 0; i < 15; i++ {
		m = m.moveCursorUp()
	}
	if m.cursor != 0 {
		t.Errorf("Cursor should be back at 0")
	}
	if m.listScroll != 0 {
		t.Errorf("listScroll should be back at 0")
	}
}

func TestDuplicateHandling(t *testing.T) {
	cfg := loadTestConfig(t)
	certs := createTestCertificates(2)
	// Make them identical
	certs[1].Certificate = certs[0].Certificate
	certs[1].Index = 1 // But keep distinct metadata

	m := NewModel(certs, cfg)
	if len(m.certificates) != 2 {
		t.Errorf("Expected 2 certificates despite duplicates, got %d", len(m.certificates))
	}
}

func TestExportLogic(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel(createTestCertificates(1), cfg)
	m.ready = true

	t.Run("Export_Success", func(t *testing.T) {
		m = m.handleExportCommand("test_export.pem")
		if m.viewMode != ViewPopup || m.popupType != PopupAlert {
			t.Errorf("Expected PopupAlert after export")
		}
		if !strings.Contains(m.popupMessage, "successfully") {
			t.Errorf("Expected success message, got %q", m.popupMessage)
		}
	})

	t.Run("Export_Empty_Filename", func(t *testing.T) {
		m = *NewModel(createTestCertificates(1), cfg)
		m = m.handleExportCommand("")
		if m.viewMode != ViewSplash {
			t.Errorf("Expected no change for empty filename, got viewMode=%v", m.viewMode)
		}
	})
}
