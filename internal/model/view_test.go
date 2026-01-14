package model

import (
	"strings"
	"testing"

	"github.com/kanywst/y509/internal/config"
)

func TestRenderHeader(t *testing.T) {
	cfg, _ := config.LoadConfig()
	m := NewModel(createTestCertificates(1), cfg)
	m.width = 80
	m.height = 24
	m.ready = true

	header := m.renderHeader()
	if !strings.Contains(header, "y509 - Certificate Viewer") {
		t.Errorf("Header does not contain title")
	}
}

func TestRenderLeftPane(t *testing.T) {
	cfg, _ := config.LoadConfig()
	m := NewModel(createTestCertificates(5), cfg)
	m.width = 80
	m.height = 24
	m.ready = true

	pane := m.renderLeftPane(40, 20)
	if !strings.Contains(pane, "STATUS") || !strings.Contains(pane, "SUBJECT") {
		t.Errorf("Left pane missing headers")
	}

	// Check if all certificates are listed (at least by name)
	if !strings.Contains(pane, "Test Certificate A") {
		t.Errorf("Left pane missing certificate A")
	}
}

func TestRenderRightPane(t *testing.T) {
	cfg, _ := config.LoadConfig()
	m := NewModel(createTestCertificates(1), cfg)
	m.width = 80
	m.height = 24
	m.ready = true

	pane := m.renderRightPane(40, 20)
	// Default tab is Subject
	if !strings.Contains(pane, "Subject") || !strings.Contains(pane, "CN:") {
		t.Errorf("Right pane missing Subject details")
	}
}

func TestRenderPopup(t *testing.T) {
	cfg, _ := config.LoadConfig()
	m := NewModel(createTestCertificates(1), cfg)
	m.width = 80
	m.height = 24
	m.ready = true

	// Test Search Popup
	m.viewMode = ViewPopup
	m.popupType = PopupSearch
	view := m.View()
	if !strings.Contains(view, "Search") {
		t.Errorf("Search popup title missing")
	}

	// Test Alert Popup
	m.popupType = PopupAlert
	m.popupMessage = "Test Alert Message"
	view = m.View()
	if !strings.Contains(view, "Test Alert Message") {
		t.Errorf("Alert popup message missing")
	}
}

func TestMinimumSizeWarning(t *testing.T) {
	cfg, _ := config.LoadConfig()
	m := NewModel(createTestCertificates(1), cfg)
	m.width = 10
	m.height = 3
	m.ready = true

	view := m.View()
	// When width is small, lipgloss wraps the text, so "Terminal too small" might be split by newlines
	if !strings.Contains(view, "Terminal") || !strings.Contains(view, "too small") {
		t.Errorf("Minimum size warning not displayed or correctly wrapped")
	}
}
