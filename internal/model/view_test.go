package model

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/y509/internal/config"
	"github.com/kanywst/y509/pkg/certificate"
)

func TestChainPositionLabelsLoneSelfSignedAsRoot(t *testing.T) {
	cfg, _ := config.LoadConfig()
	m := NewModel(createTestCertificates(1), cfg)

	out := m.renderChainPosition(m.allCertificates[0])
	if !strings.Contains(out, "Root") {
		t.Errorf("lone self-signed cert should be labeled Root, got:\n%s", out)
	}
	if strings.Contains(out, "Leaf") {
		t.Errorf("lone self-signed cert should not be labeled Leaf, got:\n%s", out)
	}
}

func TestStatusIconReflectsExpiringSoon(t *testing.T) {
	cfg, _ := config.LoadConfig()
	styles := NewStyles(&cfg.Theme)

	// Fixed window so the test doesn't depend on a local .y509 config.
	const warnDays = 30

	tests := []struct {
		name     string
		notAfter time.Time
		want     string
	}{
		{name: "Already expired", notAfter: time.Now().Add(-24 * time.Hour), want: "✖"},
		{name: "Expiring within window", notAfter: time.Now().Add(5 * 24 * time.Hour), want: "▲"},
		{name: "Well in the future", notAfter: time.Now().Add(365 * 24 * time.Hour), want: "●"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &certificate.Info{
				Certificate:      &x509.Certificate{NotAfter: tt.notAfter},
				ValidationStatus: certificate.StatusGood,
			}
			icon, _ := getStatusIconAndStyle(info, styles, warnDays)
			if icon != tt.want {
				t.Errorf("icon = %q, want %q", icon, tt.want)
			}
		})
	}
}

func TestRenderHeader(t *testing.T) {
	cfg, _ := config.LoadConfig()
	m := NewModel(createTestCertificates(1), cfg)
	m.width = 80
	m.height = 24
	m.ready = true

	header := m.renderHeader()
	if !strings.Contains(header, "y509") {
		t.Errorf("Header does not contain title")
	}
}

func TestRenderLeftPane(t *testing.T) {
	cfg, _ := config.LoadConfig()
	m := NewModel(createTestCertificates(5), cfg)
	m.width = 80
	m.height = 24
	m.list.SetSize(38, 18)
	m.ready = true

	pane := m.renderLeftPane(40, 20)
	if !strings.Contains(pane, "SUBJECT") {
		t.Errorf("Left pane missing headers")
	}

	// Check if all certificates are listed (at least by name)
	if !strings.Contains(pane, "Test Certificate A") {
		t.Errorf("Left pane missing certificate A")
	}
}

func TestRenderRightPane(t *testing.T) {
	cfg, _ := config.LoadConfig()
	mp := NewModel(createTestCertificates(1), cfg)
	mp.width = 80
	mp.height = 24
	mp.ready = true
	m := mp.resizeComponents().refreshViewportContent()

	pane := m.renderRightPane(40, 20)
	// Default tab is Subject
	if !strings.Contains(pane, "Subject") || !strings.Contains(pane, "CN") {
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
	view := m.View().Content
	if !strings.Contains(view, "Search") {
		t.Errorf("Search popup title missing")
	}

	// Test Alert Popup
	m.popupType = PopupAlert
	m.popupMessage = "Test Alert Message"
	view = m.View().Content
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

	view := m.View().Content
	// When width is small, lipgloss wraps the text, so "Terminal too small" might be split by newlines
	if !strings.Contains(view, "Terminal") || !strings.Contains(view, "too small") {
		t.Errorf("Minimum size warning not displayed or correctly wrapped")
	}
}
