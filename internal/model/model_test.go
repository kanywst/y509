package model

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kanywst/y509/internal/config"
	"github.com/kanywst/y509/pkg/certificate"
)

// createTestCertificates creates test certificates for testing
func createTestCertificates(count int) []*certificate.Info {
	certs := make([]*certificate.Info, count)
	for i := 0; i < count; i++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject: pkix.Name{
				CommonName:   "Test Certificate " + string(rune('A'+i)),
				Organization: []string{"Test Org"},
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(24 * time.Hour),
			KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			panic(err)
		}
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			panic(err)
		}
		certs[i] = &certificate.Info{
			Certificate: cert,
		}
	}
	return certs
}

func loadTestConfig(t *testing.T) *config.Config {
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	return cfg
}

func TestNewModel(t *testing.T) {
	certs := createTestCertificates(3)
	cfg := loadTestConfig(t)
	model := NewModel(certs, cfg)

	if len(model.certificates) != 3 {
		t.Errorf("Expected 3 certificates, got %d", len(model.certificates))
	}
	if len(model.allCertificates) != 3 {
		t.Errorf("Expected 3 certificates in allCertificates, got %d", len(model.allCertificates))
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
	cfg := loadTestConfig(t)
	model := NewModel(createTestCertificates(3), cfg)
	cmd := model.Init()
	if cmd == nil {
		t.Error("Expected Init to return a command, got nil")
	}
}

func TestUpdate(t *testing.T) {
	cfg := loadTestConfig(t)
	m := *NewModel(createTestCertificates(3), cfg)
	var updatedModel tea.Model
	var cmd tea.Cmd

	msg := tea.WindowSizeMsg{Width: 100, Height: 50}
	updatedModel, cmd = m.Update(msg)
	if cmd != nil {
		t.Errorf("Expected no command from window size message, got %v", cmd)
	}
	m = updatedModel.(Model)
	if m.width != 100 || m.height != 50 {
		t.Errorf("Expected window size to be updated, got width=%d, height=%d", m.width, m.height)
	}

	m.viewMode = ViewSplash
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updatedModel.(Model)
	if m.viewMode != ViewNormal {
		t.Errorf("Expected view mode to be ViewNormal, got %v", m.viewMode)
	}

	m.viewMode = ViewNormal
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updatedModel.(Model)
	if m.cursor != 1 {
		t.Errorf("Expected cursor to be 1, got %d", m.cursor)
	}

	// Test entering Popup mode
	m.viewMode = ViewNormal
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updatedModel.(Model)
	if m.viewMode != ViewPopup {
		t.Errorf("Expected view mode to be ViewPopup after '/' key, got %v", m.viewMode)
	}
	if m.popupType != PopupSearch {
		t.Errorf("Expected popup type to be PopupSearch, got %v", m.popupType)
	}

	m = *NewModel(createTestCertificates(3), cfg)
	m.viewMode = ViewNormal
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Error("Expected quit command")
	}
}

func TestView(t *testing.T) {
	cfg := loadTestConfig(t)
	model := NewModel(createTestCertificates(3), cfg)
	model.ready = true

	model.viewMode = ViewSplash
	view := model.View()
	if view == "" {
		t.Error("Expected non-empty splash view")
	}

	model.viewMode = ViewNormal
	view = model.View()
	if view == "" {
		t.Error("Expected non-empty normal view")
	}
}

func TestUtilityFunctions(t *testing.T) {
	if max(5, 3) != 5 {
		t.Error("max(5, 3) should return 5")
	}
	if max(2, 7) != 7 {
		t.Error("max(2, 7) should return 7")
	}

	if min(5, 3) != 3 {
		t.Error("min(5, 3) should return 3")
	}
	if min(2, 7) != 2 {
		t.Error("min(2, 7) should return 2")
	}
}
