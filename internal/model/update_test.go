package model

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kanywst/y509/pkg/certificate"
)

// Helper to create a dummy certificate
func createDummyCert(index int) *certificate.Info {
	return &certificate.Info{
		Certificate: &x509.Certificate{
			SerialNumber: big.NewInt(int64(index)),
			Subject:      pkix.Name{CommonName: "Test Cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		},
		Index: index,
		Label: "Test Cert",
	}
}

func TestNavigationKeys(t *testing.T) {
	certs := []*certificate.Info{
		createDummyCert(1),
		createDummyCert(2),
		createDummyCert(3),
	}
	cfg := loadTestConfig(t)
	modelPtr := NewModel(certs, cfg)
	m := *modelPtr
	m.SetDimensions(100, 20)
	m.viewMode = ViewNormal
	m.focus = FocusLeft
	m.ready = true

	// Test 'j' (down) in list
	t.Run("NormalMode_List_Down_j", func(t *testing.T) {
		initialCursor := m.cursor
		newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = newModel.(Model)
		if m.cursor != initialCursor+1 {
			t.Errorf("Expected cursor to increment (j), got %d", m.cursor)
		}
	})

	// Test 'k' (up) in list
	t.Run("NormalMode_List_Up_k", func(t *testing.T) {
		initialCursor := m.cursor
		newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(Model)
		if m.cursor != initialCursor-1 {
			t.Errorf("Expected cursor to decrement (k), got %d", m.cursor)
		}
	})

	// Switch focus to right pane
	m.focus = FocusRight

	// Test 'j' (scroll down) in detail pane (Normal Mode)
	t.Run("NormalMode_Detail_Down_j", func(t *testing.T) {
		initialScroll := m.rightPaneScroll
		newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = newModel.(Model)
		if m.rightPaneScroll != initialScroll+1 {
			t.Errorf("Expected scroll to increment (j), got %d", m.rightPaneScroll)
		}
	})

	// Test 'k' (scroll up) in detail pane (Normal Mode)
	t.Run("NormalMode_Detail_Up_k", func(t *testing.T) {
		initialScroll := m.rightPaneScroll
		newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(Model)
		if m.rightPaneScroll != initialScroll-1 {
			t.Errorf("Expected scroll to decrement (k), got %d", m.rightPaneScroll)
		}
	})
}
