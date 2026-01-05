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
func createDummyCert(index int) *certificate.CertificateInfo {
	return &certificate.CertificateInfo{
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
	certs := []*certificate.CertificateInfo{
		createDummyCert(1),
		createDummyCert(2),
		createDummyCert(3),
	}

	modelPtr := NewModel(certs)
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

func TestDetailModeNavigation(t *testing.T) {
	certs := []*certificate.CertificateInfo{createDummyCert(1)}
	modelPtr := NewModel(certs)
	m := *modelPtr
	m.SetDimensions(100, 20)
	m.viewMode = ViewDetail
	m.ready = true

	// Test 'j' (scroll down) in Detail Mode
	t.Run("DetailMode_Down_j", func(t *testing.T) {
		initialScroll := m.rightPaneScroll
		newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = newModel.(Model)
		if m.rightPaneScroll != initialScroll+1 {
			t.Errorf("Expected scroll to increment (j) in Detail Mode, got %d", m.rightPaneScroll)
		}
	})

	// Test 'k' (scroll up) in Detail Mode
	t.Run("DetailMode_Up_k", func(t *testing.T) {
		initialScroll := m.rightPaneScroll
		newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(Model)
		if m.rightPaneScroll != initialScroll-1 {
			t.Errorf("Expected scroll to decrement (k) in Detail Mode, got %d", m.rightPaneScroll)
		}
	})
}

func TestMouseNavigation(t *testing.T) {
	certs := []*certificate.CertificateInfo{
		createDummyCert(1),
		createDummyCert(2),
	}
	modelPtr := NewModel(certs)
	m := *modelPtr
	m.SetDimensions(100, 20)
	m.viewMode = ViewNormal
	m.focus = FocusLeft
	m.ready = true

	// Test Mouse Wheel Down (List)
	t.Run("Mouse_List_Down", func(t *testing.T) {
		initialCursor := m.cursor
		newModel, _ := m.Update(tea.MouseMsg{Button: tea.MouseButtonWheelDown})
		m = newModel.(Model)
		if m.cursor != initialCursor+1 {
			t.Errorf("Expected cursor to increment (wheel down), got %d", m.cursor)
		}
	})

	// Test Mouse Wheel Up (List)
	t.Run("Mouse_List_Up", func(t *testing.T) {
		initialCursor := m.cursor
		newModel, _ := m.Update(tea.MouseMsg{Button: tea.MouseButtonWheelUp})
		m = newModel.(Model)
		if m.cursor != initialCursor-1 {
			t.Errorf("Expected cursor to decrement (wheel up), got %d", m.cursor)
		}
	})
}
