package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kanywst/y509/internal/config"
	"github.com/kanywst/y509/internal/model"
	"github.com/kanywst/y509/pkg/certificate"
)

func TestDebugMinimumSizeWarning(t *testing.T) {
	// Create test certificates
	certs := []*certificate.Info{}

	// Load config
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Create model
	m := model.NewModel(certs, cfg)

	// Simulate what the test is doing
	m.SetDimensions(10, 3)
	m.SetReady(true)

	fmt.Printf("Model width: %d, height: %d\n", m.GetWidth(), m.GetHeight())

	view := m.View()
	fmt.Printf("View content: %q\n", view)

	// The text might contain newlines, so we check using substrings
	if strings.Contains(view, "Terminal") && strings.Contains(view, "too small") {
		fmt.Println("✓ Minimum size warning is working correctly")
		// Test passed
	} else {
		t.Errorf("Expected minimum size warning, got: %q\n", view)
		fmt.Printf("✗ Expected minimum size warning, got: %q\n", view)
	}
}
