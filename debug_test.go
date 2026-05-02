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
	content := view.Content
	fmt.Printf("View content: %q\n", content)

	// The text might contain newlines, so we check using substrings
	if strings.Contains(content, "Terminal") && strings.Contains(content, "too small") {
		fmt.Println("✓ Minimum size warning is working correctly")
		// Test passed
	} else {
		t.Errorf("Expected minimum size warning, got: %q\n", content)
		fmt.Printf("✗ Expected minimum size warning, got: %q\n", content)
	}
}
