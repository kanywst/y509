package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kanywst/y509/internal/model"
	"github.com/kanywst/y509/pkg/certificate"
)

func TestDebugMinimumSizeWarning(t *testing.T) {
	// Create test certificates
	certs := []*certificate.CertificateInfo{}

	// Create model
	m := model.NewModel(certs)

	// Simulate what the test is doing
	m.width = 10
	m.height = 3
	m.ready = true

	fmt.Printf("Model width: %d, height: %d\n", m.width, m.height)

	view := m.View()
	fmt.Printf("View content: %q\n", view)

	if strings.Contains(view, "Terminal too small") {
		fmt.Println("✓ Minimum size warning is working correctly")
	} else {
		fmt.Printf("✗ Expected minimum size warning, got: %q\n", view)
	}
}
