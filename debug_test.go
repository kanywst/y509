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
	m.SetDimensions(10, 3)
	m.SetReady(true)

	fmt.Printf("Model width: %d, height: %d\n", m.GetWidth(), m.GetHeight())

	view := m.View()
	fmt.Printf("View content: %q\n", view)

	// テキストには改行が含まれるかもしれないので、正規表現を使用して確認します
	if strings.Contains(view, "Terminal") && strings.Contains(view, "too small") {
		fmt.Println("✓ Minimum size warning is working correctly")
		// テストは成功
	} else {
		t.Errorf("Expected minimum size warning, got: %q\n", view)
		fmt.Printf("✗ Expected minimum size warning, got: %q\n", view)
	}
}
