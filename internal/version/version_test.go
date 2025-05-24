package version

import (
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	version := GetVersion()
	if version == "" {
		t.Error("Expected non-empty version")
	}

	// In development, version might be "dev" or contain "v"
	if version != "dev" && !strings.Contains(version, "v") {
		t.Errorf("Expected version to be 'dev' or contain 'v', got %q", version)
	}
}

func TestGetFullVersion(t *testing.T) {
	fullVersion := GetFullVersion()
	if fullVersion == "" {
		t.Error("Expected non-empty full version")
	}

	// In development environment, it might just return "dev"
	if fullVersion == "dev" {
		// This is acceptable in development
		return
	}

	// In production builds, should contain version, commit, and date
	expectedParts := []string{"Version:", "Commit:", "Date:"}
	for _, part := range expectedParts {
		if !strings.Contains(fullVersion, part) {
			t.Errorf("Expected full version to contain %q, got %q", part, fullVersion)
		}
	}
}

func TestGetShortVersion(t *testing.T) {
	shortVersion := GetShortVersion()
	if shortVersion == "" {
		t.Error("Expected non-empty short version")
	}

	// In development, both might be "dev"
	fullVersion := GetFullVersion()
	if shortVersion == "dev" && fullVersion == "dev" {
		// This is acceptable in development
		return
	}

	// In production, short version should be shorter than or equal to full version
	if len(shortVersion) > len(fullVersion) {
		t.Error("Expected short version to be shorter than or equal to full version")
	}
}
