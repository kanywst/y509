package config

import (
	"os"
	"path/filepath"
	"testing"
)

// LoadConfig searches $HOME and the working directory for .y509.yaml. Both are
// redirected so a developer's real config cannot change the result.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	t.Chdir(t.TempDir())
	return home
}

func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".y509.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	isolate(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.ExpiryWarningDays != DefaultExpiryWarningDays {
		t.Errorf("ExpiryWarningDays = %d, want %d", cfg.ExpiryWarningDays, DefaultExpiryWarningDays)
	}
	want := newDefaultTheme()
	if cfg.Theme != want {
		t.Errorf("Theme = %+v, want %+v", cfg.Theme, want)
	}
}

func TestLoadConfigMissingFileIsNotAnError(t *testing.T) {
	isolate(t)

	// No .y509.yaml anywhere: a ConfigFileNotFoundError must be swallowed so the
	// TUI still starts with defaults.
	if _, err := LoadConfig(); err != nil {
		t.Errorf("LoadConfig() error = %v, want nil when no config file exists", err)
	}
}

func TestLoadConfigReadsHomeConfig(t *testing.T) {
	home := isolate(t)
	writeConfig(t, home, "theme:\n  text: \"#ffffff\"\n  title: \"#ff0000\"\nexpiry_warning_days: 7\n")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Theme.Text != "#ffffff" {
		t.Errorf("Theme.Text = %q, want %q", cfg.Theme.Text, "#ffffff")
	}
	if cfg.Theme.Title != "#ff0000" {
		t.Errorf("Theme.Title = %q, want %q", cfg.Theme.Title, "#ff0000")
	}
	if cfg.ExpiryWarningDays != 7 {
		t.Errorf("ExpiryWarningDays = %d, want 7", cfg.ExpiryWarningDays)
	}
	// Keys the file did not mention keep their defaults.
	if want := newDefaultTheme().Border; cfg.Theme.Border != want {
		t.Errorf("Theme.Border = %q, want the default %q", cfg.Theme.Border, want)
	}
}

func TestLoadConfigPrefersHomeOverWorkingDirectory(t *testing.T) {
	home := isolate(t)
	writeConfig(t, home, "theme:\n  text: \"#111111\"\n")

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	writeConfig(t, cwd, "theme:\n  text: \"#222222\"\n")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// $HOME is registered first, so viper resolves it ahead of ".".
	if cfg.Theme.Text != "#111111" {
		t.Errorf("Theme.Text = %q, want the home config to win with %q", cfg.Theme.Text, "#111111")
	}
}

func TestLoadConfigClampsNonPositiveExpiryWindow(t *testing.T) {
	for _, body := range []string{"expiry_warning_days: 0\n", "expiry_warning_days: -5\n"} {
		t.Run(body, func(t *testing.T) {
			home := isolate(t)
			writeConfig(t, home, body)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig() error = %v", err)
			}
			if cfg.ExpiryWarningDays != DefaultExpiryWarningDays {
				t.Errorf("ExpiryWarningDays = %d, want it clamped to %d",
					cfg.ExpiryWarningDays, DefaultExpiryWarningDays)
			}
		})
	}
}

func TestLoadConfigReportsMalformedFileButStillReturnsDefaults(t *testing.T) {
	home := isolate(t)
	writeConfig(t, home, "theme: [this is not a mapping\n")

	cfg, err := LoadConfig()
	if err == nil {
		t.Error("LoadConfig() error = nil, want a parse error for malformed YAML")
	}
	if cfg == nil {
		t.Fatal("LoadConfig() returned a nil config; callers rely on it always being usable")
	}
	if cfg.ExpiryWarningDays != DefaultExpiryWarningDays {
		t.Errorf("ExpiryWarningDays = %d, want the default %d even after a parse error",
			cfg.ExpiryWarningDays, DefaultExpiryWarningDays)
	}
}

func TestNewDefaultThemeHasNoEmptyColors(t *testing.T) {
	theme := newDefaultTheme()

	if theme.Text == "" || theme.Border == "" || theme.Background == "" {
		t.Errorf("default theme has empty core colors: %+v", theme)
	}
}
