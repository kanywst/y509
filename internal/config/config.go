// Package config handles application configuration and theming.
package config

import (
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Theme holds the color configuration for the application.
type Theme struct {
	Text           string `mapstructure:"text"`
	Border         string `mapstructure:"border"`
	BorderFocus    string `mapstructure:"border_focus"`
	Background     string `mapstructure:"background"`
	StatusBar      string `mapstructure:"status_bar"`
	StatusBarText  string `mapstructure:"status_bar_text"`
	CommandBar     string `mapstructure:"command_bar"`
	CommandBarText string `mapstructure:"command_bar_text"`
	Error          string `mapstructure:"error"`
	Highlight      string `mapstructure:"highlight"`
	HighlightText  string `mapstructure:"highlight_text"`
	HighlightDim   string `mapstructure:"highlight_dim"`
	StatusValid    string `mapstructure:"status_valid"`
	StatusWarning  string `mapstructure:"status_warning"`
	StatusExpired  string `mapstructure:"status_expired"`
	Title          string `mapstructure:"title"`
	SectionTitle   string `mapstructure:"section_title"`
	DetailKey      string `mapstructure:"detail_key"`
	ListRowAlt     string `mapstructure:"list_row_alt"`
}

// Config holds the application's configuration.
type Config struct {
	Theme Theme `mapstructure:"theme"`
}

// newDefaultTheme returns a Theme struct with all default values.
func newDefaultTheme() Theme {
	return Theme{
		Text:           "252",
		Border:         "240",
		BorderFocus:    "62",
		Background:     "", // default to terminal background
		StatusBar:      "62",
		StatusBarText:  "230",
		CommandBar:     "240",
		CommandBarText: "255",
		Error:          "196",
		Highlight:      "62",
		HighlightText:  "230",
		HighlightDim:   "240",
		StatusValid:    "40",
		StatusWarning:  "220",
		StatusExpired:  "196",
		Title:          "aqua",
		SectionTitle:   "aqua",
		DetailKey:      "244",
		ListRowAlt:     "235",
	}
}

// LoadConfig loads the configuration from file and environment.
// It always returns a valid Config object, falling back to defaults if necessary.
func LoadConfig() (*Config, error) {
	v := viper.New()
	defaultTheme := newDefaultTheme()

	// Set default values using the default theme struct
	v.SetDefault("theme.text", defaultTheme.Text)
	v.SetDefault("theme.border", defaultTheme.Border)
	v.SetDefault("theme.border_focus", defaultTheme.BorderFocus)
	v.SetDefault("theme.background", defaultTheme.Background)
	v.SetDefault("theme.status_bar", defaultTheme.StatusBar)
	v.SetDefault("theme.status_bar_text", defaultTheme.StatusBarText)
	v.SetDefault("theme.command_bar", defaultTheme.CommandBar)
	v.SetDefault("theme.command_bar_text", defaultTheme.CommandBarText)
	v.SetDefault("theme.error", defaultTheme.Error)
	v.SetDefault("theme.highlight", defaultTheme.Highlight)
	v.SetDefault("theme.highlight_text", defaultTheme.HighlightText)
	v.SetDefault("theme.highlight_dim", defaultTheme.HighlightDim)
	v.SetDefault("theme.status_valid", defaultTheme.StatusValid)
	v.SetDefault("theme.status_warning", defaultTheme.StatusWarning)
	v.SetDefault("theme.status_expired", defaultTheme.StatusExpired)
	v.SetDefault("theme.title", defaultTheme.Title)
	v.SetDefault("theme.section_title", defaultTheme.SectionTitle)
	v.SetDefault("theme.detail_key", defaultTheme.DetailKey)
	v.SetDefault("theme.list_row_alt", defaultTheme.ListRowAlt)

	// Set config file
	v.SetConfigName(".y509")
	v.SetConfigType("yaml")
	if home, err := os.UserHomeDir(); err == nil {
		v.AddConfigPath(home)
	}
	v.AddConfigPath(".")

	// Env variables
	v.SetEnvPrefix("Y509")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file
	var readErr error
	if err := v.ReadInConfig(); err != nil {
		// We acknowledge the error but don't return nil here to ensure
		// default values are still available.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			readErr = err
		}
	}

	// Unmarshal config
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		// If unmarshal fails entirely, we still want to return a config object with hardcoded defaults
		// as a last resort, though viper defaults should have been enough.
		return &Config{Theme: defaultTheme}, err
	}

	return &config, readErr
}
