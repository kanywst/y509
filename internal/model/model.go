package model

import (
	"crypto/x509"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/y509/internal/config"
	"github.com/kanywst/y509/pkg/certificate"
)

type (
	// Focus represents which pane is currently focused
	Focus int
)

const (
	// FocusLeft is for the left pane
	FocusLeft Focus = iota
	// FocusRight is for the right pane
	FocusRight
)

// Styles holds the lipgloss styles for the application, based on the theme.
type Styles struct {
	Pane          lipgloss.Style
	PaneFocus     lipgloss.Style
	Warning       lipgloss.Style
	StatusBar     lipgloss.Style
	CommandBar    lipgloss.Style
	CommandError  lipgloss.Style
	Highlight     lipgloss.Style
	HighlightDim  lipgloss.Style
	StatusValid   lipgloss.Style
	StatusWarning lipgloss.Style
	StatusExpired lipgloss.Style
	Title         lipgloss.Style
	SectionTitle  lipgloss.Style
	DetailKey     lipgloss.Style
	Tab           lipgloss.Style
	TabActive     lipgloss.Style
	TabSeparator  lipgloss.Style
	ListRowAlt    lipgloss.Style
}

// NewStyles creates a new Styles struct from a theme.
func NewStyles(theme *config.Theme) Styles {
	return Styles{
		Pane:          lipgloss.NewStyle().Border(lipgloss.RoundedBorder(), true).BorderForeground(lipgloss.Color(theme.Border)),
		PaneFocus:     lipgloss.NewStyle().Border(lipgloss.RoundedBorder(), true).BorderForeground(lipgloss.Color(theme.BorderFocus)),
		Warning:       lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Error)).Bold(true),
		StatusBar:     lipgloss.NewStyle().Background(lipgloss.Color(theme.StatusBar)).Foreground(lipgloss.Color(theme.StatusBarText)).Bold(true),
		CommandBar:    lipgloss.NewStyle().Background(lipgloss.Color(theme.CommandBar)).Foreground(lipgloss.Color(theme.CommandBarText)),
		CommandError:  lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Error)).Bold(true),
		Highlight:     lipgloss.NewStyle().Background(lipgloss.Color(theme.Highlight)).Foreground(lipgloss.Color(theme.HighlightText)),
		HighlightDim:  lipgloss.NewStyle().Background(lipgloss.Color(theme.HighlightDim)),
		StatusValid:   lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusValid)),
		StatusWarning: lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusWarning)),
		StatusExpired: lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusExpired)),
		Title:         lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Title)),
		SectionTitle:  lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Title)).Bold(true),
		DetailKey:     lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Text)).Bold(true),
		Tab:           lipgloss.NewStyle().Padding(0, 1),
		TabActive:     lipgloss.NewStyle().Padding(0, 1).Underline(true).Bold(true),
		TabSeparator:  lipgloss.NewStyle().Foreground(lipgloss.Color("240")).SetString(" | "),
		ListRowAlt:    lipgloss.NewStyle().Background(lipgloss.Color(theme.ListRowAlt)),
	}
}

// Model represents the application state
type Model struct {
	certificates    []*certificate.Info // Filtered list of certificates
	allCertificates []*certificate.Info // Original unfiltered list
	cursor          int                 // Index of the selected certificate
	width           int                 // Window width
	height          int                 // Window height
	ready           bool                // Whether dimensions are initialized
	Config          *config.Config      // Application configuration
	Styles          Styles              // Computed Lip Gloss styles
	focus           Focus               // Currently focused pane

	// Tabs for the right pane
	tabs      []string
	activeTab int

	// View mode
	viewMode ViewMode

	// Scrolling
	rightPaneScroll int
	listScroll      int

	// Popup state
	popupType    PopupType
	popupMessage string
	textInput    textinput.Model

	// Internal state for logic
	detailField  string
	detailValue  string
	searchQuery  string
	filterActive bool
	filterType   string
}

// SetDimensions sets the width and height of the model (for testing only)
func (m *Model) SetDimensions(width, height int) {
	m.width = width
	m.height = height
}

// SetReady sets the ready state of the model (for testing only)
func (m *Model) SetReady(ready bool) {
	m.ready = ready
}

// GetWidth returns the width of the model (for testing only)
func (m Model) GetWidth() int {
	return m.width
}

// GetHeight returns the height of the model (for testing only)
func (m Model) GetHeight() int {
	return m.height
}

// NewModel creates a new model with certificates
func NewModel(certs []*certificate.Info, cfg *config.Config) *Model {
	// Defensive check for config
	if cfg == nil {
		var err error
		cfg, err = config.LoadConfig()
		if err != nil {
			// This should not happen as LoadConfig has defaults, but handle just in case
			panic("failed to load initial configuration")
		}
	}

	// Sort and validate the certificate chain
	var sortedCerts []*certificate.Info
	if len(certs) > 0 {
		rawCerts := make([]*x509.Certificate, len(certs))
		for i, c := range certs {
			rawCerts[i] = c.Certificate
		}
		// Sort the raw certificates
		sortedRawCerts, _ := certificate.SortChain(rawCerts)

		// Map raw certificates to their Info wrappers for efficient lookup.
		// Use fingerprint as key, and a slice of wrappers to handle potential duplicates
		// in the input (preserving their distinct metadata like original index).
		certMap := make(map[string][]*certificate.Info)
		for _, c := range certs {
			fingerprint := certificate.FormatFingerprint(c.Certificate)
			certMap[fingerprint] = append(certMap[fingerprint], c)
		}

		// Build sorted list of Info
		sortedCerts = make([]*certificate.Info, len(sortedRawCerts))
		for i, rawCert := range sortedRawCerts {
			fingerprint := certificate.FormatFingerprint(rawCert)
			if infos, ok := certMap[fingerprint]; ok && len(infos) > 0 {
				// Take the first available wrapper for this fingerprint
				sortedCerts[i] = infos[0]
				// Remove it from the map slice so duplicates use the next available wrapper
				certMap[fingerprint] = infos[1:]
			} else {
				// Safeguard: Create a new wrapper if not found in map (should not happen if SortChain only reorders)
				sortedCerts[i] = &certificate.Info{
					Certificate: rawCert,
				}
			}
		}
		certificate.ValidateChainLinks(sortedCerts)
	}

	tabs := []string{"Subject", "Issuer", "Validity", "SANs", "Misc"}

	ti := textinput.New()
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(cfg.Theme.Highlight))
	ti.Focus()

	return &Model{
		certificates:    sortedCerts,
		allCertificates: sortedCerts,
		cursor:          0,
		ready:           false,
		viewMode:        ViewSplash,
		focus:           FocusLeft,
		tabs:            tabs,
		activeTab:       0,
		rightPaneScroll: 0,
		listScroll:      0,
		Config:          cfg,
		Styles:          NewStyles(&cfg.Theme),
		textInput:       ti,
		// Logic fields
		detailField:  "",
		detailValue:  "",
		searchQuery:  "",
		filterActive: false,
		filterType:   "",
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	// Wait a bit for the splash screen to be visible
	return tea.Tick(time.Millisecond*500, func(_ time.Time) tea.Msg {
		return SplashDoneMsg{}
	})
}
