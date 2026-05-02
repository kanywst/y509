package model

import (
	"crypto/x509"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
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
	StatusBarKey  lipgloss.Style
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
	DetailValue   lipgloss.Style
	Tab           lipgloss.Style
	TabActive     lipgloss.Style
	ListRowAlt    lipgloss.Style
	HeaderTitle   lipgloss.Style
	Breadcrumb    lipgloss.Style
	BreadcrumbSep lipgloss.Style
	PopupBorder   lipgloss.Style
	PopupTitle    lipgloss.Style
	PopupHint     lipgloss.Style
	Badge         lipgloss.Style
	BadgeValid    lipgloss.Style
	BadgeWarning  lipgloss.Style
	BadgeExpired  lipgloss.Style
	ChainLine     lipgloss.Style
	ChainNode     lipgloss.Style
	ProgressFull  lipgloss.Style
	ProgressEmpty lipgloss.Style
	Dimmed        lipgloss.Style
}

// NewStyles creates a new Styles struct from a theme.
func NewStyles(theme *config.Theme) Styles {
	return Styles{
		Pane:          lipgloss.NewStyle().Border(lipgloss.RoundedBorder(), true).BorderForeground(lipgloss.Color(theme.Border)),
		PaneFocus:     lipgloss.NewStyle().Border(lipgloss.RoundedBorder(), true).BorderForeground(lipgloss.Color(theme.BorderFocus)),
		Warning:       lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Error)).Bold(true),
		StatusBar:     lipgloss.NewStyle().Background(lipgloss.Color(theme.StatusBar)).Foreground(lipgloss.Color(theme.StatusBarText)).Padding(0, 1),
		StatusBarKey:  lipgloss.NewStyle().Background(lipgloss.Color(theme.Highlight)).Foreground(lipgloss.Color(theme.HighlightText)).Bold(true).Padding(0, 1),
		CommandBar:    lipgloss.NewStyle().Background(lipgloss.Color(theme.CommandBar)).Foreground(lipgloss.Color(theme.CommandBarText)),
		CommandError:  lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Error)).Bold(true),
		Highlight:     lipgloss.NewStyle().Background(lipgloss.Color(theme.Highlight)).Foreground(lipgloss.Color(theme.HighlightText)).Bold(true),
		HighlightDim:  lipgloss.NewStyle().Background(lipgloss.Color(theme.HighlightDim)).Foreground(lipgloss.Color(theme.Text)),
		StatusValid:   lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusValid)),
		StatusWarning: lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusWarning)),
		StatusExpired: lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusExpired)),
		Title:         lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Title)),
		SectionTitle:  lipgloss.NewStyle().Foreground(lipgloss.Color(theme.SectionTitle)).Bold(true),
		DetailKey:     lipgloss.NewStyle().Foreground(lipgloss.Color(theme.DetailKey)),
		DetailValue:   lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Text)),
		Tab:           lipgloss.NewStyle().Padding(0, 2).Foreground(lipgloss.Color(theme.DetailKey)),
		TabActive:     lipgloss.NewStyle().Padding(0, 2).Foreground(lipgloss.Color(theme.Title)).Bold(true),
		ListRowAlt:    lipgloss.NewStyle().Background(lipgloss.Color(theme.ListRowAlt)),
		HeaderTitle:   lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Title)).Bold(true).Padding(0, 1),
		Breadcrumb:    lipgloss.NewStyle().Foreground(lipgloss.Color(theme.DetailKey)),
		BreadcrumbSep: lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Border)).SetString(" › "),
		PopupBorder:   lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color(theme.BorderFocus)).Padding(1, 2),
		PopupTitle:    lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Title)).Bold(true),
		PopupHint:     lipgloss.NewStyle().Foreground(lipgloss.Color(theme.DetailKey)).Italic(true),
		Badge:         lipgloss.NewStyle().Padding(0, 1),
		BadgeValid:    lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusValid)).Bold(true),
		BadgeWarning:  lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusWarning)).Bold(true),
		BadgeExpired:  lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusExpired)).Bold(true),
		ChainLine:     lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Border)),
		ChainNode:     lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Title)),
		ProgressFull:  lipgloss.NewStyle().Foreground(lipgloss.Color(theme.StatusValid)),
		ProgressEmpty: lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Border)),
		Dimmed:        lipgloss.NewStyle().Foreground(lipgloss.Color(theme.DetailKey)),
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
	listScroll int
	viewport   viewport.Model

	// Popup state
	popupType    PopupType
	popupMessage string
	textInput    textinput.Model

	// Key bindings and help
	keys keyMap
	help help.Model

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
	tiStyles := textinput.DefaultDarkStyles()
	tiStyles.Cursor.Color = lipgloss.Color(cfg.Theme.Highlight)
	ti.SetStyles(tiStyles)
	ti.Focus()

	helpModel := help.New()
	helpModel.Styles = help.DefaultDarkStyles()

	vp := viewport.New()
	vp.MouseWheelEnabled = false
	vp.SoftWrap = true

	return &Model{
		certificates:    sortedCerts,
		allCertificates: sortedCerts,
		cursor:          0,
		ready:           false,
		viewMode:        ViewSplash,
		focus:           FocusLeft,
		tabs:            tabs,
		activeTab:       0,
		listScroll:      0,
		viewport:        vp,
		Config:          cfg,
		Styles:          NewStyles(&cfg.Theme),
		textInput:       ti,
		keys:            defaultKeyMap(),
		help:            helpModel,
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
