package model

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kanywst/y509/pkg/certificate"
)

// Model represents the application state
type Model struct {
	certificates    []*certificate.CertificateInfo
	allCertificates []*certificate.CertificateInfo // Original unfiltered list
	cursor          int
	focus           Focus
	width           int
	height          int
	ready           bool

	// Command mode
	viewMode     ViewMode
	commandInput string
	commandError string

	// Detail view
	detailField string
	detailValue string

	// Search and filter
	searchQuery  string
	filterActive bool
	filterType   string

	// Splash screen
	splashTimer int

	// Right pane scrolling
	rightPaneScroll int
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
func NewModel(certs []*certificate.CertificateInfo) *Model {
	return &Model{
		certificates:    certs,
		allCertificates: certs,
		cursor:          0,
		focus:           FocusLeft,
		ready:           false,
		viewMode:        ViewSplash,
		commandInput:    "",
		commandError:    "",
		detailField:     "",
		detailValue:     "",
		searchQuery:     "",
		filterActive:    false,
		filterType:      "",
		splashTimer:     0,
		rightPaneScroll: 0,
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	// スプラッシュスクリーンを表示するために少し待機
	return tea.Tick(time.Millisecond*500, func(t time.Time) tea.Msg {
		return SplashDoneMsg{}
	})
}