package model

// Focus represents which pane is currently focused
type Focus int

const (
	FocusLeft Focus = iota
	FocusRight
	FocusCommand
)

// ViewMode represents the current view mode
type ViewMode int

const (
	ViewSplash ViewMode = iota
	ViewNormal
	ViewCommand
	ViewDetail
)

// SplashDoneMsg indicates splash screen is complete
type SplashDoneMsg struct{}

// Formatting constants
const (
	// Border and padding
	borderPadding  = 2
	contentPadding = 4

	// Minimum widths for different display modes
	minUltraCompactWidth = 25
	minCompactWidth      = 40
	minMediumWidth       = 60

	// Label truncation
	labelPadding           = 8
	cnPadding              = 4
	subjectPadding         = 10
	scrollIndicatorPadding = 6

	// Status bar
	statusBarHeight  = 1
	commandBarHeight = 1
)
