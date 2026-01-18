package model

// ViewMode represents the current view mode
type ViewMode int

const (
	// ViewSplash is the initial loading screen
	ViewSplash ViewMode = iota
	// ViewNormal is the standard two-pane view
	ViewNormal
	// ViewHelp is the full-screen help overlay
	ViewHelp
	// ViewPopup is the modal popup overlay
	ViewPopup
)

// PopupType defines the type of popup currently displayed
type PopupType int

const (
	// PopupNone indicates no popup is active
	PopupNone PopupType = iota
	// PopupSearch is the search input popup
	PopupSearch
	// PopupFilter is the filter criteria popup
	PopupFilter
	// PopupExport is the certificate export filename popup
	PopupExport
	// PopupAlert is a notification popup
	PopupAlert // For validation results or errors
)

// SplashDoneMsg indicates splash screen is complete
type SplashDoneMsg struct{}

// Formatting constants
const (
	// Status bar
	statusBarHeight  = 1
	commandBarHeight = 1

	// Layout heights
	HeaderHeight     = 2 // Title + separator line
	PaneBorderHeight = 2 // Top and bottom borders
	ListHeaderHeight = 2 // "STATUS", "SUBJECT", etc. + separator
)
