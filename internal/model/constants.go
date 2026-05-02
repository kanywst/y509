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

// Layout constants. Kept centralized so that a UI tweak in one component
// (e.g. a new bottom border) does not silently misalign sizing logic in
// Update / renderLeftPane / renderRightPane.
const (
	// statusBarHeight is the rendered height of the bottom status bar.
	statusBarHeight = 1

	// HeaderHeight is the application header (title row + divider line).
	HeaderHeight = 2

	// PaneBorderHeight accounts for the rounded top + bottom border on a
	// pane rendered with lipgloss.RoundedBorder().
	PaneBorderHeight = 2

	// ListHeaderHeight is the height occupied by the SUBJECT/EXPIRES
	// column header above the list body in renderLeftPane.
	ListHeaderHeight = 1

	// PaneSideBorderWidth accounts for the single visible border column.
	// The left pane uses BorderRight(false), so only one border column
	// occupies horizontal space.
	PaneSideBorderWidth = 1
)
