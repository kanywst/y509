package version

import (
	"strings"

	"go.uber.org/zap"
)

var (
	// Version is set via ldflags during build
	Version = "dev"
	// GitCommit is set via ldflags during build
	GitCommit = "unknown"
	// BuildDate is set via ldflags during build
	BuildDate = "unknown"
	logger    *zap.Logger
)

func init() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic("failed to initialize zap logger")
	}
}

// GetVersion returns the version string
func GetVersion() string {
	return Version
}

// GetFullVersion returns the full version string including git commit and build date
func GetFullVersion() string {
	version := Version

	// Add git commit if available
	if GitCommit != "unknown" {
		if len(GitCommit) > 7 {
			version += " (" + GitCommit[:7] + ")"
		} else {
			version += " (" + GitCommit + ")"
		}
	}

	// Add build date if available
	if BuildDate != "unknown" {
		version += " built on " + BuildDate
	}

	return version
}

// GetShortVersion returns just the version number for display
func GetShortVersion() string {
	version := GetVersion()
	if version == "dev" {
		return "dev"
	}
	return version
}

// IsDevVersion returns true if this is a development version
func IsDevVersion() bool {
	return Version == "dev"
}

// IsReleaseVersion returns true if this is a release version
func IsReleaseVersion() bool {
	return !IsDevVersion() && !strings.Contains(Version, "-")
}
