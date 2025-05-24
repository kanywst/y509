package version

import (
	"fmt"
	"runtime/debug"
)

var (
	// Version is set via ldflags during build
	Version = "dev"
	// GitCommit is set via ldflags during build
	GitCommit = ""
	// BuildDate is set via ldflags during build
	BuildDate = ""
)

// GetVersion returns the version string
func GetVersion() string {
	if Version != "dev" {
		return Version
	}

	// Try to get version from build info (for go install)
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "(devel)" && info.Main.Version != "" {
			return info.Main.Version
		}
	}

	return "dev"
}

// GetFullVersion returns the full version string with build info
func GetFullVersion() string {
	version := GetVersion()

	if GitCommit != "" {
		if len(GitCommit) > 7 {
			version += fmt.Sprintf(" (%s)", GitCommit[:7])
		} else {
			version += fmt.Sprintf(" (%s)", GitCommit)
		}
	}

	if BuildDate != "" {
		version += fmt.Sprintf(" built on %s", BuildDate)
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
