// Package version provides version information for the application.
package version

import (
	"runtime/debug"
	"strings"
)

var (
	// Version is the current version of the application
	Version = "dev"
	// GitCommit is the git commit hash at build time
	GitCommit = "unknown"
	// BuildDate is the date the binary was built
	BuildDate = "unknown"
)

// Release builds get these values from -ldflags. A `go install` build gets no
// ldflags at all, so it reported itself as "dev" forever -- even though the
// toolchain had already stamped the module version and the VCS revision into
// the binary. Read them back out.
func init() {
	if Version != "dev" {
		// -ldflags won; leave everything alone.
		return
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	// "(devel)" is what a build from a local working tree reports.
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = info.Main.Version
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			GitCommit = setting.Value
		case "vcs.time":
			BuildDate = setting.Value
		}
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
