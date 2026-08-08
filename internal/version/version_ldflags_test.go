package version

import "testing"

// The exported getters read package-level variables that release builds stamp
// through -ldflags. A test binary never gets those flags, so the interesting
// branches are only reachable by setting the variables directly.
func withVars(t *testing.T, v, commit, date string) {
	t.Helper()
	oldV, oldC, oldD := Version, GitCommit, BuildDate
	t.Cleanup(func() { Version, GitCommit, BuildDate = oldV, oldC, oldD })
	Version, GitCommit, BuildDate = v, commit, date
}

func TestGetFullVersionTruncatesLongCommit(t *testing.T) {
	withVars(t, "v1.2.3", "0123456789abcdef", "2026-08-08T00:00:00Z")

	want := "v1.2.3 (0123456) built on 2026-08-08T00:00:00Z"
	if got := GetFullVersion(); got != want {
		t.Errorf("GetFullVersion() = %q, want %q", got, want)
	}
}

func TestGetFullVersionKeepsShortCommitWhole(t *testing.T) {
	withVars(t, "v1.2.3", "abc123", "unknown")

	want := "v1.2.3 (abc123)"
	if got := GetFullVersion(); got != want {
		t.Errorf("GetFullVersion() = %q, want %q", got, want)
	}
}

func TestGetFullVersionOmitsUnknownFields(t *testing.T) {
	withVars(t, "v1.2.3", "unknown", "unknown")

	if got := GetFullVersion(); got != "v1.2.3" {
		t.Errorf("GetFullVersion() = %q, want %q", got, "v1.2.3")
	}
}

func TestGetShortVersionReturnsTagForReleases(t *testing.T) {
	withVars(t, "v1.2.3", "unknown", "unknown")

	if got := GetShortVersion(); got != "v1.2.3" {
		t.Errorf("GetShortVersion() = %q, want %q", got, "v1.2.3")
	}
}

func TestVersionKindPredicates(t *testing.T) {
	tests := []struct {
		version   string
		isDev     bool
		isRelease bool
	}{
		{"dev", true, false},
		{"v1.2.3", false, true},
		{"v1.2.3-rc.1", false, false},
		{"v1.2.3-dirty", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			withVars(t, tt.version, "unknown", "unknown")

			if got := IsDevVersion(); got != tt.isDev {
				t.Errorf("IsDevVersion() = %v, want %v", got, tt.isDev)
			}
			if got := IsReleaseVersion(); got != tt.isRelease {
				t.Errorf("IsReleaseVersion() = %v, want %v", got, tt.isRelease)
			}
		})
	}
}
