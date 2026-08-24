package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func restoreLog(t *testing.T) {
	t.Helper()
	old := Log
	t.Cleanup(func() { Log = old })
}

func TestInitWritesToTheGivenFile(t *testing.T) {
	restoreLog(t)
	logFile := filepath.Join(t.TempDir(), "y509.log")

	if err := Init(logFile, false); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	Log.Info("hello from the test")
	if err := Log.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	if !strings.Contains(string(data), "hello from the test") {
		t.Errorf("log file does not contain the message, got %q", data)
	}
}

func TestInitDebugEnablesDebugLevel(t *testing.T) {
	restoreLog(t)
	logFile := filepath.Join(t.TempDir(), "debug.log")

	if err := Init(logFile, true); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if !Log.Core().Enabled(zap.DebugLevel) {
		t.Error("debug level is not enabled after Init(_, true)")
	}

	Log.Debug("a debug line")
	_ = Log.Sync()

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	if !strings.Contains(string(data), "a debug line") {
		t.Errorf("debug line was not written, got %q", data)
	}
}

func TestInitWithoutDebugDropsDebugLines(t *testing.T) {
	restoreLog(t)
	logFile := filepath.Join(t.TempDir(), "info.log")

	if err := Init(logFile, false); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if Log.Core().Enabled(zap.DebugLevel) {
		t.Error("debug level should be disabled by default")
	}
}

// privateCacheDir points the user cache directory at a scratch directory, so a
// test exercising the default log path never touches the real one.
func privateCacheDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the cache directory is resolved from %LocalAppData% on Windows")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	dir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("os.UserCacheDir() error = %v", err)
	}
	return dir
}

func TestDefaultLogFileIsUnderTheUserCacheDir(t *testing.T) {
	cache := privateCacheDir(t)

	want := filepath.Join(cache, "y509", "y509.log")
	if got := DefaultLogFile(); got != want {
		t.Errorf("DefaultLogFile() = %q, want %q", got, want)
	}
}

func TestDefaultLogFileIsNotSharedInTempDir(t *testing.T) {
	// No home of any kind, so the cache directory cannot be resolved and the
	// fallback kicks in. It may live in os.TempDir(), but never as a fixed name
	// straight in it -- that is the collision the fallback exists to avoid.
	if runtime.GOOS == "windows" {
		t.Skip("os.UserCacheDir() reads %LocalAppData% on Windows, not $HOME")
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")

	got := DefaultLogFile()
	if dir := filepath.Dir(got); dir == os.TempDir() {
		t.Errorf("DefaultLogFile() = %q, which is a fixed name in the shared %s", got, os.TempDir())
	}
	if want := fmt.Sprintf("y509-%d", os.Getuid()); filepath.Base(filepath.Dir(got)) != want {
		t.Errorf("DefaultLogFile() = %q, want the parent directory scoped to the user as %q", got, want)
	}
}

func TestInitDefaultsToAPrivateUserDirectory(t *testing.T) {
	restoreLog(t)
	privateCacheDir(t)

	if err := Init("", false); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	Log.Info("default path")
	_ = Log.Sync()

	logFile := DefaultLogFile()
	if _, err := os.Stat(logFile); err != nil {
		t.Fatalf("expected the log at %s: %v", logFile, err)
	}

	info, err := os.Stat(filepath.Dir(logFile))
	if err != nil {
		t.Fatalf("stat of the log directory: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("log directory mode = %#o, want %#o so no other user can read it", perm, 0o700)
	}
}

func TestInitReturnsErrorForUnwritablePath(t *testing.T) {
	restoreLog(t)
	// A path whose parent is a regular file can never be opened for writing.
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding the file: %v", err)
	}

	if err := Init(filepath.Join(parent, "y509.log"), false); err == nil {
		t.Error("Init() returned nil for a path under a regular file")
	}
}
