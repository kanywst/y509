package logger

import (
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

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("os.UserCacheDir() reads %LocalAppData% on Windows")
	}
}

// privateCacheDir keeps a test of the default path off the real cache directory.
func privateCacheDir(t *testing.T) string {
	t.Helper()
	skipOnWindows(t)

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

func TestInitWithoutAUserCacheDirWritesNothing(t *testing.T) {
	restoreLog(t)
	skipOnWindows(t)

	tmp := t.TempDir()
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("TMPDIR", tmp)

	if got := DefaultLogFile(); got != "" {
		t.Errorf("DefaultLogFile() = %q, want no default", got)
	}
	if err := Init("", false); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	Log.Info("nowhere to go")
	_ = Log.Sync()

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("reading the temporary directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Init() wrote %d entries into the shared %s", len(entries), tmp)
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

// A container, a CI runner or a distribution build sandbox can hand y509 a HOME
// it cannot write to. Logging is a side channel there, so the whole command
// must not exit: PersistentPreRun turns any error from Init into os.Exit(1),
// which took down every subcommand, --help and completion included.
func TestInitSurvivesAnUncreatableDefaultDirectory(t *testing.T) {
	restoreLog(t)
	skipOnWindows(t)

	// A cache directory whose parent is a regular file can never be created.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding the file: %v", err)
	}
	t.Setenv("HOME", blocked)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(blocked, ".cache"))

	if err := Init("", false); err != nil {
		t.Fatalf("Init() error = %v, want nil so the command still runs", err)
	}
	if Log == nil {
		t.Fatal("Init() left Log nil, so the first log line panics")
	}
	Log.Info("nowhere to go")
	_ = Log.Sync()
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
