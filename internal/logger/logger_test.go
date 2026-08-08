package logger

import (
	"os"
	"path/filepath"
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

func TestInitDefaultsToTempDir(t *testing.T) {
	restoreLog(t)
	// The default path is shared with any other y509 on the machine, so point
	// TMPDIR somewhere private for the duration of the test.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	if err := Init("", false); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	Log.Info("default path")
	_ = Log.Sync()

	if _, err := os.Stat(filepath.Join(os.TempDir(), "y509.log")); err != nil {
		t.Errorf("expected y509.log in %s: %v", os.TempDir(), err)
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
