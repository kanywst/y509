// Package logger provides application-wide logging functionality.
package logger

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	logFileName = "y509.log"
	logDirName  = "y509"
	logDirPerm  = 0o700
)

var (
	// Log is the global logger instance, initialized with a no-op logger by default
	Log = zap.NewNop()
)

// DefaultLogFile reports where Init writes when --log-file is not given, or ""
// when this user has no private directory to write to. os.TempDir() is not an
// option: every account on the host shares it, and can prepare whatever y509
// opens there.
func DefaultLogFile() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, logDirName, logFileName)
}

// Init initializes the logger with the specified configuration.
//
// A --log-file the caller named is opened or the error is returned: they asked
// for that file, so silently not writing it would be worse than failing. The
// default destination is best-effort. A read-only or absent HOME is ordinary in
// containers, in CI and inside distribution build sandboxes, and logging is a
// side channel there -- losing it must not take the command down with it.
func Init(logFile string, debug bool) error {
	requested := logFile != ""
	if !requested {
		logFile = DefaultLogFile()
		if logFile == "" {
			// Nowhere private to log, so log nowhere.
			Log = zap.NewNop()
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(logFile), logDirPerm); err != nil {
			Log = zap.NewNop()
			return nil
		}
	}

	config := zap.NewProductionConfig()
	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.OutputPaths = []string{logFile}
	config.ErrorOutputPaths = []string{logFile}

	// Build returns a nil logger alongside the error, so assign through a local
	// rather than leaving Log nil for a caller that carries on.
	built, err := config.Build()
	if err != nil {
		if !requested {
			Log = zap.NewNop()
			return nil
		}
		return fmt.Errorf("opening the log file: %w", err)
	}
	Log = built

	return nil
}
