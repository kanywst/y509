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

// Init initializes the logger with the specified configuration
func Init(logFile string, debug bool) error {
	if logFile == "" {
		logFile = DefaultLogFile()
		if logFile == "" {
			// Nowhere private to log, so log nowhere.
			Log = zap.NewNop()
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(logFile), logDirPerm); err != nil {
			return fmt.Errorf("creating the log directory: %w", err)
		}
	}

	config := zap.NewProductionConfig()
	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.OutputPaths = []string{logFile}
	config.ErrorOutputPaths = []string{logFile}

	var err error
	Log, err = config.Build()
	if err != nil {
		return err
	}

	return nil
}
