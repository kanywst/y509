// Package logger provides application-wide logging functionality.
package logger

import (
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Log is the global logger instance, initialized with a no-op logger by default
	Log = zap.NewNop()
)

// Init initializes the logger with the specified configuration
func Init(logFile string, debug bool) error {
	if logFile == "" {
		logFile = filepath.Join(os.TempDir(), "y509.log")
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
