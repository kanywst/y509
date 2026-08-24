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

// DefaultLogFile reports where Init writes when --log-file is not given.
//
// A fixed name in os.TempDir() would be one world-writable path shared by every
// account on the host: interleaved lines, a file owned by whoever ran y509
// first, and a place to pre-plant a symlink that y509 then writes through.
func DefaultLogFile() string {
	path, _ := defaultLogFile()
	return path
}

// defaultLogFile also reports whether the path landed in a directory other
// users can write to.
func defaultLogFile() (path string, shared bool) {
	// $XDG_CACHE_HOME or ~/.cache, ~/Library/Caches, %LocalAppData%.
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, logDirName, logFileName), false
	}
	// Only when the environment names no home at all: a daemon, a stripped
	// cron env. Back in the shared directory, so scope the name to the user.
	return filepath.Join(os.TempDir(), tempLogDirName(), logFileName), true
}

func tempLogDirName() string {
	// Getuid is -1 on Windows, where TempDir is already per-user.
	if uid := os.Getuid(); uid >= 0 {
		return fmt.Sprintf("%s-%d", logDirName, uid)
	}
	return logDirName
}

// ensureLogDir creates the log directory, readable by its owner alone.
func ensureLogDir(dir string, shared bool) error {
	if err := os.MkdirAll(dir, logDirPerm); err != nil {
		return err
	}
	if !shared {
		return nil
	}
	// MkdirAll is content with a symlink that is already in place. In the
	// user's own cache directory that link can only be their own doing, but in
	// the shared one it can be anybody's, pointing anywhere.
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// Init initializes the logger with the specified configuration
func Init(logFile string, debug bool) error {
	if logFile == "" {
		var shared bool
		logFile, shared = defaultLogFile()
		if err := ensureLogDir(filepath.Dir(logFile), shared); err != nil {
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
