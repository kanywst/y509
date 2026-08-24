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
	// logFileName is the basename of the default log file.
	logFileName = "y509.log"
	// logDirName is the per-application directory the default log lives in.
	logDirName = "y509"
	// logDirPerm keeps the default log directory readable by its owner alone.
	// The log records which files were opened and which hosts were dialled,
	// which on a shared machine is nobody else's business.
	logDirPerm = 0o700
)

var (
	// Log is the global logger instance, initialized with a no-op logger by default
	Log = zap.NewNop()
)

// DefaultLogFile reports the path Init writes to when --log-file is not given.
//
// It deliberately avoids a fixed name directly in os.TempDir(). /tmp is shared
// and world-writable, so every account on a host would append to the same
// /tmp/y509.log: interleaved lines, a file whose owner is whoever ran y509
// first (so the next user's run fails outright), and an obvious place for
// someone else to pre-plant a symlink that y509 then writes through.
func DefaultLogFile() string {
	// UserCacheDir is per-user by construction: $XDG_CACHE_HOME or ~/.cache on
	// Linux, ~/Library/Caches on macOS, %LocalAppData% on Windows.
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, logDirName, logFileName)
	}

	// It only fails when the environment names no home at all -- a daemon, a
	// stripped cron env. Fall back to os.TempDir(), still scoped so that two
	// accounts never meet in the same file.
	return filepath.Join(os.TempDir(), tempLogDirName(), logFileName)
}

// tempLogDirName names the fallback directory after the current user.
func tempLogDirName() string {
	// Getuid returns -1 on Windows, where TempDir is already per-user.
	if uid := os.Getuid(); uid >= 0 {
		return fmt.Sprintf("%s-%d", logDirName, uid)
	}
	return logDirName
}

// Init initializes the logger with the specified configuration
func Init(logFile string, debug bool) error {
	if logFile == "" {
		logFile = DefaultLogFile()

		// The default path lives in a directory y509 owns and may have to
		// create. 0700 is the part that matters: it is what keeps the other
		// accounts on the host out of the log, and what stops them from
		// planting the file before this process gets there.
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
