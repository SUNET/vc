package logger

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log for portability
type Log struct {
	logr.Logger
}

// New creates a default logger based on what kind of environment is used.
func New(name, logPath string, production bool) (*Log, error) {
	var zc zap.Config

	switch production {
	case true:
		zc = zap.NewProductionConfig()
	case false:
		zc = zap.NewDevelopmentConfig()
		zc.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	zc.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zc.DisableCaller = true
	zc.DisableStacktrace = true

	if logPath != "" {
		if err := os.MkdirAll(logPath, fs.ModeDir); err != nil {
			return nil, err
		}

		zc.OutputPaths = []string{
			filepath.Join(logPath, fmt.Sprintf("%s.log", name)),
		}
	}

	z, err := zc.Build()
	if err != nil {
		return nil, err
	}

	log := zapr.NewLogger(z)

	return &Log{Logger: log.WithName(name)}, nil
}

// NewSimple creates a simple logger for barbaric purposes
func NewSimple(name string) *Log {
	return &Log{Logger: zapr.NewLogger(zap.L().Named(name))}
}

// New creates a sub-logger of the original one
func (l *Log) New(path string) *Log {
	return &Log{Logger: l.WithName(path)}
}

// Info log
func (l *Log) Info(msg string, args ...any) {
	l.Logger.V(0).WithValues(args...).Info(msg)
}

// Warn log - same verbosity as Info but signals a potential problem
func (l *Log) Warn(msg string, args ...any) {
	l.Logger.V(0).WithValues(args...).Info("WARN: " + msg)
}

// Debug log
func (l *Log) Debug(msg string, args ...any) {
	l.Logger.V(1).WithValues(args...).Info(msg)
}

// Trace log
func (l *Log) Trace(msg string, args ...any) {
	l.Logger.V(2).WithValues(args...).Info(msg)
}
