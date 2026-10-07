package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

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
		if err := os.MkdirAll(logPath, 0o700); err != nil {
			return nil, err
		}

		zc.OutputPaths = []string{
			filepath.Join(logPath, fmt.Sprintf("%s.log", name)),
		}
	}

	// Sampling is applied below, not by Build, so errors can be exempted
	// from it - see neverSampleErrors.
	sampling := zc.Sampling
	zc.Sampling = nil

	z, err := zc.Build(zap.WrapCore(neverSampleErrors(sampling)))
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

// neverSampleErrors returns a core wrapper that applies sampling to
// everything BELOW error level and lets errors through untouched.
//
// zap's production config samples by (level, message) within a one-second
// window: the first Initial records are kept and then one in Thereafter.
// Structured fields take no part in the decision, so a burst of errors
// sharing one message - which is what a well-named error message IS - is
// mostly dropped, taking its req_id, path and status with it.
//
// That is survivable for an info line and not for an error. An error record
// is the only place an operator can find out why a caller was refused:
// SUNET/vc#357 made the API hand out a request id INSTEAD of the cause, so
// a sampler quietly deciding that 400 of the last 500 failures were
// repetitive leaves those 400 callers holding an id that appears nowhere.
// Flood protection against repeated errors is a real concern, but it is the
// wrong side of this trade: an operator can rate-limit a log pipeline,
// where nobody can recover a line that was never written.
//
// A nil sampling config (the development logger) samples nothing and is
// returned unchanged.
func neverSampleErrors(sampling *zap.SamplingConfig) func(zapcore.Core) zapcore.Core {
	return func(core zapcore.Core) zapcore.Core {
		if sampling == nil {
			return core
		}
		sampled := zapcore.NewSamplerWithOptions(
			core, time.Second, sampling.Initial, sampling.Thereafter,
		)
		return zapcore.NewTee(
			&levelFilterCore{Core: sampled, accept: func(l zapcore.Level) bool { return l < zapcore.ErrorLevel }},
			&levelFilterCore{Core: core, accept: func(l zapcore.Level) bool { return l >= zapcore.ErrorLevel }},
		)
	}
}

// levelFilterCore passes only the records its predicate accepts to the core
// it wraps.
type levelFilterCore struct {
	zapcore.Core
	accept func(zapcore.Level) bool
}

func (c *levelFilterCore) Enabled(level zapcore.Level) bool {
	return c.accept(level) && c.Core.Enabled(level)
}

func (c *levelFilterCore) With(fields []zapcore.Field) zapcore.Core {
	return &levelFilterCore{Core: c.Core.With(fields), accept: c.accept}
}

func (c *levelFilterCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.accept(entry.Level) {
		return checked
	}
	return c.Core.Check(entry, checked)
}
