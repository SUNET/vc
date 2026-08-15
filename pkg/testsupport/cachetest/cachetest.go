// Package cachetest provides a generic constructor helper for the
// near-identical cache.New(ctx, cfg, dbService, tracer, log) tests that
// exist once per service package (apigw, verifier, registry). Each service
// has its own db.Service and cache.Service types, so this is generic over
// both rather than importing any of them directly, keeping the package
// leaf-level and import-cycle free.
package cachetest

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"
	"github.com/SUNET/vc/pkg/trace"
)

// New builds the test logger and tracer, then calls newFn with them,
// mirroring the boilerplate every service's cache.New unit test needs.
func New[S any, D any](t *testing.T, cfg *model.Cfg, dbService *D, newFn func(context.Context, *model.Cfg, *D, *trace.Tracer, *logger.Log) (*S, error)) (*S, error) {
	t.Helper()
	log := testsupport.TestLogger(t)
	tracer := tracertest.New(t, cfg, log, "cache-test")
	return newFn(t.Context(), cfg, dbService, tracer, log)
}
