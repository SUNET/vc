// Package tracertest provides a shared *trace.Tracer constructor for use in
// unit tests.
//
// It intentionally lives in its own leaf package, separate from
// pkg/testsupport: pkg/trace depends on pkg/model, which in turn depends on
// packages (e.g. pkg/mdoc) that import pkg/cache. pkg/cache's own tests
// import pkg/testsupport for its Docker/Mongo container helpers, so adding a
// pkg/trace dependency to pkg/testsupport itself would create an import
// cycle. Keeping the tracer helper here, imported only by packages that
// don't sit on that cycle, avoids the problem.
package tracertest

import (
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/stretchr/testify/require"
)

// New builds a *trace.Tracer suitable for use in unit tests, tagged with the
// given service name.
func New(t *testing.T, cfg *model.Cfg, log *logger.Log, serviceName string) *trace.Tracer {
	t.Helper()
	tracer, err := trace.New(t.Context(), cfg, serviceName, log)
	require.NoError(t, err)
	return tracer
}
