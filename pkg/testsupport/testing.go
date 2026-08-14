package testsupport

import (
	"testing"

	"github.com/SUNET/vc/pkg/logger"

	"github.com/stretchr/testify/require"
)

// TestLogger builds a *logger.Log suitable for use in unit tests.
//
// Deliberately does not also provide a TestTracer helper here: pkg/trace
// depends on pkg/model, which in turn depends on packages (e.g. pkg/mdoc)
// that import pkg/cache. Since pkg/cache's own tests import testsupport,
// pulling pkg/trace/pkg/model into this package would create an import
// cycle. Tracer construction for tests stays local to each caller package.
func TestLogger(t *testing.T) *logger.Log {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	return log
}
