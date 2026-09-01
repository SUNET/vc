package sqltest

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/stretchr/testify/require"
)

// Closer is satisfied by every db.Service (apigw, verifier, ...): each has
// its own concrete Service type, but all share this one method shape.
type Closer interface {
	Close(context.Context) error
}

// NewServiceFunc matches a db package's own New(ctx, cfg, tracer, log)
// constructor - every db.Service package has one with this exact signature.
type NewServiceFunc[S Closer] func(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (S, error)

// NewServiceForTest builds a *logger.Log and *trace.Tracer, calls newFn to
// exercise a db package's real New()/newSQL() code path end to end (config
// -> sqlstore.Connect -> sqlstore.ApplySchema -> store wiring) against cfg,
// and registers svc.Close on t.Cleanup. This is the one piece of setup
// every db.Service's SQL contract test shares - callers still build cfg
// themselves (via PostgresConfig/MariaDBConfig below) and still write their
// own package-specific assertions against the returned service.
func NewServiceForTest[S Closer](t *testing.T, tracerName string, cfg *model.Cfg, newFn NewServiceFunc[S]) S {
	t.Helper()
	log := testsupport.TestLogger(t)
	tracer := tracertest.New(t, cfg, log, tracerName)

	svc, err := newFn(t.Context(), cfg, tracer, log)
	require.NoError(t, err)
	require.NotNil(t, svc)
	// t.Cleanup-registered functions run after the testing package cancels
	// t.Context(), so Close must use a fresh context here - not t.Context()
	// again, which would already be done for by the time this runs.
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	return svc
}

// RunPostgresAndMariaDBContract runs newFn (a db package's own New()) against
// both a fresh Postgres and a fresh MariaDB testcontainer, as subtests named
// "Postgres"/"MariaDB", calling checkFn against each resulting service. This
// is the shared two-backend contract-test shape every db.Service's SQL test
// uses; callers keep their own checkFn with package-specific assertions.
func RunPostgresAndMariaDBContract[S Closer](t *testing.T, tracerName string, newFn NewServiceFunc[S], checkFn func(*testing.T, S)) {
	t.Helper()

	t.Run("Postgres", func(t *testing.T) {
		pgCfg, cleanup := PostgresConfig(t)
		defer cleanup()
		cfg := &model.Cfg{Common: &model.Common{SQL: sqlstore.SQL{Backend: "postgres", Postgres: pgCfg}}}
		checkFn(t, NewServiceForTest(t, tracerName, cfg, newFn))
	})

	t.Run("MariaDB", func(t *testing.T) {
		mdbCfg, cleanup := MariaDBConfig(t)
		defer cleanup()
		cfg := &model.Cfg{Common: &model.Common{SQL: sqlstore.SQL{Backend: "mariadb", MariaDB: mdbCfg}}}
		checkFn(t, NewServiceForTest(t, tracerName, cfg, newFn))
	})
}
