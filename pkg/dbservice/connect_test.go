package dbservice

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"

	"github.com/stretchr/testify/require"
)

// TestConnect_RejectsHAWithSQLBackend is a regression test for a real gap
// Copilot flagged: HA-mode caching (pkg/cache's Mongo-backed AuthContext/
// generic caches, wired up by each service's own cache.Service.New) needs a
// *mongo.Client, but Connect never establishes one when a SQL backend is
// selected - every service's cache setup would otherwise get a nil client
// and fail deep inside pkg/cache instead of at startup with a clear error.
func TestConnect_RejectsHAWithSQLBackend(t *testing.T) {
	log := testsupport.TestLogger(t)
	cfg := &model.Cfg{Common: &model.Common{
		HA: model.HAConfig{Enable: true},
		SQL: sqlstore.SQL{
			Backend:  "postgres",
			Postgres: &sqlstore.PostgresConfig{Host: "unused", Port: 5432, Database: "unused"},
		},
	}}
	tracer := tracertest.New(t, cfg, log, "dbservice-test")

	_, err := Connect(t.Context(), cfg, tracer, "test:db:connect")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Common.HA.Enable")
	require.True(t, strings.Contains(err.Error(), "postgres"))
}

// TestConnect_HADisabledWithSQLBackendIsUnaffected confirms the guard is
// scoped to HA.Enable specifically - it must not reject a plain SQL-backend
// deployment (the overwhelmingly common case) before ever reaching the real
// connection attempt.
func TestConnect_HADisabledWithSQLBackendIsUnaffected(t *testing.T) {
	log := testsupport.TestLogger(t)
	cfg := &model.Cfg{Common: &model.Common{
		SQL: sqlstore.SQL{
			Backend:  "postgres",
			Postgres: &sqlstore.PostgresConfig{Host: "unused", Port: 5432, Database: "unused"},
		},
	}}
	tracer := tracertest.New(t, cfg, log, "dbservice-test")

	_, err := Connect(t.Context(), cfg, tracer, "test:db:connect")
	// Expected to fail (no real Postgres at "unused"), but NOT with the
	// HA-guard error - confirms the guard didn't fire for HA.Enable=false.
	require.Error(t, err)
	require.NotContains(t, err.Error(), "Common.HA.Enable")
}
