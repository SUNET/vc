// Package sqltest provides shared Postgres/MariaDB testcontainer helpers,
// pre-migrated and ready to use, for repository-level SQL store tests, plus
// NewServiceForTest (service.go) - the shared "build cfg, call a db
// package's New(), register Close on cleanup" harness every db.Service's
// SQL contract test uses.
//
// It lives in its own leaf package, separate from pkg/testsupport itself,
// matching pkg/testsupport/tracertest and pkg/testsupport/cachetest: those
// two exist to avoid import cycles through packages that still depend on
// pkg/model, which this package now also imports (for NewServiceForTest).
package sqltest

import (
	"context"
	"strconv"
	"testing"

	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"

	"github.com/jmoiron/sqlx"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mariadb"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// containerHostPort resolves ctr's host and mapped port for portSpec (e.g.
// "5432/tcp") as a (host, int port) pair, terminating ctr and failing the
// test on any error - shared by every StartXxx/XxxConfig helper below, all
// of which otherwise repeated this exact host/port/strconv.Atoi sequence.
//
// Terminate always uses context.Background(), not ctx: ctx is t.Context(),
// which the testing package can cancel mid-call (e.g. on a test timeout),
// and Terminate should reliably clean up the container regardless of why
// this function is failing - matching every other cleanup path in this
// package.
func containerHostPort(t *testing.T, ctr testcontainers.Container, ctx context.Context, portSpec, label string) (string, int) {
	t.Helper()
	host, err := ctr.Host(ctx)
	if err != nil {
		_ = ctr.Terminate(context.Background())
		t.Fatalf("%s host: %v", label, err)
	}
	port, err := ctr.MappedPort(ctx, portSpec)
	if err != nil {
		_ = ctr.Terminate(context.Background())
		t.Fatalf("%s mapped port: %v", label, err)
	}
	portNum, err := strconv.Atoi(port.Port())
	if err != nil {
		_ = ctr.Terminate(context.Background())
		t.Fatalf("%s port: %v", label, err)
	}
	return host, portNum
}

// StartPostgres spins up a throwaway, fully-migrated Postgres container and
// returns a connected *sqlx.DB, its Dialect, and a cleanup function. Skips
// the calling test if Docker is not available.
//
// The returned cleanup closure always terminates the container via
// context.Background(), not the ctx used for setup: ctx is t.Context(),
// which the testing package cancels once the test is done, and the whole
// point of Terminate is to run reliably during teardown - a caller that
// registers cleanup via t.Cleanup (rather than a bare defer) could
// otherwise have it run against an already-canceled context and silently
// fail to terminate, leaking the container.
func StartPostgres(t *testing.T) (*sqlx.DB, sqlstore.Dialect, func()) {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := postgres.Run(ctx, "postgres:16", postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = ctr.Terminate(context.Background())
		t.Fatalf("postgres connection string: %v", err)
	}

	db, err := sqlx.Open(sqlstore.PostgresDialect.DriverName(), connStr)
	if err != nil {
		_ = ctr.Terminate(context.Background())
		t.Fatalf("open postgres: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_ = ctr.Terminate(context.Background())
		t.Fatalf("ping postgres: %v", err)
	}

	if err := sqlstore.ApplySchema(ctx, db, sqlstore.PostgresDialect, nil); err != nil {
		_ = db.Close()
		_ = ctr.Terminate(context.Background())
		t.Fatalf("migrate postgres: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = ctr.Terminate(context.Background())
	}
	return db, sqlstore.PostgresDialect, cleanup
}

// StartMariaDB spins up a throwaway, fully-migrated MariaDB container and
// returns a connected *sqlx.DB, its Dialect, and a cleanup function. Skips
// the calling test if Docker is not available.
func StartMariaDB(t *testing.T) (*sqlx.DB, sqlstore.Dialect, func()) {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := mariadb.Run(ctx, "mariadb:11")
	if err != nil {
		t.Fatalf("start mariadb container: %v", err)
	}

	// Deliberately NOT multiStatements=true here: ApplySchema now opens its
	// own dedicated migration connection with that enabled (see
	// MariaDBConfig.MigrationDSN) rather than needing it on the
	// application's own pool.
	connStr, err := ctr.ConnectionString(ctx, "parseTime=true")
	if err != nil {
		_ = ctr.Terminate(context.Background())
		t.Fatalf("mariadb connection string: %v", err)
	}

	db, err := sqlx.Open(sqlstore.MariaDBDialect.DriverName(), connStr)
	if err != nil {
		_ = ctr.Terminate(context.Background())
		t.Fatalf("open mariadb: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_ = ctr.Terminate(context.Background())
		t.Fatalf("ping mariadb: %v", err)
	}

	host, portNum := containerHostPort(t, ctr, ctx, "3306/tcp", "mariadb")
	cfg := &sqlstore.SQL{
		Backend: "mariadb",
		MariaDB: &sqlstore.MariaDBConfig{
			Host:     host,
			Port:     portNum,
			User:     "test",
			Password: "test",
			Database: "test",
		},
	}

	if err := sqlstore.ApplySchema(ctx, db, sqlstore.MariaDBDialect, cfg); err != nil {
		_ = db.Close()
		_ = ctr.Terminate(context.Background())
		t.Fatalf("migrate mariadb: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = ctr.Terminate(context.Background())
	}
	return db, sqlstore.MariaDBDialect, cleanup
}

// PostgresConfig spins up a throwaway, unmigrated Postgres container and
// returns a *sqlstore.PostgresConfig pointing at it (for exercising the real
// sqlstore.Connect/db.New code path, as opposed to StartPostgres's
// already-opened *sqlx.DB) and a cleanup function.
func PostgresConfig(t *testing.T) (*sqlstore.PostgresConfig, func()) {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := postgres.Run(ctx, "postgres:16", postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	host, portNum := containerHostPort(t, ctr, ctx, "5432/tcp", "postgres")

	cfg := &sqlstore.PostgresConfig{
		Host:         host,
		Port:         portNum,
		User:         "postgres",
		Password:     "postgres",
		Database:     "postgres",
		SSLMode:      "disable",
		MaxOpenConns: 5,
		MaxIdleConns: 2,
	}
	return cfg, func() { _ = ctr.Terminate(context.Background()) }
}

// MariaDBConfig spins up a throwaway, unmigrated MariaDB container and
// returns a *sqlstore.MariaDBConfig pointing at it (for exercising the real
// sqlstore.Connect/db.New code path, as opposed to StartMariaDB's
// already-opened *sqlx.DB) and a cleanup function.
func MariaDBConfig(t *testing.T) (*sqlstore.MariaDBConfig, func()) {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := mariadb.Run(ctx, "mariadb:11")
	if err != nil {
		t.Fatalf("start mariadb container: %v", err)
	}

	host, portNum := containerHostPort(t, ctr, ctx, "3306/tcp", "mariadb")

	cfg := &sqlstore.MariaDBConfig{
		Host:         host,
		Port:         portNum,
		User:         "test",
		Password:     "test",
		Database:     "test",
		MaxOpenConns: 5,
		MaxIdleConns: 2,
	}
	return cfg, func() { _ = ctr.Terminate(context.Background()) }
}
