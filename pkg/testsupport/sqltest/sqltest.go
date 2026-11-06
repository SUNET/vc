// Package sqltest provides shared Postgres/MariaDB testcontainer helpers,
// pre-migrated or unmigrated, for repository-level SQL store tests, plus
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

// runPostgres starts a throwaway postgres:16 container with the module's basic
// wait strategies and terminates it when the test ends, failing the test on a
// terminate error. It skips the test when Docker is not available and fails it
// when the start fails. Every Postgres helper here starts through it.
func runPostgres(t *testing.T) *postgres.PostgresContainer {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctr, err := postgres.Run(t.Context(), "postgres:16", postgres.BasicWaitStrategies())
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	return ctr
}

// runMariaDB starts a throwaway mariadb:11 container with the module's wait
// strategy and terminates it when the test ends, failing the test on a
// terminate error. It skips the test when Docker is not available and fails it
// when the start fails. Every MariaDB helper here starts through it.
func runMariaDB(t *testing.T) *mariadb.MariaDBContainer {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctr, err := mariadb.Run(t.Context(), "mariadb:11")
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("start mariadb container: %v", err)
	}
	return ctr
}

// containerHostPort returns ctr's host and the host port mapped to portSpec
// (e.g. "5432/tcp"), failing the test on any error.
func containerHostPort(t *testing.T, ctr testcontainers.Container, portSpec, label string) (string, int) {
	t.Helper()
	ctx := t.Context()
	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("%s host: %v", label, err)
	}
	port, err := ctr.MappedPort(ctx, portSpec)
	if err != nil {
		t.Fatalf("%s mapped port: %v", label, err)
	}
	portNum, err := strconv.Atoi(port.Port())
	if err != nil {
		t.Fatalf("%s port: %v", label, err)
	}
	return host, portNum
}

// openDB returns a pinged pool on connStr and closes it when the test ends,
// before the container's termination. It fails the test on any error.
func openDB(t *testing.T, dialect sqlstore.Dialect, connStr string) *sqlx.DB {
	t.Helper()
	db, err := sqlx.Open(dialect.DriverName(), connStr)
	if err != nil {
		t.Fatalf("open %s: %v", dialect.Name(), err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatalf("ping %s: %v", dialect.Name(), err)
	}
	return db
}

// OpenPostgres starts a container as runPostgres does and returns a connected,
// unmigrated *sqlx.DB. The pool closes and the container terminates when the
// test ends.
func OpenPostgres(t *testing.T) *sqlx.DB {
	t.Helper()
	ctr := runPostgres(t)
	connStr, err := ctr.ConnectionString(t.Context(), "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}
	return openDB(t, sqlstore.PostgresDialect, connStr)
}

// OpenMariaDB starts a container as runMariaDB does and returns a connected,
// unmigrated *sqlx.DB plus the config sqlstore.ApplySchema needs to migrate it.
// The pool closes and the container terminates when the test ends.
//
// The pool has parseTime=true and lacks multiStatements: ApplySchema opens its
// own migration connection with that enabled (see MariaDBConfig.MigrationDSN).
func OpenMariaDB(t *testing.T) (*sqlx.DB, *sqlstore.SQL) {
	t.Helper()
	ctr := runMariaDB(t)
	connStr, err := ctr.ConnectionString(t.Context(), "parseTime=true")
	if err != nil {
		t.Fatalf("mariadb connection string: %v", err)
	}
	db := openDB(t, sqlstore.MariaDBDialect, connStr)
	return db, &sqlstore.SQL{Backend: "mariadb", MariaDB: mariaDBConfig(t, ctr)}
}

// StartPostgres returns a connected, fully-migrated *sqlx.DB and its Dialect,
// on a container started as OpenPostgres does.
func StartPostgres(t *testing.T) (*sqlx.DB, sqlstore.Dialect) {
	t.Helper()
	db := OpenPostgres(t)
	if err := sqlstore.ApplySchema(t.Context(), db, sqlstore.PostgresDialect, nil); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	return db, sqlstore.PostgresDialect
}

// StartMariaDB returns a connected, fully-migrated *sqlx.DB and its Dialect,
// on a container started as OpenMariaDB does.
func StartMariaDB(t *testing.T) (*sqlx.DB, sqlstore.Dialect) {
	t.Helper()
	db, cfg := OpenMariaDB(t)
	if err := sqlstore.ApplySchema(t.Context(), db, sqlstore.MariaDBDialect, cfg); err != nil {
		t.Fatalf("migrate mariadb: %v", err)
	}
	return db, sqlstore.MariaDBDialect
}

// PostgresConfig starts a container as runPostgres does and returns a
// *sqlstore.PostgresConfig pointing at it, unmigrated, for exercising the real
// sqlstore.Connect/db.New code path. The container terminates when the test ends.
func PostgresConfig(t *testing.T) *sqlstore.PostgresConfig {
	t.Helper()
	host, portNum := containerHostPort(t, runPostgres(t), "5432/tcp", "postgres")
	return &sqlstore.PostgresConfig{
		Host:         host,
		Port:         portNum,
		User:         "postgres",
		Password:     "postgres",
		Database:     "postgres",
		SSLMode:      "disable",
		MaxOpenConns: 5,
		MaxIdleConns: 2,
	}
}

// MariaDBConfig starts a container as runMariaDB does and returns a
// *sqlstore.MariaDBConfig pointing at it, unmigrated, for exercising the real
// sqlstore.Connect/db.New code path. The container terminates when the test ends.
func MariaDBConfig(t *testing.T) *sqlstore.MariaDBConfig {
	t.Helper()
	return mariaDBConfig(t, runMariaDB(t))
}

// mariaDBConfig returns the *sqlstore.MariaDBConfig for ctr's module defaults.
func mariaDBConfig(t *testing.T, ctr *mariadb.MariaDBContainer) *sqlstore.MariaDBConfig {
	t.Helper()
	host, portNum := containerHostPort(t, ctr, "3306/tcp", "mariadb")
	return &sqlstore.MariaDBConfig{
		Host:         host,
		Port:         portNum,
		User:         "test",
		Password:     "test",
		Database:     "test",
		MaxOpenConns: 5,
		MaxIdleConns: 2,
	}
}
