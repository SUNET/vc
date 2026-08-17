// Package sqltest provides shared Postgres/MariaDB testcontainer helpers,
// pre-migrated and ready to use, for repository-level SQL store tests.
//
// It lives in its own leaf package, separate from pkg/testsupport itself,
// for the same reason as pkg/testsupport/tracertest: pkg/sqlstore depends
// on pkg/model, which in turn depends on packages (e.g. pkg/mdoc) that
// import pkg/cache, and pkg/cache's own tests already import
// pkg/testsupport. Adding a pkg/sqlstore dependency to pkg/testsupport
// itself would create an import cycle; keeping it here, imported only by
// packages that don't sit on that cycle, avoids the problem.
package sqltest

import (
	"strconv"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"

	"github.com/jmoiron/sqlx"
	"github.com/testcontainers/testcontainers-go/modules/mariadb"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// StartPostgres spins up a throwaway, fully-migrated Postgres container and
// returns a connected *sqlx.DB, its Dialect, and a cleanup function. Skips
// the calling test if Docker is not available.
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
		_ = ctr.Terminate(ctx)
		t.Fatalf("postgres connection string: %v", err)
	}

	db, err := sqlx.Open(sqlstore.PostgresDialect.DriverName(), connStr)
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("open postgres: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_ = ctr.Terminate(ctx)
		t.Fatalf("ping postgres: %v", err)
	}

	if err := sqlstore.ApplySchema(db, sqlstore.PostgresDialect); err != nil {
		_ = db.Close()
		_ = ctr.Terminate(ctx)
		t.Fatalf("migrate postgres: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = ctr.Terminate(ctx)
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

	connStr, err := ctr.ConnectionString(ctx, "multiStatements=true", "parseTime=true")
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("mariadb connection string: %v", err)
	}

	db, err := sqlx.Open(sqlstore.MariaDBDialect.DriverName(), connStr)
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("open mariadb: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_ = ctr.Terminate(ctx)
		t.Fatalf("ping mariadb: %v", err)
	}

	if err := sqlstore.ApplySchema(db, sqlstore.MariaDBDialect); err != nil {
		_ = db.Close()
		_ = ctr.Terminate(ctx)
		t.Fatalf("migrate mariadb: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = ctr.Terminate(ctx)
	}
	return db, sqlstore.MariaDBDialect, cleanup
}

// PostgresConfig spins up a throwaway, unmigrated Postgres container and
// returns a *model.PostgresConfig pointing at it (for exercising the real
// sqlstore.Connect/db.New code path, as opposed to StartPostgres's
// already-opened *sqlx.DB) and a cleanup function.
func PostgresConfig(t *testing.T) (*model.PostgresConfig, func()) {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := postgres.Run(ctx, "postgres:16", postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("postgres host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("postgres mapped port: %v", err)
	}
	portNum, err := strconv.Atoi(port.Port())
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("postgres port: %v", err)
	}

	cfg := &model.PostgresConfig{
		Host:         host,
		Port:         portNum,
		User:         "postgres",
		Password:     "postgres",
		Database:     "postgres",
		SSLMode:      "disable",
		MaxOpenConns: 5,
		MaxIdleConns: 2,
	}
	return cfg, func() { _ = ctr.Terminate(ctx) }
}

// MariaDBConfig spins up a throwaway, unmigrated MariaDB container and
// returns a *model.MariaDBConfig pointing at it (for exercising the real
// sqlstore.Connect/db.New code path, as opposed to StartMariaDB's
// already-opened *sqlx.DB) and a cleanup function.
func MariaDBConfig(t *testing.T) (*model.MariaDBConfig, func()) {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := mariadb.Run(ctx, "mariadb:11")
	if err != nil {
		t.Fatalf("start mariadb container: %v", err)
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("mariadb host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "3306/tcp")
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("mariadb mapped port: %v", err)
	}
	portNum, err := strconv.Atoi(port.Port())
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("mariadb port: %v", err)
	}

	cfg := &model.MariaDBConfig{
		Host:         host,
		Port:         portNum,
		User:         "test",
		Password:     "test",
		Database:     "test",
		MaxOpenConns: 5,
		MaxIdleConns: 2,
	}
	return cfg, func() { _ = ctr.Terminate(ctx) }
}
