package sqlstore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jmoiron/sqlx"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// Postgres migrations use a ".pgsql" extension rather than plain ".sql":
// SonarCloud's PL/SQL (Oracle) analyzer otherwise claims any ".sql" file by
// default and flags this Postgres DDL for not using VARCHAR2, an Oracle-only
// type that doesn't exist in PostgreSQL. golang-migrate's source parser
// treats the file extension as an opaque placeholder (see its Regex "ext"
// in source/parse.go), so this has no functional effect.
//
//go:embed migrations/postgres/*.pgsql
var postgresMigrations embed.FS

//go:embed migrations/mariadb/*.sql
var mariadbMigrations embed.FS

// ApplySchema runs any pending schema migrations for the given dialect against
// db. Safe to call on every service startup: golang-migrate tracks applied
// versions in a schema_migrations table in the target database and is a
// no-op once the schema is already current, mirroring how Mongo index
// creation already happens idempotently at startup.
func ApplySchema(db *sqlx.DB, dialect Dialect) error {
	ctx := context.Background()

	// A single connection dedicated to running migrations, distinct from
	// db's own pool. This matters because golang-migrate's database driver
	// closes whatever it was constructed from when the migrate instance is
	// torn down: WithInstance(db.DB, ...) would make it close db itself (the
	// shared pool every other query in the service also uses), while
	// WithConnection(conn, ...) only closes this one borrowed connection —
	// which is what lets ApplySchema run repeatedly against a long-lived
	// shared pool (once per service startup) without ever closing db out
	// from under the rest of the service, and without leaking a connection
	// either.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlstore: acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	var (
		migrationsFS embed.FS
		subdir       string
		newDBDriver  func() (database.Driver, error)
	)

	switch dialect.Name() {
	case "postgres":
		migrationsFS, subdir = postgresMigrations, "migrations/postgres"
		newDBDriver = func() (database.Driver, error) {
			return postgres.WithConnection(ctx, conn, &postgres.Config{})
		}
	case "mariadb":
		migrationsFS, subdir = mariadbMigrations, "migrations/mariadb"
		newDBDriver = func() (database.Driver, error) {
			// Note: each migration file contains more than one SQL statement
			// (e.g. a CREATE TABLE followed by CREATE INDEX statements) --
			// this requires the underlying connection's DSN to have been
			// opened with multiStatements=true (see MariaDBConfig.DSN),
			// which the go-sql-driver/mysql driver needs to execute more
			// than one statement per Exec call.
			return mysql.WithConnection(ctx, conn, &mysql.Config{})
		}
	default:
		return fmt.Errorf("sqlstore: no migrations for dialect %q", dialect.Name())
	}

	sub, err := fs.Sub(migrationsFS, subdir)
	if err != nil {
		return fmt.Errorf("sqlstore: load embedded migrations: %w", err)
	}
	src, err := iofs.New(sub, ".")
	if err != nil {
		return fmt.Errorf("sqlstore: init migration source: %w", err)
	}

	dbDriver, err := newDBDriver()
	if err != nil {
		return fmt.Errorf("sqlstore: init migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, dialect.Name(), dbDriver)
	if err != nil {
		return fmt.Errorf("sqlstore: init migrate: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("sqlstore: run migrations: %w", err)
	}
	return nil
}
