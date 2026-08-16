package sqlstore

import (
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

// Migrate runs any pending schema migrations for the given dialect against
// db. Safe to call on every service startup: golang-migrate tracks applied
// versions in a schema_migrations table in the target database and is a
// no-op once the schema is already current, mirroring how Mongo index
// creation already happens idempotently at startup.
func Migrate(db *sqlx.DB, dialect Dialect) error {
	var (
		migrationsFS embed.FS
		subdir       string
		newDBDriver  func() (database.Driver, error)
	)

	switch dialect.Name() {
	case "postgres":
		migrationsFS, subdir = postgresMigrations, "migrations/postgres"
		newDBDriver = func() (database.Driver, error) {
			return postgres.WithInstance(db.DB, &postgres.Config{})
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
			return mysql.WithInstance(db.DB, &mysql.Config{})
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

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("sqlstore: run migrations: %w", err)
	}
	return nil
}
