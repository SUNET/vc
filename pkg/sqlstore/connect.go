package sqlstore

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/pkg/model"

	"github.com/jmoiron/sqlx"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" database/sql driver
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// Connect opens a connection pool for the backend selected by cfg.Backend
// and returns it alongside the matching Dialect. Pings the database before
// returning so connection/auth failures surface at startup rather than on
// first query.
func Connect(ctx context.Context, cfg *model.SQL) (*sqlx.DB, Dialect, error) {
	switch cfg.Backend {
	case "postgres":
		if cfg.Postgres == nil {
			return nil, nil, fmt.Errorf("sqlstore: backend is postgres but Common.SQL.Postgres is not configured")
		}
		db, err := sqlx.Open(PostgresDialect.DriverName(), cfg.Postgres.DSN())
		if err != nil {
			return nil, nil, fmt.Errorf("sqlstore: open postgres: %w", err)
		}
		db.SetMaxOpenConns(cfg.Postgres.MaxOpenConns)
		db.SetMaxIdleConns(cfg.Postgres.MaxIdleConns)
		if err := db.PingContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("sqlstore: ping postgres: %w", err)
		}
		return db, PostgresDialect, nil

	case "mariadb":
		if cfg.MariaDB == nil {
			return nil, nil, fmt.Errorf("sqlstore: backend is mariadb but Common.SQL.MariaDB is not configured")
		}
		dsn, err := cfg.MariaDB.DSN()
		if err != nil {
			return nil, nil, fmt.Errorf("sqlstore: build mariadb dsn: %w", err)
		}
		db, err := sqlx.Open(MariaDBDialect.DriverName(), dsn)
		if err != nil {
			return nil, nil, fmt.Errorf("sqlstore: open mariadb: %w", err)
		}
		db.SetMaxOpenConns(cfg.MariaDB.MaxOpenConns)
		db.SetMaxIdleConns(cfg.MariaDB.MaxIdleConns)
		if err := db.PingContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("sqlstore: ping mariadb: %w", err)
		}
		return db, MariaDBDialect, nil

	default:
		return nil, nil, fmt.Errorf("sqlstore: unsupported backend %q (expected \"postgres\" or \"mariadb\")", cfg.Backend)
	}
}
