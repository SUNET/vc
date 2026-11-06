package sqlstore_test

import (
	"strconv"
	"testing"

	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/mariadb"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" database/sql driver
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// allTables lists every table created by the migrations, used to assert
// the schema landed as expected after ApplySchema runs.
var allTables = []string{
	"datastore",
	"datastore_identity_mapping",
	"identity_mappings",
	"credential_offer",
	"oidc_dynamic_registration",
	"clients",
	"token_status_list",
	"token_status_list_metadata",
	"credential_subjects",
	"cache_entries",
}

func TestApplySchema_Postgres(t *testing.T) {
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := postgres.Run(ctx, "postgres:16", postgres.BasicWaitStrategies())
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sqlx.Open(sqlstore.PostgresDialect.DriverName(), connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.PingContext(ctx))

	require.NoError(t, sqlstore.ApplySchema(ctx, db, sqlstore.PostgresDialect, nil))
	// Running again must be a no-op (ErrNoChange handled internally), not an error.
	require.NoError(t, sqlstore.ApplySchema(ctx, db, sqlstore.PostgresDialect, nil))

	for _, table := range allTables {
		_, err := db.ExecContext(ctx, "SELECT 1 FROM "+table+" LIMIT 0")
		require.NoErrorf(t, err, "table %q should exist after migration", table)
	}
}

func TestApplySchema_MariaDB(t *testing.T) {
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := mariadb.Run(ctx, "mariadb:11")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	// Deliberately NOT multiStatements=true here: ApplySchema now opens its
	// own dedicated migration connection with that enabled (see
	// MariaDBConfig.MigrationDSN) rather than needing it on the
	// application's own pool.
	connStr, err := ctr.ConnectionString(ctx, "parseTime=true")
	require.NoError(t, err)

	db, err := sqlx.Open(sqlstore.MariaDBDialect.DriverName(), connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.PingContext(ctx))

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	port, err := ctr.MappedPort(ctx, "3306/tcp")
	require.NoError(t, err)
	portNum, err := strconv.Atoi(port.Port())
	require.NoError(t, err)
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

	require.NoError(t, sqlstore.ApplySchema(ctx, db, sqlstore.MariaDBDialect, cfg))
	require.NoError(t, sqlstore.ApplySchema(ctx, db, sqlstore.MariaDBDialect, cfg))

	for _, table := range allTables {
		_, err := db.ExecContext(ctx, "SELECT 1 FROM "+table+" LIMIT 0")
		require.NoErrorf(t, err, "table %q should exist after migration", table)
	}

	requireExactStringColumns(t, db)
}

// requireExactStringColumns requires the NO PAD binary collation on every
// string column of every table except the migration tool's own. A column off it
// compares under another rule than Postgres, MongoDB and the SPOCP engine, so a
// variant spelling of an identifier can reach another subject's row. A migration
// adding a table must name the collation.
func requireExactStringColumns(t *testing.T, db *sqlx.DB) {
	t.Helper()
	var columns []struct {
		Table     string `db:"TABLE_NAME"`
		Column    string `db:"COLUMN_NAME"`
		Collation string `db:"COLLATION_NAME"`
	}
	require.NoError(t, db.SelectContext(t.Context(), &columns,
		`SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME FROM information_schema.COLUMNS
		 WHERE TABLE_SCHEMA = DATABASE() AND COLLATION_NAME IS NOT NULL AND TABLE_NAME <> 'schema_migrations'`))
	require.NotEmpty(t, columns, "the schema has string columns")
	for _, c := range columns {
		assert.Equalf(t, "utf8mb4_nopad_bin", c.Collation, "collation of %s.%s", c.Table, c.Column)
	}
}
