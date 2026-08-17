package sqlstore_test

import (
	"testing"

	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"

	"github.com/jmoiron/sqlx"
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

	require.NoError(t, sqlstore.ApplySchema(db, sqlstore.PostgresDialect))
	// Running again must be a no-op (ErrNoChange handled internally), not an error.
	require.NoError(t, sqlstore.ApplySchema(db, sqlstore.PostgresDialect))

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

	connStr, err := ctr.ConnectionString(ctx, "multiStatements=true")
	require.NoError(t, err)

	db, err := sqlx.Open(sqlstore.MariaDBDialect.DriverName(), connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.PingContext(ctx))

	require.NoError(t, sqlstore.ApplySchema(db, sqlstore.MariaDBDialect))
	require.NoError(t, sqlstore.ApplySchema(db, sqlstore.MariaDBDialect))

	for _, table := range allTables {
		_, err := db.ExecContext(ctx, "SELECT 1 FROM "+table+" LIMIT 0")
		require.NoErrorf(t, err, "table %q should exist after migration", table)
	}
}
