package sqlstore_test

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/mariadb"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestJSONTextExtract_KeyWithQuotes_Postgres is a regression test for a
// Copilot review finding on #571: JSONTextExtract interpolated key directly
// into the SQL string literal ("...->>'%s'"), which produced invalid SQL
// for a key containing a single quote (every caller today passes a
// hardcoded key, so this was never exploitable in practice, but it was a
// real robustness/defense-in-depth gap). Verifies the escaped key still
// round-trips correctly against a real Postgres instance, not just that the
// generated SQL text looks right.
func TestJSONTextExtract_KeyWithQuotes_Postgres(t *testing.T) {
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

	_, err = db.ExecContext(ctx, "CREATE TABLE t (data JSONB NOT NULL)")
	require.NoError(t, err)

	const key = `o'brien`
	docBytes, err := json.Marshal(map[string]string{key: "expected-value"})
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO t (data) VALUES ($1)", string(docBytes))
	require.NoError(t, err)

	expr := sqlstore.PostgresDialect.JSONTextExtract("data", key)
	var got string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT "+expr+" FROM t").Scan(&got))
	require.Equal(t, "expected-value", got)
}

// TestJSONTextExtract_KeyWithQuotes_MariaDB is the MariaDB analogue of the
// Postgres test above -- same regression, same fix (escapeMariaDBJSONPathKey).
func TestJSONTextExtract_KeyWithQuotes_MariaDB(t *testing.T) {
	if !testsupport.IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := mariadb.Run(ctx, "mariadb:11")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	connStr, err := ctr.ConnectionString(ctx)
	require.NoError(t, err)

	db, err := sqlx.Open(sqlstore.MariaDBDialect.DriverName(), connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.PingContext(ctx))

	_, err = db.ExecContext(ctx, "CREATE TABLE t (data JSON NOT NULL)")
	require.NoError(t, err)

	// MariaDB JSON path keys with a double quote are the interesting case
	// (the key gets embedded in a double-quoted path segment); include a
	// single quote too, since the whole path also sits inside a SQL string
	// literal.
	const key = `o'br"ien`
	docBytes, err := json.Marshal(map[string]string{key: "expected-value"})
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO t (data) VALUES (?)", string(docBytes))
	require.NoError(t, err)

	expr := sqlstore.MariaDBDialect.JSONTextExtract("data", key)
	var got string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT "+expr+" FROM t").Scan(&got))
	require.Equal(t, "expected-value", got)
}
