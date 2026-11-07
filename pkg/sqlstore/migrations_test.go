package sqlstore_test

import (
	"fmt"
	"io/fs"
	"strconv"
	"testing"

	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
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
	requirePopulatedDatabaseSurvivesExactIdentifiers(t, db, cfg.MariaDB)
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

// requirePopulatedDatabaseSurvivesExactIdentifiers runs the exact identifiers
// migration in both directions on rows, on a database whose default character
// set is latin1. Up must give each child row its parent's spelling, or adding
// the foreign key back refuses the row and the service does not start. Down must
// keep JSON characters latin1 lacks and restore the schema that migrations up to
// the previous version create on this database.
func requirePopulatedDatabaseSurvivesExactIdentifiers(t *testing.T, db *sqlx.DB, cfg *sqlstore.MariaDBConfig) {
	t.Helper()
	ctx := t.Context()

	_, err := db.ExecContext(ctx, "ALTER DATABASE test CHARACTER SET latin1 COLLATE latin1_swedish_ci")
	require.NoError(t, err)

	m, version, previous := newExactIdentifiersMigrator(t, cfg)
	require.NoError(t, m.Down())
	require.NoError(t, m.Migrate(previous))
	schema := showCreateTables(t, db)

	const document = `{"name":"张伟😀"}`
	jsonColumns := seedJSONColumns(t, db, document)

	seedParent := func() {
		mustExec(t, db, `INSERT INTO datastore (authentic_source, scope, document_id, document_data) VALUES ('Alpha', 'Pid', 'Doc', ?)`, document)
	}
	seedParent()
	for spelling, identity := range map[string]string{"Alpha": "exact", "alpha": "case", "Álpha": "accent", "Alpha ": "space"} {
		mustExec(t, db, `INSERT INTO datastore_identity_mapping VALUES (?, 'Pid', 'Doc', ?)`, spelling, identity)
	}

	require.NoError(t, m.Migrate(version))

	var sources []string
	require.NoError(t, db.SelectContext(ctx, &sources, `SELECT authentic_source FROM datastore_identity_mapping`))
	assert.Equal(t, []string{"Alpha", "Alpha", "Alpha", "Alpha"}, sources)

	mustExec(t, db, `DELETE FROM datastore WHERE authentic_source = 'Alpha'`)
	var children int
	require.NoError(t, db.GetContext(ctx, &children, `SELECT COUNT(*) FROM datastore_identity_mapping`))
	assert.Zero(t, children, "deleting the parent cascades to every child")

	seedParent()
	require.NoError(t, m.Migrate(previous))

	for _, c := range jsonColumns {
		var stored []byte
		require.NoError(t, db.GetContext(ctx, &stored, fmt.Sprintf(`SELECT UNHEX(HEX(%s)) FROM %s LIMIT 1`, c.Column, c.Table)))
		assert.Equalf(t, document, string(stored), "%s.%s after down", c.Table, c.Column)
	}
	assert.Equal(t, schema, showCreateTables(t, db), "SHOW CREATE TABLE after down")
}

// newExactIdentifiersMigrator returns a migrator on its own multi-statement
// connection, as ApplySchema has, with the version of the exact identifiers
// migration and the version before it.
func newExactIdentifiersMigrator(t *testing.T, cfg *sqlstore.MariaDBConfig) (*migrate.Migrate, uint, uint) {
	t.Helper()
	ctx := t.Context()

	dsn, err := cfg.MigrationDSN()
	require.NoError(t, err)
	pool, err := sqlx.Open(sqlstore.MariaDBDialect.DriverName(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })
	conn, err := pool.Conn(ctx)
	require.NoError(t, err)
	driver, err := mysql.WithConnection(ctx, conn, &mysql.Config{})
	require.NoError(t, err)

	migrations, err := fs.Sub(sqlstore.MariaDBMigrations, "migrations/mariadb")
	require.NoError(t, err)
	names, err := fs.Glob(migrations, "*_exact_identifiers.up.sql")
	require.NoError(t, err)
	require.Len(t, names, 1)
	parsed, err := source.Parse(names[0])
	require.NoError(t, err)
	files, err := iofs.New(migrations, ".")
	require.NoError(t, err)
	previous, err := files.Prev(parsed.Version)
	require.NoError(t, err)

	m, err := migrate.NewWithInstance("iofs", files, sqlstore.MariaDBDialect.Name(), driver)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = m.Close()
	})
	return m, parsed.Version, previous
}

type jsonColumn struct {
	Table  string `db:"TABLE_NAME"`
	Column string `db:"COLUMN_NAME"`
}

// seedJSONColumns stores document in every JSON column of the schema, which MariaDB
// reports as utf8mb4_bin on a latin1 database, and returns those columns.
func seedJSONColumns(t *testing.T, db *sqlx.DB, document string) []jsonColumn {
	t.Helper()
	for _, insert := range []string{
		`INSERT INTO identity_mappings (authentic_source, authentic_source_person_id, attributes) VALUES ('a', 'p', '{}')`,
		`INSERT INTO credential_offer VALUES ('u', '{}')`,
		`INSERT INTO clients (client_id, redirect_uris, grant_types, response_types, token_endpoint_auth_method, allowed_scopes, subject_type)
		 VALUES ('c', '[]', '[]', '[]', 'm', '[]', 'public')`,
		`INSERT INTO token_status_list_metadata VALUES (1, 1, '[]')`,
		`INSERT INTO cache_entries VALUES ('n', 'k', '{}', '2031-01-01 00:00:00')`,
		`INSERT INTO datastore (authentic_source, scope, document_id, document_data) VALUES ('s', 'p', 'd', '{}')`,
	} {
		mustExec(t, db, insert)
	}
	var columns []jsonColumn
	require.NoError(t, db.SelectContext(t.Context(), &columns,
		`SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS
		 WHERE TABLE_SCHEMA = DATABASE() AND COLLATION_NAME = 'utf8mb4_bin'`))
	require.NotEmpty(t, columns, "the schema has JSON columns")
	for _, c := range columns {
		result, err := db.ExecContext(t.Context(), fmt.Sprintf(`UPDATE %s SET %s = ?`, c.Table, c.Column), document)
		require.NoError(t, err)
		rows, err := result.RowsAffected()
		require.NoError(t, err)
		require.NotZerof(t, rows, "%s.%s has no seeded row", c.Table, c.Column)
	}
	return columns
}

func mustExec(t *testing.T, db *sqlx.DB, query string, args ...any) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), query, args...)
	require.NoError(t, err, query)
}

func showCreateTables(t *testing.T, db *sqlx.DB) map[string]string {
	t.Helper()
	schema := make(map[string]string, len(allTables))
	for _, table := range allTables {
		var name, statement string
		require.NoError(t, db.QueryRowContext(t.Context(), "SHOW CREATE TABLE "+table).Scan(&name, &statement))
		schema[table] = statement
	}
	return schema
}
