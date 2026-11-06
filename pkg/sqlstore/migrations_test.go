package sqlstore_test

import (
	"testing"

	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/require"
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
	db := sqltest.OpenPostgres(t)
	ctx := t.Context()

	require.NoError(t, sqlstore.ApplySchema(ctx, db, sqlstore.PostgresDialect, nil))
	// Running again must be a no-op (ErrNoChange handled internally), not an error.
	require.NoError(t, sqlstore.ApplySchema(ctx, db, sqlstore.PostgresDialect, nil))

	for _, table := range allTables {
		_, err := db.ExecContext(ctx, "SELECT 1 FROM "+table+" LIMIT 0")
		require.NoErrorf(t, err, "table %q should exist after migration", table)
	}
}

func TestApplySchema_MariaDB(t *testing.T) {
	db, cfg := sqltest.OpenMariaDB(t)
	ctx := t.Context()

	require.NoError(t, sqlstore.ApplySchema(ctx, db, sqlstore.MariaDBDialect, cfg))
	require.NoError(t, sqlstore.ApplySchema(ctx, db, sqlstore.MariaDBDialect, cfg))

	for _, table := range allTables {
		_, err := db.ExecContext(ctx, "SELECT 1 FROM "+table+" LIMIT 0")
		require.NoErrorf(t, err, "table %q should exist after migration", table)
	}
}
