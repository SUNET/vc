package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/sqltest"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestService builds a *Service suitable for exercising SQL-backed store
// implementations directly (bypassing New(), which would try to connect to
// MongoDB): only the fields the sql_*.go implementations actually use
// (tracer, log) are populated.
func newTestService(t *testing.T) *Service {
	t.Helper()
	log := testsupport.TestLogger(t)
	tracer := tracertest.New(t, nil, log, "apigw-db-test")
	return &Service{tracer: tracer, log: log}
}

func testCredentialOfferStoreContract(t *testing.T, store CredentialOfferStore) {
	t.Helper()
	ctx := t.Context()

	doc := &CredentialOfferDocument{
		UUID: "offer-1",
		CredentialOfferParameters: openid4vci.CredentialOfferParameters{
			CredentialIssuer:           "https://issuer.example.com",
			CredentialConfigurationIDs: []string{"pid"},
			Grants: map[string]any{
				openid4vci.GrantTypePreAuthorizedCode: map[string]any{"pre-authorized_code": "abc123"},
			},
		},
	}
	require.NoError(t, store.Save(ctx, doc))

	got, err := store.Get(ctx, "offer-1")
	require.NoError(t, err)
	assert.Equal(t, "offer-1", got.UUID)
	assert.Equal(t, "https://issuer.example.com", got.CredentialOfferParameters.CredentialIssuer)
	assert.Equal(t, []string{"pid"}, got.CredentialOfferParameters.CredentialConfigurationIDs)
	assert.NotNil(t, got.CredentialOfferParameters.Grants[openid4vci.GrantTypePreAuthorizedCode])

	require.NoError(t, store.Delete(ctx, "offer-1"))

	_, err = store.Get(ctx, "offer-1")
	assert.Error(t, err, "expected an error looking up a deleted offer")
}

func TestSQLCredentialOfferColl_Postgres(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartPostgres(t)
	defer cleanup()

	testCredentialOfferStoreContract(t, NewSQLCredentialOfferColl(newTestService(t), sqlDB, dialect))
}

func TestSQLCredentialOfferColl_MariaDB(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartMariaDB(t)
	defer cleanup()

	testCredentialOfferStoreContract(t, NewSQLCredentialOfferColl(newTestService(t), sqlDB, dialect))
}
