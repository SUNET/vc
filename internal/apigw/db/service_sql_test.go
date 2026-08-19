package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/sqltest"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"

	"github.com/stretchr/testify/require"
)

// testNewSQLService exercises the real New()/newSQL() code path end to end
// (config -> sqlstore.Connect -> sqlstore.Migrate -> store wiring), as
// opposed to the individual sql_*_test.go files, which construct each SQL
// store directly against an already-migrated database.
func testNewSQLService(t *testing.T, cfg *model.Cfg) *Service {
	t.Helper()
	log := testsupport.TestLogger(t)
	tracer := tracertest.New(t, cfg, log, "apigw-db-sql-service-test")

	svc, err := New(t.Context(), cfg, tracer, log)
	require.NoError(t, err)
	require.NotNil(t, svc)
	t.Cleanup(func() { _ = svc.Close(t.Context()) })
	return svc
}

func testNewServiceContract(t *testing.T, svc *Service) {
	t.Helper()
	ctx := t.Context()

	require.NotNil(t, svc.DatastoreColl)
	require.NotNil(t, svc.IdentityMappingsColl)
	require.NotNil(t, svc.CredentialOfferColl)
	require.NotNil(t, svc.DynamicRegistrationColl)

	// A minimal round-trip through one store confirms migrations actually
	// ran and the wired stores work against a real connection.
	require.NoError(t, svc.CredentialOfferColl.Save(ctx, &CredentialOfferDocument{
		UUID: "svc-test-offer",
		CredentialOfferParameters: openid4vci.CredentialOfferParameters{
			CredentialIssuer: "https://issuer.example.com",
		},
	}))
	got, err := svc.CredentialOfferColl.Get(ctx, "svc-test-offer")
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com", got.CredentialOfferParameters.CredentialIssuer)

	probe := svc.Status(ctx)
	require.True(t, probe.Healthy)
}

func TestNewService_Postgres(t *testing.T) {
	pgCfg, cleanup := sqltest.PostgresConfig(t)
	defer cleanup()

	cfg := &model.Cfg{Common: &model.Common{SQL: sqlstore.SQL{Backend: "postgres", Postgres: pgCfg}}}
	svc := testNewSQLService(t, cfg)
	testNewServiceContract(t, svc)
}

func TestNewService_MariaDB(t *testing.T) {
	mdbCfg, cleanup := sqltest.MariaDBConfig(t)
	defer cleanup()

	cfg := &model.Cfg{Common: &model.Common{SQL: sqlstore.SQL{Backend: "mariadb", MariaDB: mdbCfg}}}
	svc := testNewSQLService(t, cfg)
	testNewServiceContract(t, svc)
}
