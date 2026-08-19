package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/require"
)

// testNewServiceContract exercises the real New()/newSQL() code path end to
// end (config -> sqlstore.Connect -> sqlstore.ApplySchema -> store wiring).
func testNewServiceContract(t *testing.T, svc *Service) {
	t.Helper()
	ctx := t.Context()

	require.NotNil(t, svc.Clients)

	require.NoError(t, svc.Clients.Create(ctx, &Client{
		ClientID:                "svc-test-client",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		AllowedScopes:           []string{"openid"},
		SubjectType:             "public",
	}))
	got, err := svc.Clients.GetByClientID(ctx, "svc-test-client")
	require.NoError(t, err)
	require.NotNil(t, got)

	probe := svc.Status(ctx)
	require.True(t, probe.Healthy)
}

func TestNewService_Postgres(t *testing.T) {
	pgCfg, cleanup := sqltest.PostgresConfig(t)
	defer cleanup()

	cfg := &model.Cfg{Common: &model.Common{SQL: sqlstore.SQL{Backend: "postgres", Postgres: pgCfg}}}
	testNewServiceContract(t, sqltest.NewServiceForTest(t, "verifier-db-sql-service-test", cfg, New))
}

func TestNewService_MariaDB(t *testing.T) {
	mdbCfg, cleanup := sqltest.MariaDBConfig(t)
	defer cleanup()

	cfg := &model.Cfg{Common: &model.Common{SQL: sqlstore.SQL{Backend: "mariadb", MariaDB: mdbCfg}}}
	testNewServiceContract(t, sqltest.NewServiceForTest(t, "verifier-db-sql-service-test", cfg, New))
}
