package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/require"
)

// TestNewService exercises the real New()/newSQL() code path end to end
// (config -> sqlstore.Connect -> sqlstore.ApplySchema -> store wiring)
// against both Postgres and MariaDB, as opposed to the individual
// sql_*_test.go files, which construct each SQL store directly against an
// already-migrated database.
func TestNewService(t *testing.T) {
	sqltest.RunPostgresAndMariaDBContract(t, "apigw-db-sql-service-test", New, func(t *testing.T, svc *Service) {
		ctx := t.Context()

		require.NotNil(t, svc.DatastoreColl)
		require.NotNil(t, svc.IdentityMappingsColl)
		require.NotNil(t, svc.CredentialOfferColl)
		require.NotNil(t, svc.DynamicRegistrationColl)

		// A minimal round-trip through one store confirms migrations
		// actually ran and the wired stores work against a real connection.
		require.NoError(t, svc.CredentialOfferColl.Save(ctx, &CredentialOfferDocument{
			UUID: "svc-test-offer",
			CredentialOfferParameters: openid4vci.CredentialOfferParameters{
				CredentialIssuer: "https://issuer.example.com",
			},
		}))
		got, err := svc.CredentialOfferColl.Get(ctx, "svc-test-offer")
		require.NoError(t, err)
		require.Equal(t, "https://issuer.example.com", got.CredentialOfferParameters.CredentialIssuer)

		probe := svc.HealthProbe(ctx)
		require.NoError(t, probe)
	})
}
