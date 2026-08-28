package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func commonWith(uri, backend string, ha bool) *model.Cfg {
	c := &model.Common{}
	c.Mongo.URI = uri
	c.SQL = sqlstore.SQL{Backend: backend}
	c.HA.Enable = ha
	return &model.Cfg{Common: c}
}

// TestCheckMongoRequirement_IssuerNeedsNoMongo is issue #622: the issuer
// opens no store, so it must start without common.mongo.uri.
func TestCheckMongoRequirement_IssuerNeedsNoMongo(t *testing.T) {
	for _, backend := range []string{"", "mongo", "postgres"} {
		t.Run("backend="+backend, func(t *testing.T) {
			require.NoError(t, checkMongoRequirement(commonWith("", backend, false), "issuer"))
		})
	}

	t.Run("even with HA enabled", func(t *testing.T) {
		require.NoError(t, checkMongoRequirement(commonWith("", "", true), "issuer"))
	})
}

// TestCheckMongoRequirement_StoreServicesStillRequireIt guards the other
// direction: the fix must not stop apigw, registry or verifier from failing
// fast when they genuinely need a URI they have not been given.
func TestCheckMongoRequirement_StoreServicesStillRequireIt(t *testing.T) {
	for _, svc := range []string{"apigw", "registry", "verifier"} {
		t.Run(svc+" with the default backend", func(t *testing.T) {
			err := checkMongoRequirement(commonWith("", "", false), svc)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "common.mongo.uri is required")
			assert.Contains(t, err.Error(), svc)
		})

		t.Run(svc+" on a relational backend with HA", func(t *testing.T) {
			err := checkMongoRequirement(commonWith("", "postgres", true), svc)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ha.enable")
		})
	}
}

func TestCheckMongoRequirement_Satisfied(t *testing.T) {
	t.Run("a relational deployment needs no Mongo", func(t *testing.T) {
		require.NoError(t, checkMongoRequirement(commonWith("", "postgres", false), "apigw"))
	})

	t.Run("a URI satisfies every combination", func(t *testing.T) {
		require.NoError(t, checkMongoRequirement(commonWith("mongodb://db", "", true), "apigw"))
	})

	t.Run("no common block at all", func(t *testing.T) {
		require.NoError(t, checkMongoRequirement(&model.Cfg{}, "apigw"))
	})
}
