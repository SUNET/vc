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
	}

	for _, svc := range []string{"apigw", "verifier"} {
		t.Run(svc+" on a relational backend with HA", func(t *testing.T) {
			err := checkMongoRequirement(commonWith("", "postgres", true), svc)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ha.enable")
		})
	}
}

// TestCheckMongoRequirement_RegistryIsNotBackendGated pins the difference
// between registry and its neighbours: internal/registry/db calls
// connectMongo unconditionally and has no sqlstore path, so backend gating
// would let it validate with a relational backend and no URI, then fail when
// it dialled.
func TestCheckMongoRequirement_RegistryIsNotBackendGated(t *testing.T) {
	for _, backend := range []string{"postgres", "mariadb"} {
		t.Run("backend="+backend, func(t *testing.T) {
			err := checkMongoRequirement(commonWith("", backend, false), "registry")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "regardless of common.sql.backend")

			// apigw and verifier genuinely can run on that backend.
			for _, svc := range []string{"apigw", "verifier"} {
				assert.NoError(t, checkMongoRequirement(commonWith("", backend, false), svc), svc)
			}
		})
	}
}

// TestCheckMongoRequirement_NilCommon covers a config with no common block:
// Cfg.Common carries no "required" tag, so it reaches this check. For a
// service that needs Mongo, letting it through only moves the failure to the
// first dereference.
func TestCheckMongoRequirement_NilCommon(t *testing.T) {
	for _, svc := range []string{"apigw", "registry", "verifier"} {
		t.Run(svc+" is rejected", func(t *testing.T) {
			err := checkMongoRequirement(&model.Cfg{}, svc)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "common is required")
		})
	}

	t.Run("issuer is unaffected", func(t *testing.T) {
		require.NoError(t, checkMongoRequirement(&model.Cfg{}, "issuer"))
	})
}

func TestCheckMongoRequirement_Satisfied(t *testing.T) {
	t.Run("a relational deployment needs no Mongo", func(t *testing.T) {
		require.NoError(t, checkMongoRequirement(commonWith("", "postgres", false), "apigw"))
	})

	t.Run("a URI satisfies every combination", func(t *testing.T) {
		require.NoError(t, checkMongoRequirement(commonWith("mongodb://db", "", true), "apigw"))
	})

}
