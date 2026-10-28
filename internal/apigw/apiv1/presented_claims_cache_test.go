package apiv1

import (
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Verified claims cross the cache between the presentation and the
// credential request, and under HA that cache is Mongo. The memory store
// returns values as given, so these tests round-trip claims through BSON.
// SUNET/vc#865.

// bsonRoundTrip is what a Mongo-backed AuthContext.Update followed by the
// access-token lookup does to a claims map.
func bsonRoundTrip(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	raw, err := bson.Marshal(in)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, bson.Unmarshal(raw, &out))
	return out
}

// The shapes fxamacker/cbor decodes mdoc element values into, and the two
// Go types that reach the claims map from elsewhere.
func presentedShapes() map[string]any {
	return map[string]any{
		"full_date": cbor.Tag{Number: 1004, Content: "1990-01-15"},
		"tdate":     cbor.Tag{Number: 0, Content: "1990-01-15T00:00:00Z"},
		"epoch":     cbor.Tag{Number: 1, Content: int64(632361600)},
		"timestamp": time.Date(1990, 1, 15, 12, 0, 0, 0, time.UTC),
		"portrait":  []byte{0xca, 0xfe},
		"plain":     "SE",
		"nested":    map[string]any{"birth_date": cbor.Tag{Number: 1004, Content: "1990-01-15"}},
	}
}

// A raw cbor.Tag comes back from BSON as a bson.D, which normaliseFullDate
// refuses.
func TestARawCborTagDoesNotSurviveTheCache(t *testing.T) {
	back := bsonRoundTrip(t, presentedShapes())

	_, err := normaliseFullDate(back["full_date"])
	require.Error(t, err, "this is the defect: a stored cbor.Tag is unreadable on the way out")
	assert.Contains(t, err.Error(), "bson.D")
}

// documentObject converts every leaf, so the round trip changes none of
// them.
func TestNormalisedLeafClaimsSurviveTheCacheUnchanged(t *testing.T) {
	storable, err := documentObject(presentedShapes())
	require.NoError(t, err, "every shape an mdoc can present must be storable")

	back := bsonRoundTrip(t, storable)
	for _, claim := range []string{"full_date", "tdate", "epoch", "timestamp", "portrait", "plain"} {
		assert.Equalf(t, storable[claim], back[claim],
			"claim %q must read back as the value that was stored", claim)
	}

	// Each date still normalises to the same day.
	for _, claim := range []string{"full_date", "tdate", "epoch", "timestamp"} {
		got, err := normaliseFullDate(back[claim])
		require.NoErrorf(t, err, "claim %q must still normalise after the cache", claim)
		assert.Equalf(t, "1990-01-15", got, "claim %q must mean the same day it did before storage", claim)
	}
}

// A nested object reads back from BSON as a bson.D whatever its leaves
// are: the decoder decides that on the way out. SD-JWT VC claims nest, so
// they need a decoder registry; this test fails once one is in place.
func TestNestedObjectsStillChangeTypeAcrossTheCache(t *testing.T) {
	storable, err := documentObject(map[string]any{
		"identity": map[string]any{"birthdate": "1990-01-15"},
	})
	require.NoError(t, err)
	require.IsType(t, map[string]any{}, storable["identity"], "stored as a plain object")

	back := bsonRoundTrip(t, storable)
	assert.IsType(t, bson.D{}, back["identity"],
		"a sub-document still reads back as bson.D; the leaves inside it are intact, the container is not")
}

// Each claim reads the same in process and after storage.
func TestIssuanceDoesNotDependOnTheCacheBackend(t *testing.T) {
	storable, err := documentObject(presentedShapes())
	require.NoError(t, err)

	for _, claim := range []string{"full_date", "tdate", "epoch", "timestamp", "portrait", "plain"} {
		inProcess := storable[claim]
		afterStorage := bsonRoundTrip(t, storable)[claim]
		assert.Equalf(t, inProcess, afterStorage,
			"claim %q differs by cache backend, which is how this failed before", claim)
	}
}

// documentObject refuses a tag it cannot represent, before storage.
func TestAnUnrepresentableTagIsRefusedBeforeStorage(t *testing.T) {
	_, err := documentObject(map[string]any{
		"odd": cbor.Tag{Number: 42, Content: "whatever this is"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CBOR tag")
}

// finalisePresentationVerification persists only storable claims.
func TestFinalisePresentationVerificationStoresOnlyStorableClaims(t *testing.T) {
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"pid_mdoc": {Format: openid4vp.FormatMsoMdoc, Doctype: "eu.europa.ec.eudi.pid.1"},
		}}},
		cacheService: &apigwcache.Service{
			AuthContext: apigwcache.NewTestMemoryStore(10 * time.Minute),
			Document:    apigwcache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute),
		},
	}
	authCtx := &pkgcache.AuthorizationContext{SessionID: "sess-mdoc"}
	require.NoError(t, c.cacheService.AuthContext.Create(t.Context(), authCtx))

	pScope := model.PresentationScope{
		FromScope: "pid_mdoc",
		RequiredClaims: map[string][]string{
			"eu.europa.ec.eudi.pid.1.birth_date": nil,
		},
	}
	// An mdoc element value, as fxamacker/cbor decodes it.
	presented := map[string]any{
		"docType":                            "eu.europa.ec.eudi.pid.1",
		"eu.europa.ec.eudi.pid.1.birth_date": cbor.Tag{Number: 1004, Content: "1990-01-15"},
	}

	require.NoError(t, c.finalisePresentationVerification(t.Context(), authCtx, pScope, presented))

	stored := authCtx.VerifiedClaims["eu.europa.ec.eudi.pid.1.birth_date"]
	assert.IsTypef(t, "", stored,
		"a cbor.Tag must not reach the cache: it has no BSON representation and comes back unreadable (type was %T)", stored)
	assert.Equal(t, "1990-01-15", stored)

	// The stored date still normalises after a BSON round trip.
	got, err := normaliseFullDate(bsonRoundTrip(t, authCtx.VerifiedClaims)["eu.europa.ec.eudi.pid.1.birth_date"])
	require.NoError(t, err, "the whole point: issuance must still read it after storage")
	assert.Equal(t, "1990-01-15", got)
}
