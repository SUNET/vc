package cache

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// The HA cache persists the whole authorization context - this query
// inside it - and another replica reads it back, so whatever BSON does to
// these values is what the OTHER replica sends.
//
// The driver's json.Number encoder tries Int64 and then Float64, which
// rounds a decimal beyond float64 precision and an integer beyond int64 -
// the exact values the JSON and YAML paths preserve. A req param is an
// input to a proof, so a replica rounding one computes a different
// pseudonym than the replica that built the request.
//
// Written here rather than in pkg/openid4vp because this is the question
// being asked: not "does the codec work" but "does the real driver, on
// the real struct, keep what was configured".
func TestAuthorizationContextKeepsExactNumbersThroughBSON(t *testing.T) {
	for _, tc := range []struct{ name, literal string }{
		{"a decimal beyond float64 precision", "1.00000000000000001"},
		{"an integer beyond int64", "123456789012345678901234567890"},
		{"the first integer a float64 cannot hold", "9007199254740993"},
		{"and an ordinary one, which must also be untouched", "7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
				ID: "nym", Format: openid4vp.FormatCircuitZk,
				Meta: openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
				Req: []openid4vp.ReqItem{{
					ID: openid4vp.FunctionPseudonym, Return: "nym-1",
					Params: map[string]any{"p": json.Number(tc.literal)},
				}},
			}}}

			stored, err := bson.Marshal(&AuthorizationContext{SessionID: "s", DCQLQuery: query})
			require.NoError(t, err)

			var loaded AuthorizationContext
			require.NoError(t, bson.Unmarshal(stored, &loaded))
			require.NotNil(t, loaded.DCQLQuery)

			// Compared as TEXT: a float64 comparison is exactly what
			// cannot see this defect.
			encoded, err := json.Marshal(loaded.DCQLQuery)
			require.NoError(t, err)
			assert.Contains(t, string(encoded), tc.literal,
				"the other replica has to send the number that was configured, not a rounding of it")
		})
	}
}

// And a query the typed model cannot hold survives too - the raw escape
// hatch is no use if it only works on the replica that built it.
func TestAuthorizationContextKeepsARawQueryThroughBSON(t *testing.T) {
	const wire = `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[{"fn_id":"age_check"}]}}`
	credential, err := openid4vp.NewRawCredentialQuery([]byte(wire))
	require.NoError(t, err)

	stored, err := bson.Marshal(&AuthorizationContext{
		SessionID: "s",
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{credential}},
	})
	require.NoError(t, err)

	var loaded AuthorizationContext
	require.NoError(t, bson.Unmarshal(stored, &loaded))
	require.NotNil(t, loaded.DCQLQuery)
	require.Len(t, loaded.DCQLQuery.Credentials, 1)

	encoded, err := json.Marshal(loaded.DCQLQuery.Credentials[0])
	require.NoError(t, err)
	assert.JSONEq(t, wire, string(encoded))
	assert.Equal(t, "q", loaded.DCQLQuery.Credentials[0].ID,
		"and the shadow the response path matches by")
}

// An absent query stays absent rather than becoming an empty one.
func TestAuthorizationContextWithoutADCQLQuery(t *testing.T) {
	stored, err := bson.Marshal(&AuthorizationContext{SessionID: "s"})
	require.NoError(t, err)

	var loaded AuthorizationContext
	require.NoError(t, bson.Unmarshal(stored, &loaded))
	assert.Nil(t, loaded.DCQLQuery)
}

// Rolling upgrades, both directions. The exact copy is ADDITIVE, so
// neither build is broken by the other's documents.
func TestAuthorizationContextSurvivesARollingUpgrade(t *testing.T) {
	query := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
		ID: "nym", Format: openid4vp.FormatCircuitZk,
		Meta: openid4vp.MetaQuery{DoctypeValue: "d"},
		Req: []openid4vp.ReqItem{{ID: openid4vp.FunctionPseudonym, Return: "nym-1",
			Params: map[string]any{"p": json.Number("1.00000000000000001")}}},
	}}}

	t.Run("a new replica reads an old document", func(t *testing.T) {
		// What an older build wrote: the query as a document, with no
		// exact copy beside it.
		type oldShape struct {
			SessionID string          `bson:"session_id"`
			DCQLQuery *openid4vp.DCQL `bson:"dcql_query,omitempty"`
		}
		stored, err := bson.Marshal(&oldShape{SessionID: "s", DCQLQuery: query})
		require.NoError(t, err)

		var loaded AuthorizationContext
		require.NoError(t, bson.Unmarshal(stored, &loaded),
			"an old document must still load; a rollout cannot require every session to be new")
		require.NotNil(t, loaded.DCQLQuery)
		require.Len(t, loaded.DCQLQuery.Credentials, 1)
		assert.Equal(t, "nym", loaded.DCQLQuery.Credentials[0].ID)

		// Rounded, because that is what the old build stored. Nothing
		// regresses; the exactness is what is new, not a repair of what
		// was already written.
		encoded, err := json.Marshal(loaded.DCQLQuery)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), "1.00000000000000001")
	})

	t.Run("an old replica reads a new document", func(t *testing.T) {
		stored, err := bson.Marshal(&AuthorizationContext{SessionID: "s", DCQLQuery: query})
		require.NoError(t, err)

		// An older build models only dcql_query and ignores the rest.
		var loaded struct {
			SessionID string          `bson:"session_id"`
			DCQLQuery *openid4vp.DCQL `bson:"dcql_query,omitempty"`
		}
		require.NoError(t, bson.Unmarshal(stored, &loaded),
			"a new document must still load on an old replica, or a rollout fails in the other direction")
		require.NotNil(t, loaded.DCQLQuery)
		require.Len(t, loaded.DCQLQuery.Credentials, 1)
		assert.Equal(t, "nym", loaded.DCQLQuery.Credentials[0].ID)
	})

	t.Run("and a new replica reads a new document exactly", func(t *testing.T) {
		stored, err := bson.Marshal(&AuthorizationContext{SessionID: "s", DCQLQuery: query})
		require.NoError(t, err)

		var loaded AuthorizationContext
		require.NoError(t, bson.Unmarshal(stored, &loaded))
		encoded, err := json.Marshal(loaded.DCQLQuery)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "1.00000000000000001")
	})
}

// A corrupted exact copy is refused rather than quietly replaced by the
// rounded one, which would send numbers that differ from those stored.
func TestAuthorizationContextRefusesACorruptExactQuery(t *testing.T) {
	stored, err := bson.Marshal(bson.M{"session_id": "s", "dcql_query_exact": "{not json"})
	require.NoError(t, err)

	var loaded AuthorizationContext
	require.Error(t, bson.Unmarshal(stored, &loaded))
}

// The exact copy is DERIVED from DCQLQuery, so clearing the query has to
// clear it too.
//
// A context loaded from BSON carries the exact text in memory. A caller
// that then clears DCQLQuery and saves would otherwise leave the old text
// in the replacement document - and the next read prefers it, restoring
// the query that had just been removed.
func TestClearingTheQueryClearsTheExactCopy(t *testing.T) {
	query := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
		ID: "nym", Format: openid4vp.FormatCircuitZk,
		Meta: openid4vp.MetaQuery{DoctypeValue: "d"},
	}}}

	stored, err := bson.Marshal(&AuthorizationContext{SessionID: "s", DCQLQuery: query})
	require.NoError(t, err)

	var loaded AuthorizationContext
	require.NoError(t, bson.Unmarshal(stored, &loaded))
	require.NotNil(t, loaded.DCQLQuery)
	require.NotEmpty(t, loaded.DCQLQueryExact, "the exact copy is what makes this worth testing")

	// What a caller removing the query does.
	loaded.DCQLQuery = nil
	resaved, err := bson.Marshal(&loaded)
	require.NoError(t, err)

	var reloaded AuthorizationContext
	require.NoError(t, bson.Unmarshal(resaved, &reloaded))
	assert.Nil(t, reloaded.DCQLQuery, "a removed query must not come back")
	assert.Empty(t, reloaded.DCQLQueryExact)
}
