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
