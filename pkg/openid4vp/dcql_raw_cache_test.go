package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A request object is JSON-encoded into the HA cache and read back by
// another node (internal/verifier/cache). So a query this model cannot
// hold has to survive that round trip, or the escape hatch works only on
// the node that built the request - which is the shape of bug that shows
// up as "it works on one replica".
func TestRawSurvivesAJSONRoundTrip(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"the WIP shape, claims as an object", `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[{"fn_id":"age_check","id":"h"}]}}`},
		{"req as an object, as a later generation might", `{"id":"q","format":"circuit_zk","req":{"not":"an array"}}`},
		{"a member whose type the model does not expect", `{"id":"q","format":"circuit_zk","meta":"not an object"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// As the verifier built it.
			built := CredentialQuery{Raw: json.RawMessage(tc.query)}

			// Into the cache.
			stored, err := json.Marshal(&DCQL{Credentials: []CredentialQuery{built}})
			require.NoError(t, err)

			// And back out on another node.
			var loaded DCQL
			require.NoError(t, json.Unmarshal(stored, &loaded),
				"a query the model cannot hold must still load; otherwise the request exists only where it was made")
			require.Len(t, loaded.Credentials, 1)

			// What goes to the wallet is what was configured.
			out, err := json.Marshal(loaded.Credentials[0])
			require.NoError(t, err)
			assert.JSONEq(t, tc.query, string(out))
		})
	}
}

// A query the model DOES understand still decodes typed, so the fallback
// does not quietly swallow everything.
func TestTypedQueriesStillDecodeTyped(t *testing.T) {
	const in = `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"age_check","return":"h"}]}`
	var query CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(in), &query))

	assert.Nil(t, query.Raw, "this shape is modelled, so it must not fall back to raw")
	require.Len(t, query.Req, 1)
	assert.Equal(t, FunctionAgeCheck, query.Req[0].ID)
}

// Invalid JSON is still an error. The fallback keeps shapes, not rubbish:
// bytes that are not JSON cannot be put inside a request object at all.
func TestInvalidJSONIsStillRejected(t *testing.T) {
	var query CredentialQuery
	require.Error(t, json.Unmarshal([]byte(`{not json`), &query))
}

// The escape hatch has to get PAST the ingress, not just through the
// serialiser. UIInteraction and the two VC 2.0 paths run every query it
// is handed through ValidateCredentialQuery, and a raw query carries no
// Format - which every other reader in this package reads as SD-JWT. Left
// unguarded, the hatch fails on "vct_values is required" at the one door
// a browser-built query arrives by.
func TestValidateDoesNotJudgeARawQuery(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"the WIP shape, claims as an object", `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[]}}`},
		{"an sd-jwt query with no vct_values, which is what the SD-JWT branch refuses", `{"id":"q","format":"vc+sd-jwt","claims":{"_req":[]}}`},
		{"meta itself of a type the model does not expect", `{"id":"q","format":"mso_mdoc","meta":"not an object"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var query CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(tc.query), &query))
			require.NotNil(t, query.Raw, "the point of this case is that it fell back to raw")
			assert.NoError(t, ValidateCredentialQuery(query))
		})
	}
}

// Not judging is not the same as not looking. Raw is emitted verbatim, so
// bytes that are not JSON would make the whole request object unencodable
// at send time, far from the configuration that caused it.
func TestValidateRejectsRawThatIsNotJSON(t *testing.T) {
	err := ValidateCredentialQuery(CredentialQuery{Raw: json.RawMessage(`{not json`)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "raw")
}
