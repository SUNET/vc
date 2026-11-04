package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vendoredVectorQuery returns the "query" member of a vendored circuit_zk
// conformance vector.
func vendoredVectorQuery(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "pkg", "openid4vp", "testdata", "zkp_req", "zkp_req", name))
	require.NoError(t, err)
	var doc struct {
		Query json.RawMessage `json:"query"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Query)
	return doc.Query
}

// A request object this verifier published must reload from its own
// cache, whatever query it carries.
//
// The authorization-context decoder was fixed first and this one was
// missed, which is the shape of the defect: the request object is cached
// separately, and an HA request_uri lookup reads it back on another node.
// So a request the raw escape hatch built - a conformance harness
// deliberately sending a malformed query to see what a wallet does -
// could be PUBLISHED, and then the wallet sent to fetch it got nothing.
//
// Driven through the actual decoder the cache is constructed with, not
// through json.Unmarshal: the whole point is that this path differed
// from the other one.
func TestRequestObjectDecoderReloadsARawQuery(t *testing.T) {
	for _, name := range []string{
		"err_meta_doctype_not_string.json",
		"err_meta_vct_values_not_strings.json",
	} {
		t.Run(name, func(t *testing.T) {
			wire := vendoredVectorQuery(t, name)

			built, err := openid4vp.NewRawCredentialQuery(wire)
			require.NoError(t, err, "the constructor accepts it; that is the escape hatch")

			published := &openid4vp.RequestObject{
				ClientID:  "x509_san_dns:verifier.example",
				Nonce:     "n-1",
				State:     "s-1",
				DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{built}},
			}
			stored, err := json.Marshal(published)
			require.NoError(t, err)

			// The premise: a strict decode of these very bytes fails,
			// which is what the request_uri lookup used to do.
			require.Error(t, json.Unmarshal(stored, &openid4vp.RequestObject{}),
				"if this stops failing, this test is pinning something else")

			loaded, err := requestObjectDecoder(stored)
			require.NoError(t, err, "a request this verifier published must be deliverable")
			require.NotNil(t, loaded.DCQLQuery)
			require.Len(t, loaded.DCQLQuery.Credentials, 1)
			require.NotNil(t, loaded.DCQLQuery.Credentials[0].Raw,
				"a shape the model cannot hold must reload raw, not be repaired into it")

			// The rest of the request object survives the detour.
			assert.Equal(t, published.ClientID, loaded.ClientID)
			assert.Equal(t, published.Nonce, loaded.Nonce)
			assert.Equal(t, published.State, loaded.State)

			// And the wallet receives what was published.
			again, err := json.Marshal(loaded.DCQLQuery.Credentials[0])
			require.NoError(t, err)
			assert.JSONEq(t, string(wire), string(again))
		})
	}
}

// An ordinary request object still decodes, and a genuinely broken one
// still reports what is wrong with it rather than the retry's error.
func TestRequestObjectDecoderStillFailsClosed(t *testing.T) {
	t.Run("an ordinary request object", func(t *testing.T) {
		stored, err := json.Marshal(&openid4vp.RequestObject{
			ClientID: "x509_san_dns:verifier.example", Nonce: "n-1",
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
				ID: "pid", Format: openid4vp.FormatSDJWTVC,
				Meta: openid4vp.MetaQuery{VCTValues: []string{"https://example.com/pid"}},
			}}},
		})
		require.NoError(t, err)

		loaded, err := requestObjectDecoder(stored)
		require.NoError(t, err)
		require.NotNil(t, loaded.DCQLQuery)
		assert.Equal(t, "pid", loaded.DCQLQuery.Credentials[0].ID)
		assert.Nil(t, loaded.DCQLQuery.Credentials[0].Raw,
			"an ordinary query must still decode into the model, not take the raw detour")
	})

	t.Run("not JSON at all", func(t *testing.T) {
		_, err := requestObjectDecoder([]byte("{not json"))
		require.Error(t, err)
	})

	t.Run("a failure that is not the query reports its own error", func(t *testing.T) {
		// client_id is a string; an object there is an ordinary decode
		// failure, and the retry must not mask it.
		_, err := requestObjectDecoder([]byte(`{"client_id":{"not":"a string"},"nonce":"n-1"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id",
			"the error must name what actually failed, not the dcql retry")
	})

	t.Run("a query that means two things is still refused", func(t *testing.T) {
		// checkRawConstraints runs inside UnmarshalTrustedDCQL, so a
		// duplicate constraint does not reload however it got stored.
		_, err := requestObjectDecoder([]byte(
			`{"nonce":"n-1","dcql_query":{"credentials":[{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["a"]},"meta":{"vct_values":["b"]}}]}}`))
		require.Error(t, err)
	})
}
