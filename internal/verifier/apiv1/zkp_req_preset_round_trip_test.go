package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// browserCopy is the preset-to-DCQL copy that presentation-definition.js
// performs, in the shape the browser performs it: field by field, over
// the JSON the server published, producing the JSON the browser posts.
//
// Written against the published JSON rather than the Go structs on
// purpose. The two key names this guards - the preset's `req` and the
// wire's `_req`, and the item's `fn_id` - exist only in the JSON; the Go
// side is one field with one tag at each end, so a test that stayed in
// Go would agree with itself no matter what either tag said.
func browserCopy(t *testing.T, preset *UIPreset) []byte {
	t.Helper()

	published, err := json.Marshal(preset.Credentials)
	require.NoError(t, err)

	var credentials []map[string]any
	require.NoError(t, json.Unmarshal(published, &credentials))

	out := make([]map[string]any, 0, len(credentials))
	for _, credential := range credentials {
		copied := map[string]any{
			"id":     credential["id"],
			"format": credential["format"],
			"meta":   credential["meta"],
		}
		if claims, ok := credential["claims"]; ok {
			copied["claims"] = claims
		}
		// The line this test exists for: the preset's `req` is the
		// wire's `_req`.
		if req, ok := credential["req"]; ok {
			copied["_req"] = req
		}
		out = append(out, copied)
	}

	query, err := json.Marshal(map[string]any{"credentials": out})
	require.NoError(t, err)
	return query
}

// What the operator UI does end to end: read /ui/metadata, copy the
// preset into a DCQL query, post it back. Both halves had a key wrong
// and neither said so.
//
// The item key `fn_id` was published while the browser's valibot schema
// still checked `id`, so parsing /ui/metadata threw and the live gdc
// operator page never left its spinner. Behind it, the browser copied
// the preset's `req` to a posted `req`, which CredentialQuery.Req (tag
// `_req`) does not match - encoding/json drops it - so the query would
// have gone out with no items, asking the wallet for nothing and
// reading as a wallet fault.
func TestPublishedPresetSurvivesTheBrowserRoundTrip(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
		Format: openid4vp.FormatZkpReq,
		Req:    nymReq,
	}, nil)
	cfg.Verifier.PublicURL = "https://verifier.example.com"
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(t.Context())
	require.NoError(t, err)
	preset := reply.Presets["Nym"]
	require.NotNil(t, preset)

	posted := browserCopy(t, preset)

	var query openid4vp.DCQL
	require.NoError(t, json.Unmarshal(posted, &query))
	require.Len(t, query.Credentials, 1)

	credential := query.Credentials[0]
	require.NotEmpty(t, credential.Req,
		"the posted query carries no req items, so the request would ask the wallet for nothing")
	assert.Equal(t, nymReq, credential.Req,
		"the items the operator configured must be the items that go out")
	assert.Equal(t, openid4vp.FunctionPseudonym, credential.Req[0].FnID,
		"the function identifier must survive as fn_id")

	// And the whole thing must be a query this verifier will accept.
	_, err = client.UIInteraction(t.Context(), &UIInteractionRequest{DCQLQuery: &query})
	require.NoError(t, err, "the verifier refused the query its own preset produced")
	assert.Equal(t, "mso_mdoc", query.Credentials[0].Meta.SourceFormat)
}
