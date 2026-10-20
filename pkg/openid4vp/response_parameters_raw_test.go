package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Not every presentation is a string. A circuit_zk presentation is an
// object, and the decoder used to refuse the whole response over it.
//
// It is kept RAW and only raw: the string map is what every other
// format reads, and a re-encoded object there would hand that format a
// token it cannot parse while losing the bytes the new one needs - a
// repeated member or handle is invisible after a decode, because Go
// keeps the last of a repeated key.
func TestVPResponseKeepsObjectPresentationsRaw(t *testing.T) {
	const body = `{
	  "state": "s",
	  "vp_token": {
	    "nym_attestation": [{"circuit_id": "urn:c", "results": {"h": {"satisfied": true}}}],
	    "pid": "a.b.c"
	  }
	}`

	var response VPResponse
	require.NoError(t, json.Unmarshal([]byte(body), &response))

	assert.Equal(t, []string{"a.b.c"}, response.VPToken["pid"], "a string presentation still decodes")
	assert.NotContains(t, response.VPToken, "nym_attestation", "an object presentation is not a string token")

	raw, ok := response.VPTokenRaw["nym_attestation"]
	require.True(t, ok, "it has to be reachable as raw bytes")
	assert.Contains(t, string(raw), `"circuit_id"`)

	// Byte-for-byte what arrived, because a re-encoding is exactly
	// what a duplicate check can no longer see.
	assert.JSONEq(t, `[{"circuit_id": "urn:c", "results": {"h": {"satisfied": true}}}]`, string(raw))

	// Every entry, not only the object one, so a caller never has to
	// ask which map an entry is in.
	assert.Contains(t, response.VPTokenRaw, "pid")
}

// Admitting one more legitimate shape is not admitting everything.
func TestVPResponseStillRefusesAMalformedEntry(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"a number", `{"state":"s","vp_token":{"pid": 42}}`},
		{"an array of numbers", `{"state":"s","vp_token":{"pid": [1,2]}}`},
		{"an array of arrays", `{"state":"s","vp_token":{"pid": [[]]}}`},
		{"a mixed array", `{"state":"s","vp_token":{"pid": [{"a":1}, 2]}}`},
		{"an empty array", `{"state":"s","vp_token":{"pid": []}}`},
		{"an empty string", `{"state":"s","vp_token":{"pid": ""}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response VPResponse
			assert.Error(t, json.Unmarshal([]byte(tc.body), &response))
		})
	}
}
