package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ldpPresentation is the shape a wallet answers an ldp_vc query with: the
// W3C presentation itself, as a JSON object. OpenID4VP 1.0 section 8.1 puts it
// in the vp_token array as an object, where an SD-JWT or mdoc is a string.
// Values are placeholders; the structure is what an Accredify wallet sent.
const ldpPresentation = `{
  "@context": "https://www.w3.org/ns/credentials/v2",
  "type": "VerifiablePresentation",
  "holder": "did:key:z6MkExampleHolder",
  "verifiableCredential": {
    "type": ["VerifiableCredential", "IndividualIDCredential"],
    "issuer": {"id": "did:web:issuer.example"},
    "credentialSubject": {"fullName": "Alice Example", "email": "alice@example.org"},
    "proof": {"type": "DataIntegrityProof", "cryptosuite": "ecdsa-sd-2023", "proofValue": "u2V0AhVhAPlaceholder"}
  },
  "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022", "proofPurpose": "authentication", "challenge": "nonce", "domain": "x509_san_dns:verifier.example", "proofValue": "zPlaceholder"}
}`

func compactJSON(t *testing.T, s string) string {
	t.Helper()
	var v json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(s), &v))
	out, err := json.Marshal(v)
	require.NoError(t, err)
	return string(out)
}

func TestVPResponse_PresentationAsJSONObject(t *testing.T) {
	want := compactJSON(t, ldpPresentation)

	t.Run("an object in the array is carried as its compact JSON text", func(t *testing.T) {
		var r VPResponse
		require.NoError(t, json.Unmarshal([]byte(`{"state":"s","vp_token":{"individualIdvc":[`+ldpPresentation+`]}}`), &r))
		require.Equal(t, []string{want}, r.VPToken["individualIdvc"])
	})

	t.Run("a bare object is accepted as one presentation", func(t *testing.T) {
		var r VPResponse
		require.NoError(t, json.Unmarshal([]byte(`{"state":"s","vp_token":{"individualIdvc":`+ldpPresentation+`}}`), &r))
		require.Equal(t, []string{want}, r.VPToken["individualIdvc"])
	})

	t.Run("strings and objects mix in one array", func(t *testing.T) {
		var r VPResponse
		require.NoError(t, json.Unmarshal([]byte(`{"state":"s","vp_token":{"q":["eyJhbGciOiJFUzI1NiJ9.e30.sig~",`+ldpPresentation+`]}}`), &r))
		require.Equal(t, []string{"eyJhbGciOiJFUzI1NiJ9.e30.sig~", want}, r.VPToken["q"])
	})

	t.Run("the member order the wallet sent is kept", func(t *testing.T) {
		var r VPResponse
		require.NoError(t, json.Unmarshal([]byte(`{"state":"s","vp_token":{"q":[{"b": 1, "a": 2}]}}`), &r))
		assert.Equal(t, []string{`{"b":1,"a":2}`}, r.VPToken["q"])
	})

	for name, body := range map[string]string{
		"a number in the array":  `{"state":"s","vp_token":{"q":[1]}}`,
		"null in the array":      `{"state":"s","vp_token":{"q":[null]}}`,
		"a nested array":         `{"state":"s","vp_token":{"q":[["x"]]}}`,
		"an empty array":         `{"state":"s","vp_token":{"q":[]}}`,
		"an empty string":        `{"state":"s","vp_token":{"q":[""]}}`,
		"null for the query":     `{"state":"s","vp_token":{"q":null}}`,
		"a number for the query": `{"state":"s","vp_token":{"q":3}}`,
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			var r VPResponse
			require.Error(t, json.Unmarshal([]byte(body), &r))
		})
	}
}

func TestPartitionTokens_ObjectPresentationInEnvelope(t *testing.T) {
	envelope := `{"individualIdvc":[` + ldpPresentation + `]}`

	w3c, other := PartitionTokens(envelope)
	assert.Empty(t, other)
	require.Equal(t, []string{compactJSON(t, ldpPresentation)}, w3c["individualIdvc"])
}

func TestExtractClaims_ObjectPresentationInEnvelope(t *testing.T) {
	ce := &ClaimsExtractor{}
	claims, err := ce.ExtractClaimsFromVPToken(t.Context(), `{"individualIdvc":[`+ldpPresentation+`]}`)
	require.NoError(t, err)
	assert.Equal(t, "Alice Example", claims["fullName"])
	assert.Equal(t, "alice@example.org", claims["email"])
}
