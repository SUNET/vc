package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const w3cCredential = `{
	"@context": "https://www.w3.org/ns/credentials/v2",
	"type": ["VerifiableCredential", "DiplomaCredential"],
	"issuer": "did:example:issuer",
	"credentialSubject": {"id": "did:example:subject", "degree": "Master of Science"}
}`

// TestExtractClaims_W3C: a W3C VC 2.0 response is JSON, so it reached this
// extractor's DCQL branch and failed there as "cannot parse as
// map[string][]string". That is why a configured W3C scope worked through
// the UI direct-post path and nowhere else - the OIDC path extracts claims
// through here.
func TestExtractClaims_W3C(t *testing.T) {
	ce := NewClaimsExtractor()

	t.Run("bare credential", func(t *testing.T) {
		claims, err := ce.ExtractClaimsFromVPToken(t.Context(), w3cCredential)
		require.NoError(t, err)
		assert.Equal(t, "Master of Science", claims["degree"])
		assert.Equal(t, "did:example:subject", claims["id"])
	})

	t.Run("presentation with an embedded credential object", func(t *testing.T) {
		vp := `{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiablePresentation"],
			"holder": "did:example:holder",
			"verifiableCredential": [` + w3cCredential + `]
		}`
		claims, err := ce.ExtractClaimsFromVPToken(t.Context(), vp)
		require.NoError(t, err)
		assert.Equal(t, "Master of Science", claims["degree"])
	})

	t.Run("presentation with an embedded credential string", func(t *testing.T) {
		embedded, err := jsonString(w3cCredential)
		require.NoError(t, err)
		vp := `{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiablePresentation"],
			"verifiableCredential": [` + embedded + `]
		}`
		claims, err := ce.ExtractClaimsFromVPToken(t.Context(), vp)
		require.NoError(t, err)
		assert.Equal(t, "Master of Science", claims["degree"])
	})

	t.Run("inside a DCQL response", func(t *testing.T) {
		embedded, err := jsonString(w3cCredential)
		require.NoError(t, err)
		claims, err := ce.ExtractClaimsFromVPToken(t.Context(), `{"pid": [`+embedded+`]}`)
		require.NoError(t, err)
		assert.Equal(t, "Master of Science", claims["degree"])
	})

	t.Run("a credential with no subject is refused", func(t *testing.T) {
		_, err := ce.ExtractClaimsFromVPToken(t.Context(), `{"@context":"https://www.w3.org/ns/credentials/v2","credentialSubject":null}`)
		require.Error(t, err)
	})
}

// TestIsW3CDocument keeps the discriminator from swallowing DCQL responses:
// a malformed DCQL vp_token must still be reported as one, since that is the
// useful error for the case that produces it.
func TestIsW3CDocument(t *testing.T) {
	assert.True(t, isW3CDocument(w3cCredential))
	assert.True(t, isW3CDocument(`{"@context":"x","verifiableCredential":[]}`))

	assert.False(t, isW3CDocument(`{"cred1": ["token"]}`), "an ordinary DCQL response")
	assert.False(t, isW3CDocument(`{"cred1": "not-an-array"}`), "a malformed DCQL response")
	assert.False(t, isW3CDocument(`{"credentialSubject": ["token"]}`),
		"a DCQL query id that happens to be named credentialSubject, with no @context")
	assert.False(t, isW3CDocument(`{"@context": ["token"]}`),
		"@context alone is not a W3C document without a payload member")
	assert.False(t, isW3CDocument(`not json`))
}

// jsonString renders a document as a JSON string literal, which is how a
// presentation embeds a credential it carries by value.
func jsonString(s string) (string, error) {
	b, err := json.Marshal(s)
	return string(b), err
}
