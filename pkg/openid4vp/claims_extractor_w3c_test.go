package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/vc20/credential"

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

// TestExtractClaims_W3CExpanded: detectCredentialFormat accepts a leading
// "[" as a W3C credential, so the extractor has to as well - otherwise the
// verifier accepts a presentation and then claim extraction cannot read a
// claim out of the same bytes.
//
// Expanded JSON-LD is what json-gold's MarshalJSON emits, so this is the
// form anything re-serialized from an RDFCredential arrives in.
func TestExtractClaims_W3CExpanded(t *testing.T) {
	ce := NewClaimsExtractor()

	// Claims the VC 2.0 context defines, because expansion DROPS a term no
	// context defines - "degree" would not survive the round trip, and a
	// test asserting it did would be testing the fixture rather than the
	// extractor.
	const contextDefined = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject", "name": "Alice"}
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(contextDefined), nil)
	require.NoError(t, err)

	expanded, err := json.Marshal(cred)
	require.NoError(t, err)
	require.Equal(t, byte('['), expanded[0], "the fixture must really be expanded, or this proves nothing")

	claims, err := ce.ExtractClaimsFromVPToken(t.Context(), string(expanded))
	require.NoError(t, err)
	assert.Equal(t, "did:example:subject", claims["id"])
	assert.Equal(t, "Alice", claims["name"])

	// And inside a DCQL response, which is how a wallet would send it.
	embedded, err := jsonString(string(expanded))
	require.NoError(t, err)
	claims, err = ce.ExtractClaimsFromVPToken(t.Context(), `{"pid": [`+embedded+`]}`)
	require.NoError(t, err)
	assert.Equal(t, "Alice", claims["name"])
}

// TestIsExpandedNode keeps the compaction from firing on a compact document,
// which would be wasted work and a needless dependency on context loading.
func TestIsExpandedNode(t *testing.T) {
	assert.False(t, isExpandedNode(map[string]any{"@context": "x", "credentialSubject": map[string]any{}}))
	assert.False(t, isExpandedNode(map[string]any{"credentialSubject": map[string]any{}}),
		"compact terms carry no scheme")
	assert.True(t, isExpandedNode(map[string]any{"https://www.w3.org/2018/credentials#credentialSubject": []any{}}))
}

// TestW3CDocumentsIn: a DCQL response is a JSON object too, so "looks like
// JSON" cannot tell a W3C document from the envelope around one. A verifier
// that must check W3C documents before reading them has to ask which
// documents are actually there, or it fails a conformant DCQL response as a
// malformed credential without ever looking inside it.
func TestW3CDocumentsIn(t *testing.T) {
	embedded, err := jsonString(w3cCredential)
	require.NoError(t, err)

	t.Run("a bare document", func(t *testing.T) {
		got := W3CDocumentsIn(w3cCredential)
		require.Len(t, got, 1)
		require.Len(t, got[""], 1, "a bare document has no query id")
	})

	t.Run("inside a DCQL envelope", func(t *testing.T) {
		got := W3CDocumentsIn(`{"pid": [` + embedded + `]}`)
		require.Len(t, got, 1)
		require.Len(t, got["pid"], 1, "keyed by the credential query id")
	})

	t.Run("a DCQL envelope of SD-JWTs carries none", func(t *testing.T) {
		require.Empty(t, W3CDocumentsIn(`{"pid": ["eyJhbGciOiJFUzI1NiJ9.x.y~"]}`),
			"the envelope must not be mistaken for a credential")
	})

	t.Run("a bare SD-JWT carries none", func(t *testing.T) {
		require.Empty(t, W3CDocumentsIn("eyJhbGciOiJFUzI1NiJ9.x.y~"))
	})

	t.Run("expanded JSON-LD counts", func(t *testing.T) {
		require.Len(t, W3CDocumentsIn(`[{"@id":"_:b0"}]`)[""], 1)
	})

	require.Empty(t, W3CDocumentsIn(""))
	require.Empty(t, W3CDocumentsIn("not json"))
}

// TestEmbeddedCredentialCount: a caller that must not read unverified
// claims has to know when a presentation carries more than one credential,
// because VerifyAndExtract verifies only the first.
func TestEmbeddedCredentialCount(t *testing.T) {
	bare, err := EmbeddedCredentialCount(w3cCredential)
	require.NoError(t, err)
	require.Zero(t, bare, "a bare credential embeds none")

	one := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"verifiableCredential": [` + w3cCredential + `]
	}`
	got, err := EmbeddedCredentialCount(one)
	require.NoError(t, err)
	require.Equal(t, 1, got)

	two := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"verifiableCredential": [` + w3cCredential + `, ` + w3cCredential + `]
	}`
	got, err = EmbeddedCredentialCount(two)
	require.NoError(t, err)
	require.Equal(t, 2, got)

	_, err = EmbeddedCredentialCount("not json")
	require.Error(t, err)
}

// TestW3CDocumentsInSeesThroughBase64: the VC20 decoder and
// detectCredentialFormat both accept a base64url- or standard-base64-wrapped
// JSON-LD document, so a detector that only looked for a leading '{' missed
// the same credential when it arrived encoded - and the caller that refuses
// unverified W3C claims never saw it.
//
// The returned document is DECODED, because callers go on to parse it.
func TestW3CDocumentsInSeesThroughBase64(t *testing.T) {
	for name, encode := range map[string]func([]byte) string{
		"base64url": base64.RawURLEncoding.EncodeToString,
		"base64":    base64.StdEncoding.EncodeToString,
	} {
		t.Run(name, func(t *testing.T) {
			wrapped := encode([]byte(w3cCredential))

			bare := W3CDocumentsIn(wrapped)
			require.Len(t, bare, 1)
			assert.JSONEq(t, w3cCredential, bare[""][0], "the caller parses this, so it has to be decoded")

			envelope, err := json.Marshal(map[string][]string{"pid": {wrapped}})
			require.NoError(t, err)
			inEnvelope := W3CDocumentsIn(string(envelope))
			require.Len(t, inEnvelope["pid"], 1)
			assert.JSONEq(t, w3cCredential, inEnvelope["pid"][0])
		})
	}

	// An mdoc must not be mistaken for one. Its CBOR starts 0x80-0xbf while
	// '{' is 0x7b and '[' is 0x5b, so the two cannot collide - pinned here
	// because the check is a byte comparison nothing else guards.
	mdoc := base64.RawURLEncoding.EncodeToString([]byte{0xa1, 0x63, 'f', 'o', 'o'})
	assert.Nil(t, W3CDocumentsIn(mdoc), "a CBOR document is not a JSON-LD one")
}

// TestExtractClaimsFromBase64W3CToken is the other half: the extractor has to
// route an encoded document to the W3C reader rather than fall through to the
// SD-JWT parser.
func TestExtractClaimsFromBase64W3CToken(t *testing.T) {
	extractor := &ClaimsExtractor{}
	claims, err := extractor.extractClaimsFromSingleToken(base64.RawURLEncoding.EncodeToString([]byte(w3cCredential)))
	require.NoError(t, err)
	assert.Equal(t, "Master of Science", claims["degree"])
}
