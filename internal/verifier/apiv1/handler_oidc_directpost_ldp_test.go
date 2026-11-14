package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An ldp_vc query is answered with the W3C presentation as a JSON object in the
// vp_token array (OpenID4VP 1.0 section 8.1). The encrypted direct_post used to
// read every entry as a string, so a conformant wallet's response decoded to no
// token at all and the presentation was refused before anything was verified.
func TestResolveDirectPostEncrypted_PresentationAsJSONObject(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	const kid = "test-session-ldp"

	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(t.Context(), kid)
	require.NoError(t, err)

	const presentation = `{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiablePresentation","holder":"did:key:z6MkExampleHolder","verifiableCredential":{"type":["VerifiableCredential","IndividualIDCredential"],"credentialSubject":{"fullName":"Alice Example"}},"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-rdfc-2022","proofPurpose":"authentication"}}`

	encrypt := func(t *testing.T, payload string) string {
		t.Helper()
		out, err := jwe.Encrypt([]byte(payload),
			jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)
		return string(out)
	}

	state, token, err := client.resolveDirectPost(t.Context(), &DirectPostRequest{
		Response: encrypt(t, `{"state":"`+kid+`","vp_token":{"individualIdvc":[ `+presentation+` ]}}`),
	})
	require.NoError(t, err)
	assert.Equal(t, kid, state)
	assert.JSONEq(t, presentation, token, "the presentation reaches the W3C verification as the document the wallet sent")

	documents, others := openid4vp.PartitionTokens(token)
	assert.Empty(t, others)
	assert.Len(t, documents, 1, "and it is recognised as a W3C document")
}
