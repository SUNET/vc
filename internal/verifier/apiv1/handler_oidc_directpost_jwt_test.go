package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveDirectPostEncrypted covers the reported direct_post.jwt failure.
//
// With response_mode=direct_post.jwt a wallet posts only `response`, a JWE
// holding state and vp_token (OpenID4VP 1.0 8.3.1). The OIDC endpoint required
// `state` as a form field and looked the session up by it before decrypting, so
// a conformant wallet was rejected at binding with
//
//	Key: 'DirectPostRequest.state' Error:Field validation for 'state' failed on the 'required' tag
//
// and behind that the encrypted branch was a TODO stub.
func TestResolveDirectPostEncrypted(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	const (
		kid   = "test-ephemeral-kid"
		state = "test-state-123"
		token = "eyJhbGciOiJFUzI1NiJ9.e30.sig~"
	)

	_, ephemeralPubJWK, err := client.openid4vp.EphemeralKeyCache.GenerateAndStore(kid)
	require.NoError(t, err)

	encrypt := func(t *testing.T, payload any) string {
		t.Helper()
		raw, err := json.Marshal(payload)
		require.NoError(t, err)
		out, err := jwe.Encrypt(raw,
			jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)
		return string(out)
	}

	t.Run("state and vp_token come out of the JWE", func(t *testing.T) {
		// No form-level state at all, which is what a conformant wallet sends.
		req := &DirectPostRequest{Response: encrypt(t, openid4vp.VPResponse{
			State:   state,
			VPToken: map[string][]string{"pid": {token}},
		})}

		gotState, gotToken, err := client.resolveDirectPost(req)
		require.NoError(t, err)
		assert.Equal(t, state, gotState, "the session is looked up by the decrypted state")
		assert.Equal(t, token, gotToken)
	})

	t.Run("plain direct_post still uses the form fields", func(t *testing.T) {
		gotState, gotToken, err := client.resolveDirectPost(&DirectPostRequest{
			State: state, VPToken: token,
		})
		require.NoError(t, err)
		assert.Equal(t, state, gotState)
		assert.Empty(t, gotToken, "the unencrypted path carries its token separately")
	})

	t.Run("neither state nor response is refused", func(t *testing.T) {
		_, _, err := client.resolveDirectPost(&DirectPostRequest{})
		require.Error(t, err)
	})

	t.Run("a response encrypted to an unknown key is refused", func(t *testing.T) {
		_, _, err := client.resolveDirectPost(&DirectPostRequest{
			Response: "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibm8tc3VjaC1raWQifQ..aaaa.bbbb.cccc",
		})
		require.Error(t, err)
	})

	t.Run("several credentials are refused rather than guessed at", func(t *testing.T) {
		// This flow maps one credential onto the OIDC claims it issues.
		_, _, err := client.resolveDirectPost(&DirectPostRequest{Response: encrypt(t, openid4vp.VPResponse{
			State:   state,
			VPToken: map[string][]string{"pid": {token}, "ehic": {token}},
		})})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one")
	})
}
