package openid4vp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEphemeralPublicJWK_CarriesEveryRequiredMember pins the members a wallet
// checks for. The key previously carried kty, crv, x and y but not alg, and
// wallets reject the whole request object over the one missing member.
func TestEphemeralPublicJWK_CarriesEveryRequiredMember(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(5 * time.Minute)
	_, pub, err := cache.GenerateAndStore("kid-1")
	require.NoError(t, err)

	raw, err := json.Marshal(pub)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	for _, member := range []string{"kty", "crv", "x", "y", "alg"} {
		assert.Contains(t, got, member, "wallets require %q in each client_metadata JWK", member)
		assert.NotEmpty(t, got[member], "%q must not be empty", member)
	}

	assert.Equal(t, "ECDH-ES", got["alg"], "alg names the key-agreement algorithm for this key")
	assert.Equal(t, "EC", got["kty"])
	assert.Equal(t, "P-256", got["crv"])
	assert.Equal(t, "enc", got["use"])
	assert.Equal(t, "kid-1", got["kid"])
}

// TestEphemeralKeyRoundTrip guards the property the DC API change depends on:
// the private half must be retrievable by the kid advertised in the public
// half, or the wallet encrypts to a key we cannot find.
func TestEphemeralKeyRoundTrip(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(5 * time.Minute)
	priv, pub, err := cache.GenerateAndStore("session-42")
	require.NoError(t, err)

	kid, ok := pub.KeyID()
	require.True(t, ok)
	assert.Equal(t, "session-42", kid)

	found, ok := cache.Get(kid)
	require.True(t, ok, "the private key must be retrievable by the advertised kid")
	assert.Equal(t, priv, found)
}

// TestClientMetadata_EncryptedResponseEncValuesSupportedIsAnArray pins the
// wire shape. OpenID4VP 1.0 replaced the single-string
// authorization_encrypted_response_enc with an array under a new name, and a
// 1.0 wallet rejects client_metadata carrying only the old spelling.
func TestClientMetadata_EncryptedResponseEncValuesSupportedIsAnArray(t *testing.T) {
	md := &ClientMetadata{
		AuthorizationEncryptedResponseALG:   "ECDH-ES",
		AuthorizationEncryptedResponseENC:   "A256GCM",
		EncryptedResponseEncValuesSupported: []string{"A256GCM"},
	}

	raw, err := json.Marshal(md)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	values, ok := got["encrypted_response_enc_values_supported"].([]any)
	require.True(t, ok, "must serialise as an array of strings, not a string")
	assert.Equal(t, []any{"A256GCM"}, values)

	// The draft-era spellings stay so wallets that predate 1.0 keep working.
	assert.Equal(t, "A256GCM", got["authorization_encrypted_response_enc"])
	assert.Equal(t, "ECDH-ES", got["authorization_encrypted_response_alg"])
}
