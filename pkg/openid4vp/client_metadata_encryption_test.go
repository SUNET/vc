package openid4vp

import (
	"crypto"
	"encoding/json"
	"sync"
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
	t.Cleanup(cache.Stop)
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
	t.Cleanup(cache.Stop)
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

// TestGenerateAndStoreIfAbsent_Concurrent covers the check-then-act race.
// Two request objects for one session can be built at the same time - a
// wallet retry, a reload, two tabs. If both callers generated, the second
// store would win and the first caller would already have returned a public
// key whose private half was gone: the wallet encrypts, and we cannot
// decrypt.
func TestGenerateAndStoreIfAbsent_Concurrent(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(5 * time.Minute)
	t.Cleanup(cache.Stop)

	const callers = 32
	var wg sync.WaitGroup
	thumbs := make([][]byte, callers)
	errs := make([]error, callers)

	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // maximise the overlap
			pub, err := cache.GenerateAndStoreIfAbsent("one-session")
			if err != nil {
				errs[i] = err
				return
			}
			thumbs[i], errs[i] = pub.Thumbprint(crypto.SHA256)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "caller %d", i)
	}

	// Every caller must have been handed the same key.
	for i := 1; i < callers; i++ {
		assert.Equal(t, thumbs[0], thumbs[i], "caller %d got a different public key", i)
	}

	// And it must be the pair of the one private key left in the cache.
	priv, found := cache.Get("one-session")
	require.True(t, found)
	privPub, err := priv.PublicKey()
	require.NoError(t, err)
	privThumb, err := privPub.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, thumbs[0], privThumb,
		"the advertised key must be the pair of the cached private key")
}
