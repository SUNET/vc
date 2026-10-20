package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// proofWithClaims mints a real DPoP proof - signed, with the signing key's
// public JWK in the header - carrying whatever extra claims the caller
// wants alongside the required ones.
func proofWithClaims(t *testing.T, key *ecdsa.PrivateKey, extra map[string]any) string {
	t.Helper()

	claims := jwt.MapClaims{
		"jti": "regression-jti-0000000000",
		"iat": time.Now().Unix(),
		"htm": "POST",
		"htu": "https://issuer.example.com/token",
	}
	for name, value := range extra {
		claims[name] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"

	publicJWK, err := jwk.Import(&key.PublicKey)
	require.NoError(t, err)
	encoded, err := json.Marshal(publicJWK)
	require.NoError(t, err)
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(encoded, &asMap))
	token.Header["jwk"] = asMap

	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// The thumbprint is derived from the proof's own jwk HEADER - the key the
// signature was verified against - and every DPoP key-binding decision in
// this build compares it. A proof must therefore not be able to state it.
//
// It could. ValidateAndParseDPoPJWT decoded the payload into a struct that
// already held the derived value, into a field with a json name, so a
// proof signed by key B carrying {"thumbprint":"<A>"} came back claiming
// A's thumbprint - and encoding/json matches field names
// case-insensitively, so three spellings worked.
func TestValidateAndParseDPoPJWT_PayloadCannotStateTheThumbprint(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	honestA, err := ValidateAndParseDPoPJWT(proofWithClaims(t, keyA, nil))
	require.NoError(t, err)
	honestB, err := ValidateAndParseDPoPJWT(proofWithClaims(t, keyB, nil))
	require.NoError(t, err)

	// The fixture's precondition: two keys with two thumbprints, or the
	// assertions below could not tell impersonation from agreement.
	require.NotEmpty(t, honestA.Thumbprint)
	require.NotEqual(t, honestA.Thumbprint, honestB.Thumbprint)

	for _, name := range []string{"thumbprint", "Thumbprint", "THUMBPRINT", "thumbPrint"} {
		t.Run(name, func(t *testing.T) {
			forged, err := ValidateAndParseDPoPJWT(proofWithClaims(t, keyB, map[string]any{
				name: honestA.Thumbprint,
			}))
			require.NoError(t, err, "the proof is well formed; it is the claim that must not be honoured")

			assert.Equal(t, honestB.Thumbprint, forged.Thumbprint,
				"the thumbprint must come from the key that signed the proof")
			assert.NotEqual(t, honestA.Thumbprint, forged.Thumbprint,
				"a proof signed by B must never present A's thumbprint")
		})
	}

	// The header key is read the same way, and for the same reason.
	forged, err := ValidateAndParseDPoPJWT(proofWithClaims(t, keyB, map[string]any{
		"jwk": map[string]any{"kty": "oct", "k": "not-a-key"},
	}))
	require.NoError(t, err)
	require.NotNil(t, forged.JWK)
	assert.Equal(t, honestB.Thumbprint, forged.Thumbprint)
}
