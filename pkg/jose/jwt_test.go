package jose

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeJWT(t *testing.T) {
	t.Run("creates signed JWT with EC key", func(t *testing.T) {
		keyPath := createTestECKey(t)

		privateKey, err := ParseSigningKey(keyPath)
		require.NoError(t, err)

		ecKey := privateKey.(*ecdsa.PrivateKey)

		// Create pki.Signer
		signer, err := pki.NewSoftwareSigner(ecKey, "key-1")
		require.NoError(t, err)

		header := jwt.MapClaims{
			"typ": "openid4vci-proof+jwt",
		}
		body := jwt.MapClaims{
			"iss":   "joe",
			"aud":   "https://example.com",
			"iat":   1300819380,
			"nonce": "n-0S6_WzA2Mj",
		}

		signedToken, err := MakeJWT(context.Background(), header, body, signer)
		require.NoError(t, err)
		assert.NotEmpty(t, signedToken)

		// Verify the token can be parsed
		token, err := jwt.Parse(signedToken, func(token *jwt.Token) (any, error) {
			return &ecKey.PublicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("creates signed JWT with RSA key", func(t *testing.T) {
		keyPath := createTestRSAKey(t)

		privateKey, err := ParseSigningKey(keyPath)
		require.NoError(t, err)

		rsaKey := privateKey.(*rsa.PrivateKey)

		// Create pki.Signer
		signer, err := pki.NewSoftwareSigner(rsaKey, "rsa-key-1")
		require.NoError(t, err)

		header := jwt.MapClaims{
			"typ": "JWT",
		}
		body := jwt.MapClaims{
			"iss":   "joe",
			"aud":   "https://example.com",
			"iat":   1300819380,
			"nonce": "n-0S6_WzA2Mj",
		}

		signedToken, err := MakeJWT(context.Background(), header, body, signer)
		require.NoError(t, err)
		assert.NotEmpty(t, signedToken)

		// Verify the token can be parsed
		token, err := jwt.Parse(signedToken, func(token *jwt.Token) (any, error) {
			return &rsaKey.PublicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("returns error for nil signer", func(t *testing.T) {
		header := jwt.MapClaims{"typ": "JWT"}
		body := jwt.MapClaims{"iss": "test"}

		_, err := MakeJWT(context.Background(), header, body, nil)
		assert.Error(t, err)
	})

	t.Run("returns error for invalid key in signer creation", func(t *testing.T) {
		// Try to create a signer with an invalid key type
		_, err := pki.NewSoftwareSigner("not-a-key", "test-kid")
		assert.Error(t, err)
	})
}

func TestGetSigningMethodFromKey_RSA(t *testing.T) {
	t.Run("RSA_2048_returns_RS256", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		method, alg := GetSigningMethodFromKey(key)

		assert.Equal(t, jwt.SigningMethodRS256, method)
		assert.Equal(t, "RS256", alg)
	})

	t.Run("RSA_3072_returns_RS384", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		require.NoError(t, err)

		method, alg := GetSigningMethodFromKey(key)

		assert.Equal(t, jwt.SigningMethodRS384, method)
		assert.Equal(t, "RS384", alg)
	})

	t.Run("RSA_4096_returns_RS512", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		require.NoError(t, err)

		method, alg := GetSigningMethodFromKey(key)

		assert.Equal(t, jwt.SigningMethodRS512, method)
		assert.Equal(t, "RS512", alg)
	})
}

func TestGetSigningMethodFromKey_ECDSA(t *testing.T) {
	t.Run("P256_returns_ES256", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		method, alg := GetSigningMethodFromKey(key)

		assert.Equal(t, jwt.SigningMethodES256, method)
		assert.Equal(t, "ES256", alg)
	})

	t.Run("P384_returns_ES384", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		method, alg := GetSigningMethodFromKey(key)

		assert.Equal(t, jwt.SigningMethodES384, method)
		assert.Equal(t, "ES384", alg)
	})

	t.Run("P521_returns_ES512", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		method, alg := GetSigningMethodFromKey(key)

		assert.Equal(t, jwt.SigningMethodES512, method)
		assert.Equal(t, "ES512", alg)
	})
}

func TestGetSigningMethodFromKey_UnknownKeyType(t *testing.T) {
	t.Run("string_defaults_to_ES256", func(t *testing.T) {
		method, alg := GetSigningMethodFromKey("not a key")

		assert.Equal(t, jwt.SigningMethodES256, method)
		assert.Equal(t, "ES256", alg)
	})

	t.Run("int_defaults_to_ES256", func(t *testing.T) {
		method, alg := GetSigningMethodFromKey(12345)

		assert.Equal(t, jwt.SigningMethodES256, method)
		assert.Equal(t, "ES256", alg)
	})

	t.Run("nil_defaults_to_ES256", func(t *testing.T) {
		method, alg := GetSigningMethodFromKey(nil)

		assert.Equal(t, jwt.SigningMethodES256, method)
		assert.Equal(t, "ES256", alg)
	})
}
