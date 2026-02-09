package jose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
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

// makeJWTWithJWK creates a signed JWT with the public key embedded as a JWK in the header.
func makeJWTWithJWK(t *testing.T, privateKey *ecdsa.PrivateKey) string {
	t.Helper()

	// Build JWK from public key
	key, err := jwk.Import(&privateKey.PublicKey)
	require.NoError(t, err)
	jwkBytes, err := json.Marshal(key)
	require.NoError(t, err)

	var jwkMap map[string]any
	require.NoError(t, json.Unmarshal(jwkBytes, &jwkMap))

	header := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": jwkMap,
	}
	payload := map[string]any{
		"iss": "test",
		"iat": 1700000000,
	}

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)

	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	require.NoError(t, err)

	// Encode r and s as fixed-size big-endian (32 bytes each for P-256)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// makeRSAJWTWithJWK creates a signed JWT with an RSA public key embedded as a JWK in the header.
func makeRSAJWTWithJWK(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()

	// Build JWK from public key
	key, err := jwk.Import(&privateKey.PublicKey)
	require.NoError(t, err)
	jwkBytes, err := json.Marshal(key)
	require.NoError(t, err)

	var jwkMap map[string]any
	require.NoError(t, json.Unmarshal(jwkBytes, &jwkMap))

	header := map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": jwkMap,
	}
	payload := map[string]any{
		"iss": "test",
		"iat": 1700000000,
	}

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)

	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil))
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
}

func TestParseJWTWithJWKHeader(t *testing.T) {
	t.Run("parses JWT and returns base64url thumbprint", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		token := makeJWTWithJWK(t, privateKey)

		claims, tokenHeader, jwkHeader, thumbprint, err := ParseJWTWithJWKHeader(token)
		require.NoError(t, err)

		// Verify claims
		assert.Equal(t, "test", claims["iss"])

		// Verify headers
		assert.Equal(t, "ES256", tokenHeader["alg"])
		assert.Equal(t, "dpop+jwt", tokenHeader["typ"])
		assert.NotNil(t, jwkHeader)

		// Verify thumbprint is non-empty base64url (no hex chars like lowercase a-f without also being valid base64url)
		assert.NotEmpty(t, thumbprint)

		// Compute expected thumbprint independently
		key, err := jwk.Import(&privateKey.PublicKey)
		require.NoError(t, err)
		tp, err := key.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		expectedThumbprint := base64.RawURLEncoding.EncodeToString(tp)

		assert.Equal(t, expectedThumbprint, thumbprint, "thumbprint should be base64url-encoded per RFC 7638")

		// Verify it's valid base64url by decoding it
		decoded, err := base64.RawURLEncoding.DecodeString(thumbprint)
		require.NoError(t, err)
		assert.Len(t, decoded, 32, "SHA-256 thumbprint should be 32 bytes")
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		_, _, _, _, err := ParseJWTWithJWKHeader("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is empty")
	})

	t.Run("returns error for invalid JWT", func(t *testing.T) {
		_, _, _, _, err := ParseJWTWithJWKHeader("not.a.jwt")
		assert.Error(t, err)
	})

	t.Run("returns error for JWT without jwk header", func(t *testing.T) {
		// Create a valid JWT but without a jwk in the header
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "kid")
		require.NoError(t, err)

		token, err := MakeJWT(context.Background(), jwt.MapClaims{"typ": "JWT"}, jwt.MapClaims{"iss": "test"}, signer)
		require.NoError(t, err)

		_, _, _, _, err = ParseJWTWithJWKHeader(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid jwk in token header")
	})

	t.Run("parses RSA JWT with JWK header", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		token := makeRSAJWTWithJWK(t, rsaKey)

		claims, tokenHeader, jwkHeader, thumbprint, err := ParseJWTWithJWKHeader(token)
		require.NoError(t, err)

		assert.Equal(t, "test", claims["iss"])
		assert.Equal(t, "RS256", tokenHeader["alg"])
		assert.NotNil(t, jwkHeader)
		assert.NotEmpty(t, thumbprint)

		// Verify thumbprint is base64url encoded
		decoded, err := base64.RawURLEncoding.DecodeString(thumbprint)
		require.NoError(t, err)
		assert.Len(t, decoded, 32)
	})
}

func TestExtractClaim(t *testing.T) {
	t.Run("extracts existing claim", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "kid")
		require.NoError(t, err)

		token, err := MakeJWT(context.Background(), jwt.MapClaims{"typ": "JWT"}, jwt.MapClaims{
			"iss":   "test-issuer",
			"sub":   "test-subject",
			"nonce": "abc123",
		}, signer)
		require.NoError(t, err)

		value, err := ExtractClaim(token, "iss")
		require.NoError(t, err)
		assert.Equal(t, "test-issuer", value)

		value, err = ExtractClaim(token, "sub")
		require.NoError(t, err)
		assert.Equal(t, "test-subject", value)

		value, err = ExtractClaim(token, "nonce")
		require.NoError(t, err)
		assert.Equal(t, "abc123", value)
	})

	t.Run("returns error for missing claim", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "kid")
		require.NoError(t, err)

		token, err := MakeJWT(context.Background(), jwt.MapClaims{"typ": "JWT"}, jwt.MapClaims{
			"iss": "test",
		}, signer)
		require.NoError(t, err)

		_, err = ExtractClaim(token, "nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "claim \"nonexistent\" not found")
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		_, err := ExtractClaim("", "iss")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is empty")
	})

	t.Run("returns error for invalid token", func(t *testing.T) {
		_, err := ExtractClaim("not-a-jwt", "iss")
		assert.Error(t, err)
	})
}
