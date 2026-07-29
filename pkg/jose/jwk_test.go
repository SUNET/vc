package jose

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/SUNET/vc/pkg/pki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSigner implements pki.Signer for testing error paths.
type mockSigner struct {
	publicKey any
	algorithm string
	keyID     string
}

func (m *mockSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockSigner) Algorithm() string { return m.algorithm }
func (m *mockSigner) KeyID() string     { return m.keyID }
func (m *mockSigner) PublicKey() any    { return m.publicKey }

func TestParseSigningKey(t *testing.T) {
	t.Run("parses EC key SEC1 format", func(t *testing.T) {
		keyPath := createTestECKey(t)
		key, err := ParseSigningKey(keyPath)
		require.NoError(t, err)
		assert.NotNil(t, key)
		_, ok := key.(*ecdsa.PrivateKey)
		assert.True(t, ok, "expected *ecdsa.PrivateKey")
	})

	t.Run("parses EC key PKCS8 format", func(t *testing.T) {
		keyPath := createTestECKeyPKCS8(t)
		key, err := ParseSigningKey(keyPath)
		require.NoError(t, err)
		assert.NotNil(t, key)
		_, ok := key.(*ecdsa.PrivateKey)
		assert.True(t, ok, "expected *ecdsa.PrivateKey")
	})

	t.Run("parses RSA key PKCS1 format (RSA PRIVATE KEY)", func(t *testing.T) {
		keyPath := createTestRSAKey(t)

		// Verify the key file has the expected PEM block type
		keyBytes, err := os.ReadFile(keyPath) // #nosec G304
		require.NoError(t, err)
		block, _ := pem.Decode(keyBytes)
		require.NotNil(t, block)
		assert.Equal(t, "RSA PRIVATE KEY", block.Type, "expected PKCS1 format with RSA PRIVATE KEY block type")

		key, err := ParseSigningKey(keyPath)
		require.NoError(t, err)
		assert.NotNil(t, key)
		_, ok := key.(*rsa.PrivateKey)
		assert.True(t, ok, "expected *rsa.PrivateKey")
	})

	t.Run("parses RSA key PKCS8 format (PRIVATE KEY)", func(t *testing.T) {
		keyPath := createTestRSAKeyPKCS8(t)

		// Verify the key file has the expected PEM block type
		keyBytes, err := os.ReadFile(keyPath) // #nosec G304
		require.NoError(t, err)
		block, _ := pem.Decode(keyBytes)
		require.NotNil(t, block)
		assert.Equal(t, "PRIVATE KEY", block.Type, "expected PKCS8 format with PRIVATE KEY block type")

		key, err := ParseSigningKey(keyPath)
		require.NoError(t, err)
		assert.NotNil(t, key)
		_, ok := key.(*rsa.PrivateKey)
		assert.True(t, ok, "expected *rsa.PrivateKey")
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		_, err := ParseSigningKey("/non/existent/path.pem")
		assert.Error(t, err)
	})

	t.Run("returns error for invalid key", func(t *testing.T) {
		keyPath := createInvalidKeyFile(t)
		_, err := ParseSigningKey(keyPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key type")
	})
}

func TestCreateJWKSFromSigner(t *testing.T) {
	t.Run("returns error for nil signer", func(t *testing.T) {
		_, err := CreateJWKSFromSigner(nil, "sig")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signer must not be nil")
	})

	t.Run("creates JWKS from RSA signer", func(t *testing.T) {
		keyPath := createTestRSAKey(t)
		privateKey, err := ParseSigningKey(keyPath)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "test-key-id")
		require.NoError(t, err)

		jwks, err := CreateJWKSFromSigner(signer, "")
		require.NoError(t, err)
		require.NotNil(t, jwks)
		require.Len(t, jwks.Keys, 1)

		key := jwks.Keys[0]
		assert.Equal(t, "RSA", key.Kty)
		assert.Equal(t, "sig", key.Use)
		assert.Equal(t, "test-key-id", key.Kid)
		assert.Equal(t, "RS256", key.Alg)
		assert.NotEmpty(t, key.N)
		assert.NotEmpty(t, key.E)
		assert.Empty(t, key.Crv)
		assert.Empty(t, key.X)
		assert.Empty(t, key.Y)
	})

	t.Run("creates JWKS from ECDSA signer", func(t *testing.T) {
		keyPath := createTestECKey(t)
		privateKey, err := ParseSigningKey(keyPath)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "ec-key-id")
		require.NoError(t, err)

		jwks, err := CreateJWKSFromSigner(signer, "")
		require.NoError(t, err)
		require.NotNil(t, jwks)
		require.Len(t, jwks.Keys, 1)

		key := jwks.Keys[0]
		assert.Equal(t, "EC", key.Kty)
		assert.Equal(t, "sig", key.Use)
		assert.Equal(t, "ec-key-id", key.Kid)
		assert.Equal(t, "ES256", key.Alg)
		assert.Equal(t, "P-256", key.Crv)
		assert.NotEmpty(t, key.X)
		assert.NotEmpty(t, key.Y)
		assert.Empty(t, key.N)
		assert.Empty(t, key.E)
	})

	t.Run("uses custom keyUsage when provided", func(t *testing.T) {
		keyPath := createTestECKey(t)
		privateKey, err := ParseSigningKey(keyPath)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "enc-key")
		require.NoError(t, err)

		jwks, err := CreateJWKSFromSigner(signer, "enc")
		require.NoError(t, err)
		require.NotNil(t, jwks)
		require.Len(t, jwks.Keys, 1)
		assert.Equal(t, "enc", jwks.Keys[0].Use)
	})

	t.Run("JWKS marshals to valid JSON", func(t *testing.T) {
		keyPath := createTestECKey(t)
		privateKey, err := ParseSigningKey(keyPath)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "json-key")
		require.NoError(t, err)

		jwks, err := CreateJWKSFromSigner(signer, "sig")
		require.NoError(t, err)

		jwksJSON, err := json.Marshal(jwks)
		require.NoError(t, err)

		var parsed JWKS
		err = json.Unmarshal(jwksJSON, &parsed)
		require.NoError(t, err)
		require.Len(t, parsed.Keys, 1)
		assert.Equal(t, "json-key", parsed.Keys[0].Kid)
		assert.Equal(t, "EC", parsed.Keys[0].Kty)
	})

	t.Run("creates JWKS from RSA PKCS8 signer", func(t *testing.T) {
		keyPath := createTestRSAKeyPKCS8(t)
		privateKey, err := ParseSigningKey(keyPath)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "rsa-pkcs8-key")
		require.NoError(t, err)

		jwks, err := CreateJWKSFromSigner(signer, "sig")
		require.NoError(t, err)
		require.NotNil(t, jwks)
		require.Len(t, jwks.Keys, 1)

		key := jwks.Keys[0]
		assert.Equal(t, "RSA", key.Kty)
		assert.Equal(t, "sig", key.Use)
		assert.Equal(t, "rsa-pkcs8-key", key.Kid)
		assert.NotEmpty(t, key.N)
		assert.NotEmpty(t, key.E)
	})

	t.Run("creates JWKS from EC P-384 signer", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		signer, err := pki.NewSoftwareSigner(privateKey, "p384-key")
		require.NoError(t, err)

		jwks, err := CreateJWKSFromSigner(signer, "")
		require.NoError(t, err)
		require.NotNil(t, jwks)
		require.Len(t, jwks.Keys, 1)

		key := jwks.Keys[0]
		assert.Equal(t, "EC", key.Kty)
		assert.Equal(t, "P-384", key.Crv)
		assert.Equal(t, "ES384", key.Alg)
		assert.Equal(t, "sig", key.Use)
	})

	t.Run("returns error for nil public key", func(t *testing.T) {
		mock := &mockSigner{
			publicKey: nil,
			algorithm: "ES256",
			keyID:     "nil-key",
		}
		_, err := CreateJWKSFromSigner(mock, "sig")
		assert.Error(t, err)
	})

	t.Run("returns error for unsupported public key type", func(t *testing.T) {
		mock := &mockSigner{
			publicKey: "not-a-real-key",
			algorithm: "ES256",
			keyID:     "bad-key",
		}
		_, err := CreateJWKSFromSigner(mock, "sig")
		assert.Error(t, err)
	})
}

func TestParseJWK(t *testing.T) {
	t.Run("parses EC JWK map", func(t *testing.T) {
		jwkMap := map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
			"kid": "test-kid",
			"alg": "ES256",
			"use": "sig",
		}

		result, err := ParseJWK(jwkMap)
		require.NoError(t, err)
		assert.Equal(t, "EC", result.Kty)
		assert.Equal(t, "P-256", result.Crv)
		assert.Equal(t, "test-kid", result.Kid)
		assert.Equal(t, "ES256", result.Alg)
		assert.Equal(t, "sig", result.Use)
		assert.NotEmpty(t, result.X)
		assert.NotEmpty(t, result.Y)
	})

	t.Run("parses RSA JWK map", func(t *testing.T) {
		jwkMap := map[string]any{
			"kty": "RSA",
			"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			"e":   "AQAB",
			"kid": "rsa-kid",
			"alg": "RS256",
		}

		result, err := ParseJWK(jwkMap)
		require.NoError(t, err)
		assert.Equal(t, "RSA", result.Kty)
		assert.Equal(t, "rsa-kid", result.Kid)
		assert.Equal(t, "RS256", result.Alg)
		assert.NotEmpty(t, result.N)
		assert.NotEmpty(t, result.E)
	})

	t.Run("parses minimal JWK map", func(t *testing.T) {
		jwkMap := map[string]any{
			"kty": "EC",
		}

		result, err := ParseJWK(jwkMap)
		require.NoError(t, err)
		assert.Equal(t, "EC", result.Kty)
	})
}
