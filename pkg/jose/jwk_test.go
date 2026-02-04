package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"testing"
	"vc/pkg/pki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		keyBytes, err := os.ReadFile(keyPath)
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
		keyBytes, err := os.ReadFile(keyPath)
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
}
