package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// createTestECKey generates an EC P-256 key in SEC1 format and returns the file path
func createTestECKey(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_ec_key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0o600))

	return keyPath
}

// createTestECKeyPKCS8 generates an EC P-256 key in PKCS8 format and returns the file path
func createTestECKeyPKCS8(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_ec_key_pkcs8.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0o600))

	return keyPath
}

// createTestRSAKey generates an RSA 2048-bit key in PKCS1 format and returns the file path
func createTestRSAKey(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_rsa_key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0o600))

	return keyPath
}

// createTestRSAKeyPKCS8 generates an RSA 2048-bit key in PKCS8 format and returns the file path
func createTestRSAKeyPKCS8(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_rsa_key_pkcs8.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0o600))

	return keyPath
}

// createInvalidKeyFile creates an invalid key file and returns the file path
func createInvalidKeyFile(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid_key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("not a valid key"), 0o600))

	return keyPath
}
