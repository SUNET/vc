package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mockRSAKey(t *testing.T) ([]byte, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	privatePEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	publicKey := key.Public()
	publicPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(publicKey.(*rsa.PublicKey)),
		},
	)

	return privatePEM, publicPEM
}

// TestMockRSAKey verifies the mock key generation helper works correctly
func TestMockRSAKey(t *testing.T) {
	privatePEM, publicPEM := mockRSAKey(t)

	assert.NotEmpty(t, privatePEM, "Private key PEM should not be empty")
	assert.NotEmpty(t, publicPEM, "Public key PEM should not be empty")

	// Verify PEM blocks are valid
	privBlock, _ := pem.Decode(privatePEM)
	assert.NotNil(t, privBlock, "Private key PEM block should be valid")
	assert.Equal(t, "RSA PRIVATE KEY", privBlock.Type)

	pubBlock, _ := pem.Decode(publicPEM)
	assert.NotNil(t, pubBlock, "Public key PEM block should be valid")
	assert.Equal(t, "RSA PUBLIC KEY", pubBlock.Type)
}
