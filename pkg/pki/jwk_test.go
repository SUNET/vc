package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

func TestPEM2jwk(t *testing.T) {
	_, publicKey := mockRSAKey(t)

	got, err := PEM2jwk(publicKey)
	assert.NoError(t, err, "PEM to JWK conversion should not return an error")

	b, err := json.Marshal(got)
	assert.NoError(t, err, "JSON marshaling should not return an error")

	fmt.Println("JWK:", string(b))

}
