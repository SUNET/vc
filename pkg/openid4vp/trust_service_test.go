package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustService_ExtractPublicKeyFromX5C(t *testing.T) {
	ts := &TrustService{}

	t.Run("valid RSA certificate", func(t *testing.T) {
		// Generate RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Create certificate template
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   "Test RSA Certificate",
				Organization: []string{"Test Org"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		// Create self-signed certificate
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		// Encode to base64
		certBase64 := base64.StdEncoding.EncodeToString(certDER)

		// Test extraction
		pubKey, err := ts.ExtractPublicKeyFromX5C(certBase64)
		require.NoError(t, err)
		assert.NotNil(t, pubKey)

		// Verify it's an RSA public key
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		assert.True(t, ok, "Expected RSA public key")
		assert.NotNil(t, rsaPubKey)
		assert.Equal(t, privateKey.PublicKey.N, rsaPubKey.N)
	})

	t.Run("valid ECDSA certificate", func(t *testing.T) {
		// Generate ECDSA key pair
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create certificate template
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName:   "Test ECDSA Certificate",
				Organization: []string{"Test Org"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		// Create self-signed certificate
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		// Encode to base64
		certBase64 := base64.StdEncoding.EncodeToString(certDER)

		// Test extraction
		pubKey, err := ts.ExtractPublicKeyFromX5C(certBase64)
		require.NoError(t, err)
		assert.NotNil(t, pubKey)

		// Verify it's an ECDSA public key
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		assert.True(t, ok, "Expected ECDSA public key")
		assert.NotNil(t, ecdsaPubKey)
		assert.Equal(t, privateKey.PublicKey.X, ecdsaPubKey.X)
		assert.Equal(t, privateKey.PublicKey.Y, ecdsaPubKey.Y)
	})

	t.Run("invalid base64", func(t *testing.T) {
		invalidBase64 := "not-valid-base64!!!"

		pubKey, err := ts.ExtractPublicKeyFromX5C(invalidBase64)
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to decode base64 x5c certificate")
	})

	t.Run("invalid certificate data", func(t *testing.T) {
		// Valid base64 but invalid certificate
		invalidCert := base64.StdEncoding.EncodeToString([]byte("not a certificate"))

		pubKey, err := ts.ExtractPublicKeyFromX5C(invalidCert)
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})

	t.Run("empty string", func(t *testing.T) {
		pubKey, err := ts.ExtractPublicKeyFromX5C("")
		assert.Error(t, err)
		assert.Nil(t, pubKey)
	})

	t.Run("corrupted certificate", func(t *testing.T) {
		// Create a valid certificate first
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject: pkix.Name{
				CommonName: "Test",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		// Corrupt the certificate data
		corrupted := append(certDER[:len(certDER)/2], []byte("corrupted")...)
		corruptedBase64 := base64.StdEncoding.EncodeToString(corrupted)

		pubKey, err := ts.ExtractPublicKeyFromX5C(corruptedBase64)
		assert.Error(t, err)
		assert.Nil(t, pubKey)
	})
}

func TestTrustService_Creation(t *testing.T) {
	ts := &TrustService{}
	assert.NotNil(t, ts)
}
