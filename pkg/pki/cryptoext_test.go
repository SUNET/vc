package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestParseCertificate(t *testing.T) {
	testCert := generateTestCert(t)

	tests := []struct {
		name    string
		der     []byte
		ext     *cryptoutil.Extensions
		wantErr bool
	}{
		{
			name:    "nil extensions - standard parsing",
			der:     testCert.Raw,
			ext:     nil,
			wantErr: false,
		},
		{
			name:    "empty extensions - fallback to standard",
			der:     testCert.Raw,
			ext:     &cryptoutil.Extensions{},
			wantErr: false,
		},
		{
			name:    "valid DER with extensions",
			der:     testCert.Raw,
			ext:     cryptoutil.New(),
			wantErr: false,
		},
		{
			name:    "invalid DER - nil extensions",
			der:     []byte("not-a-certificate"),
			ext:     nil,
			wantErr: true,
		},
		{
			name:    "invalid DER - with extensions",
			der:     []byte("not-a-certificate"),
			ext:     cryptoutil.New(),
			wantErr: true,
		},
		{
			name:    "empty DER",
			der:     []byte{},
			ext:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseCertificate(tt.der, tt.ext)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cert)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, cert)
			// Verify it's the same certificate
			if len(tt.der) > 0 && !tt.wantErr {
				assert.Equal(t, testCert.Subject.CommonName, cert.Subject.CommonName)
			}
		})
	}
}

func TestParseCertificate_Nil(t *testing.T) {
	// Test that nil DER returns error
	cert, err := ParseCertificate(nil, nil)
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestParseCertificate_ExtensionsNilFallback(t *testing.T) {
	testCert := generateTestCert(t)

	// Should fall back to stdlib when ext is nil
	cert, err := ParseCertificate(testCert.Raw, nil)
	require.NoError(t, err)
	assert.Equal(t, testCert.SerialNumber, cert.SerialNumber)
}

func TestParseCertificate_WithConfiguredExtensions(t *testing.T) {
	testCert := generateTestCert(t)

	// Create extensions with registered parsers
	ext := cryptoutil.New()

	cert, err := ParseCertificate(testCert.Raw, ext)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, testCert.Subject.CommonName, cert.Subject.CommonName)
}
