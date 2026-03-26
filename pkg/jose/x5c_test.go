package jose

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

	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseX5CHeader(t *testing.T) {
	// Generate a test certificate
	testCert := generateTestCertificate(t)
	certB64 := base64.StdEncoding.EncodeToString(testCert.Raw)
	certB64URL := base64.RawURLEncoding.EncodeToString(testCert.Raw)

	tests := []struct {
		name        string
		x5cRaw      any
		wantCerts   int
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid single cert standard base64",
			x5cRaw:    []any{certB64},
			wantCerts: 1,
			wantErr:   false,
		},
		{
			name:      "valid single cert URL-safe base64",
			x5cRaw:    []any{certB64URL},
			wantCerts: 1,
			wantErr:   false,
		},
		{
			name:      "valid multiple certs",
			x5cRaw:    []any{certB64, certB64},
			wantCerts: 2,
			wantErr:   false,
		},
		{
			name:        "not an array",
			x5cRaw:      "not-an-array",
			wantErr:     true,
			errContains: "must be an array",
		},
		{
			name:        "empty array",
			x5cRaw:      []any{},
			wantErr:     true,
			errContains: "x5c header is empty",
		},
		{
			name:        "array element not string",
			x5cRaw:      []any{12345},
			wantErr:     true,
			errContains: "is not a string",
		},
		{
			name:        "invalid base64",
			x5cRaw:      []any{"!!!invalid!!!"},
			wantErr:     true,
			errContains: "failed to decode",
		},
		{
			name:        "valid base64 but not a certificate",
			x5cRaw:      []any{base64.StdEncoding.EncodeToString([]byte("not-a-cert"))},
			wantErr:     true,
			errContains: "failed to parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := ParseX5CHeader(tt.x5cRaw)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Len(t, certs, tt.wantCerts)
		})
	}
}

func TestParseJWKToPublicKey(t *testing.T) {
	// EC key JWK
	ecJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "WbbNmyzJRUEXswvo9hJlLPBOl2v0PMAG9dKdHaJgz0U",
		"y":   "f6pSW-KtJsmMPlKbPV3sL1zPPLQCf6D3MT0DW-jIEjI",
	}

	// RSA key JWK
	rsaJWK := map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	}

	tests := []struct {
		name        string
		jwkData     any
		wantKeyType string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid EC JWK map",
			jwkData:     ecJWK,
			wantKeyType: "*ecdsa.PublicKey",
			wantErr:     false,
		},
		{
			name:        "valid RSA JWK map",
			jwkData:     rsaJWK,
			wantKeyType: "*rsa.PublicKey",
			wantErr:     false,
		},
		{
			name:        "invalid type",
			jwkData:     "not-a-map",
			wantErr:     true,
			errContains: "must be map[string]any or []byte",
		},
		{
			name:        "invalid JWK content",
			jwkData:     map[string]any{"invalid": "jwk"},
			wantErr:     true,
			errContains: "failed to parse jwk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := ParseJWKToPublicKey(tt.jwkData)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, pubKey)

			switch tt.wantKeyType {
			case "*ecdsa.PublicKey":
				_, ok := pubKey.(*ecdsa.PublicKey)
				assert.True(t, ok, "expected *ecdsa.PublicKey")
			case "*rsa.PublicKey":
				_, ok := pubKey.(*rsa.PublicKey)
				assert.True(t, ok, "expected *rsa.PublicKey")
			}
		})
	}
}

// generateTestCertificate creates a self-signed test certificate
func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestParseX5CHeader_WithExtensions(t *testing.T) {
	testCert := generateTestCertificate(t)
	certB64 := base64.StdEncoding.EncodeToString(testCert.Raw)

	tests := []struct {
		name      string
		x5cRaw    any
		ext       *cryptoutil.Extensions
		wantCerts int
		wantErr   bool
	}{
		{
			name:      "valid cert with nil extensions",
			x5cRaw:    []any{certB64},
			ext:       nil,
			wantCerts: 1,
			wantErr:   false,
		},
		{
			name:      "valid cert with empty extensions",
			x5cRaw:    []any{certB64},
			ext:       &cryptoutil.Extensions{},
			wantCerts: 1,
			wantErr:   false,
		},
		{
			name:      "valid cert with configured extensions",
			x5cRaw:    []any{certB64},
			ext:       cryptoutil.New(),
			wantCerts: 1,
			wantErr:   false,
		},
		{
			name:      "multiple certs with extensions",
			x5cRaw:    []any{certB64, certB64},
			ext:       cryptoutil.New(),
			wantCerts: 2,
			wantErr:   false,
		},
		{
			name:    "invalid cert with extensions still fails",
			x5cRaw:  []any{base64.StdEncoding.EncodeToString([]byte("not-a-cert"))},
			ext:     cryptoutil.New(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var certs []*x509.Certificate
			var err error

			if tt.ext != nil {
				certs, err = ParseX5CHeader(tt.x5cRaw, tt.ext)
			} else {
				certs, err = ParseX5CHeader(tt.x5cRaw)
			}

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, certs, tt.wantCerts)

			// Verify certificate content
			for _, cert := range certs {
				assert.Equal(t, testCert.Subject.CommonName, cert.Subject.CommonName)
			}
		})
	}
}

func TestParseX5CHeader_ExtensionVariadic(t *testing.T) {
	testCert := generateTestCertificate(t)
	certB64 := base64.StdEncoding.EncodeToString(testCert.Raw)

	// Test that variadic with nil first element falls back properly
	ext := cryptoutil.New()

	// Call with extension
	certs, err := ParseX5CHeader([]any{certB64}, ext)
	require.NoError(t, err)
	assert.Len(t, certs, 1)

	// Call without extension (no variadic args)
	certs2, err := ParseX5CHeader([]any{certB64})
	require.NoError(t, err)
	assert.Len(t, certs2, 1)

	// Both should return equivalent certificates
	assert.Equal(t, certs[0].Subject.CommonName, certs2[0].Subject.CommonName)
}
