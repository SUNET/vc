package pki

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyLoader(t *testing.T) {
	kl := NewKeyLoader()
	assert.NotNil(t, kl)
	assert.Nil(t, kl.CryptoExt)
}

func TestNewKeyLoaderWithExtensions(t *testing.T) {
	ext := cryptoutil.New()
	kl := NewKeyLoaderWithExtensions(ext)

	assert.NotNil(t, kl)
	assert.Same(t, ext, kl.CryptoExt)
}

func TestKeyLoader_LoadCertificateChain_WithExtensions(t *testing.T) {
	// Create a temporary certificate file
	testCert := generateTestCert(t)
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test-chain.pem")

	// Write PEM-encoded certificate using pem.EncodeToMemory
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: testCert.Raw,
	})

	err := os.WriteFile(certPath, certPEM, 0o600)
	require.NoError(t, err)

	tests := []struct {
		name      string
		kl        *KeyLoader
		wantCerts int
	}{
		{
			name:      "with nil extensions",
			kl:        NewKeyLoader(),
			wantCerts: 1,
		},
		{
			name:      "with configured extensions",
			kl:        NewKeyLoaderWithExtensions(cryptoutil.New()),
			wantCerts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, pemBlocks, err := tt.kl.LoadCertificateChain(certPath)
			require.NoError(t, err)
			assert.Len(t, certs, tt.wantCerts)
			assert.Len(t, pemBlocks, tt.wantCerts)
			assert.Equal(t, testCert.Subject.CommonName, certs[0].Subject.CommonName)
		})
	}
}

func TestKeyLoader_LoadCertificateChain_InvalidFile(t *testing.T) {
	kl := NewKeyLoaderWithExtensions(cryptoutil.New())

	_, _, err := kl.LoadCertificateChain("/nonexistent/path/cert.pem")
	assert.Error(t, err)
}

func TestKeyLoader_LoadCertificateChain_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "empty.pem")

	err := os.WriteFile(certPath, []byte(""), 0o600)
	require.NoError(t, err)

	kl := NewKeyLoader()
	_, _, err = kl.LoadCertificateChain(certPath)
	assert.Error(t, err)
}

func TestKeyLoader_LoadCertificateChain_NoCerts(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "no-certs.pem")

	// Write a file with no valid PEM blocks
	err := os.WriteFile(certPath, []byte("not a pem file\n"), 0o600)
	require.NoError(t, err)

	kl := NewKeyLoader()
	_, _, err = kl.LoadCertificateChain(certPath)
	assert.Error(t, err)
}
