package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMongoClientOptions_URIOnly(t *testing.T) {
	m := Mongo{URI: "mongodb://localhost:27017"}
	opts, err := m.MongoClientOptions()
	require.NoError(t, err)
	assert.NotNil(t, opts)
	assert.Nil(t, opts.TLSConfig, "TLSConfig should be nil when TLS is not configured")
}

func TestMongoClientOptions_TLSWithCA(t *testing.T) {
	caPath := writeTempCA(t)

	m := Mongo{
		URI:        "mongodb://localhost:27017",
		TLS:        true,
		CAFilePath: caPath,
	}
	opts, err := m.MongoClientOptions()
	require.NoError(t, err)
	require.NotNil(t, opts.TLSConfig, "TLSConfig should be set when TLS is enabled")
	assert.NotNil(t, opts.TLSConfig.RootCAs, "RootCAs should be populated from CA file")
	assert.Empty(t, opts.TLSConfig.Certificates, "Certificates should be empty without mTLS")
}

func TestMongoClientOptions_MTLS(t *testing.T) {
	caPath := writeTempCA(t)
	certPath, keyPath := writeTempCertKey(t)

	m := Mongo{
		URI:          "mongodb://localhost:27017",
		TLS:          true,
		CAFilePath:   caPath,
		CertFilePath: certPath,
		KeyFilePath:  keyPath,
	}
	opts, err := m.MongoClientOptions()
	require.NoError(t, err)
	require.NotNil(t, opts.TLSConfig, "TLSConfig should be set for mTLS")
	assert.NotNil(t, opts.TLSConfig.RootCAs, "RootCAs should be populated from CA file")
	assert.Len(t, opts.TLSConfig.Certificates, 1, "Certificates should contain the client cert")
}

func TestMongoClientOptions_ImplicitTLS(t *testing.T) {
	caPath := writeTempCA(t)

	m := Mongo{
		URI:        "mongodb://localhost:27017",
		CAFilePath: caPath,
	}
	// TLS is false but CAFilePath is set, so TLS should be configured implicitly.
	opts, err := m.MongoClientOptions()
	require.NoError(t, err)
	require.NotNil(t, opts.TLSConfig, "TLSConfig should be set when CAFilePath implies TLS")
	assert.NotNil(t, opts.TLSConfig.RootCAs, "RootCAs should be populated from CA file")
}

func TestMongoClientOptions_CertWithoutKey(t *testing.T) {
	m := Mongo{
		URI:          "mongodb://localhost:27017",
		TLS:          true,
		CertFilePath: "/some/cert.crt",
	}
	opts, err := m.MongoClientOptions()
	require.NoError(t, err)
	require.NotNil(t, opts.TLSConfig, "TLSConfig should be set when TLS is enabled")
	assert.Empty(t, opts.TLSConfig.Certificates, "Certificates should be empty when only CertFilePath is set")
}

func TestMongoClientOptions_KeyWithoutCert(t *testing.T) {
	m := Mongo{
		URI:         "mongodb://localhost:27017",
		TLS:         true,
		KeyFilePath: "/some/key.pem",
	}
	opts, err := m.MongoClientOptions()
	require.NoError(t, err)
	require.NotNil(t, opts.TLSConfig, "TLSConfig should be set when TLS is enabled")
	assert.Empty(t, opts.TLSConfig.Certificates, "Certificates should be empty when only KeyFilePath is set")
}

func TestMongoClientOptions_MissingCAFile(t *testing.T) {
	m := Mongo{
		URI:        "mongodb://localhost:27017",
		TLS:        true,
		CAFilePath: "/nonexistent/ca.crt",
	}
	_, err := m.MongoClientOptions()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA file")
}

func TestMongoClientOptions_InvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "bad_ca.crt")
	require.NoError(t, os.WriteFile(caPath, []byte("not a PEM cert"), 0600))

	m := Mongo{
		URI:        "mongodb://localhost:27017",
		TLS:        true,
		CAFilePath: caPath,
	}
	_, err := m.MongoClientOptions()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid PEM certificates")
}

func TestMongoClientOptions_MissingCertFile(t *testing.T) {
	m := Mongo{
		URI:          "mongodb://localhost:27017",
		TLS:          true,
		CertFilePath: "/nonexistent/cert.crt",
		KeyFilePath:  "/nonexistent/key.pem",
	}
	_, err := m.MongoClientOptions()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load client certificate/key")
}

// --- helpers ---

func writeTempCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, os.WriteFile(caPath, certPEM, 0600))

	return caPath
}

func writeTempCertKey(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "client.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "client.key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	return certPath, keyPath
}
