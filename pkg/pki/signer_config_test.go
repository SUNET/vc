package pki_test

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

	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

// Helper to create a test key and certificate
func createTestKeyPair(t *testing.T, keyPath, certPath string) {
	t.Helper()

	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Write private key
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Write certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write certificate: %v", err)
	}
}

func TestSignerConfig_FileBasedSigning(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")
	certPath := filepath.Join(tmpDir, "test-cert.pem")

	// Create test key pair
	createTestKeyPair(t, keyPath, certPath)

	// Create SignerConfig
	config := pki.NewSignerConfig(&pki.KeyConfig{
		PrivateKeyPath: keyPath,
		ChainPath:      certPath,
	})

	// Test signing arbitrary data
	t.Run("Sign", func(t *testing.T) {
		data := []byte("test data to sign")
		signature, err := config.Sign(data)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		if len(signature) == 0 {
			t.Fatal("signature is empty")
		}
	})

	// Test JWT signing
	t.Run("SignJWT", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "user123",
			"iss": "test-service",
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token, err := config.SignJWT(claims)
		if err != nil {
			t.Fatalf("failed to sign JWT: %v", err)
		}
		if token == "" {
			t.Fatal("token is empty")
		}

		// Verify token structure
		_, _, err = jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("failed to parse JWT: %v", err)
		}
	})

	// Test GetJWK
	t.Run("GetJWK", func(t *testing.T) {
		jwk, err := config.GetJWK()
		if err != nil {
			t.Fatalf("failed to get JWK: %v", err)
		}
		if jwk.Algorithm != "ES256" {
			t.Errorf("expected algorithm ES256, got %s", jwk.Algorithm)
		}
		if jwk.Use != "sig" {
			t.Errorf("expected use 'sig', got %s", jwk.Use)
		}
	})

	// Test GetCertificate
	t.Run("GetCertificate", func(t *testing.T) {
		cert, err := config.GetCertificate()
		if err != nil {
			t.Fatalf("failed to get certificate: %v", err)
		}
		if cert.Subject.CommonName != "Test Certificate" {
			t.Errorf("unexpected certificate subject: %s", cert.Subject.CommonName)
		}
	})
}

func TestSignerConfig_LazyLoading(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")
	certPath := filepath.Join(tmpDir, "test-cert.pem")

	// Create test key pair
	createTestKeyPair(t, keyPath, certPath)

	// Create SignerConfig
	config := pki.NewSignerConfig(&pki.KeyConfig{
		PrivateKeyPath: keyPath,
		ChainPath:      certPath,
	})

	// Keys should not be loaded yet (we can't directly test this, but we test the behavior)

	// First operation should load keys
	_, err := config.Sign([]byte("test"))
	if err != nil {
		t.Fatalf("failed to sign on first call: %v", err)
	}

	// Subsequent operations should reuse loaded keys
	_, err = config.Sign([]byte("test2"))
	if err != nil {
		t.Fatalf("failed to sign on second call: %v", err)
	}

	// Different operation should also work
	_, err = config.GetJWK()
	if err != nil {
		t.Fatalf("failed to get JWK: %v", err)
	}
}

func TestSignerConfig_InvalidConfig(t *testing.T) {
	// Config with non-existent key file
	config := pki.NewSignerConfig(&pki.KeyConfig{
		PrivateKeyPath: "/nonexistent/key.pem",
	})

	_, err := config.Sign([]byte("test"))
	if err == nil {
		t.Fatal("expected error for non-existent key, got nil")
	}
}

func TestSignerConfig_ThreadSafety(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")
	certPath := filepath.Join(tmpDir, "test-cert.pem")

	// Create test key pair
	createTestKeyPair(t, keyPath, certPath)

	// Create SignerConfig
	config := pki.NewSignerConfig(&pki.KeyConfig{
		PrivateKeyPath: keyPath,
		ChainPath:      certPath,
	})

	// Launch multiple goroutines that all try to use the config
	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := range numGoroutines {
		go func(id int) {
			// Each goroutine performs multiple operations
			_, err := config.Sign([]byte("test"))
			if err != nil {
				done <- err
				return
			}

			claims := jwt.MapClaims{"sub": "user", "id": id}
			_, err = config.SignJWT(claims)
			if err != nil {
				done <- err
				return
			}

			_, err = config.GetJWK()
			done <- err
		}(i)
	}

	// Wait for all goroutines and check for errors
	for range numGoroutines {
		if err := <-done; err != nil {
			t.Errorf("goroutine error: %v", err)
		}
	}
}
