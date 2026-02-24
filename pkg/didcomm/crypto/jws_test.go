//go:build didcomm && vc20

package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestSign_ES256(t *testing.T) {
	// Generate a P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to JWK
	jwkKey, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatalf("failed to import key: %v", err)
	}
	if err := jwkKey.Set("kid", "test-key-1"); err != nil {
		t.Fatalf("failed to set kid: %v", err)
	}

	// Sign
	plaintext := []byte(`{"id":"123","type":"test"}`)
	signed, err := Sign(context.Background(), plaintext, jwkKey, SignOptions{})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(signed) == 0 {
		t.Error("expected non-empty signed message")
	}

	// Create public key for verification
	pubJWK, err := jwk.Import(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to import public key: %v", err)
	}

	// Verify
	verified, err := Verify(context.Background(), signed, pubJWK)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if string(verified) != string(plaintext) {
		t.Errorf("Verify() = %s, want %s", string(verified), string(plaintext))
	}
}

func TestSign_WithAlgorithmHint(t *testing.T) {
	// Generate a P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to JWK
	jwkKey, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatalf("failed to import key: %v", err)
	}

	// Sign with explicit algorithm
	plaintext := []byte(`{"id":"456","type":"test"}`)
	signed, err := Sign(context.Background(), plaintext, jwkKey, SignOptions{
		Algorithm: "ES256",
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(signed) == 0 {
		t.Error("expected non-empty signed message")
	}
}

func TestDetermineSigningAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		kty         string
		crv         string
		expectedAlg string
		expectError bool
	}{
		{
			name:        "P-256",
			kty:         "EC",
			crv:         "P-256",
			expectedAlg: "ES256",
		},
		{
			name:        "P-384",
			kty:         "EC",
			crv:         "P-384",
			expectedAlg: "ES384",
		},
		{
			name:        "secp256k1",
			kty:         "EC",
			crv:         "secp256k1",
			expectedAlg: "ES256K",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var privateKey *ecdsa.PrivateKey
			var err error

			switch tt.crv {
			case "P-256":
				privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			case "P-384":
				privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			default:
				t.Skip("curve not supported for test key generation")
			}

			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			jwkKey, err := jwk.Import(privateKey)
			if err != nil {
				t.Fatalf("failed to import key: %v", err)
			}

			alg, err := determineSigningAlgorithm(jwkKey, "")
			if tt.expectError {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("determineSigningAlgorithm() error = %v", err)
			}

			if alg.String() != tt.expectedAlg {
				t.Errorf("algorithm = %v, want %v", alg.String(), tt.expectedAlg)
			}
		})
	}
}

func TestParseSigningAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"EdDSA", "EdDSA", false},
		{"ES256", "ES256", false},
		{"ES256K", "ES256K", false},
		{"ES384", "ES384", false},
		{"UNKNOWN", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			alg, err := parseSigningAlgorithm(tt.input)
			if tt.hasError {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseSigningAlgorithm() error = %v", err)
			}

			if alg.String() != tt.expected {
				t.Errorf("algorithm = %v, want %v", alg.String(), tt.expected)
			}
		})
	}
}
