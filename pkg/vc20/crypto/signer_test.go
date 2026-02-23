//go:build vc20
// +build vc20

package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"vc/pkg/pki"
)

func TestECDSAKeyWrapper_SignDigest(t *testing.T) {
	// Generate a test P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	wrapper := NewECDSAKeyWrapper(privateKey)

	// Test Algorithm
	if got := wrapper.Algorithm(); got != "ES256" {
		t.Errorf("Algorithm() = %q, want ES256", got)
	}

	// Test PublicKey
	pubKey := wrapper.PublicKey()
	if pubKey == nil {
		t.Error("PublicKey() returned nil")
	}
	if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("PublicKey() returned %T, want *ecdsa.PublicKey", pubKey)
	}

	// Test SignDigest
	digest := make([]byte, 32) // SHA-256 digest size
	rand.Read(digest)

	signature, err := wrapper.SignDigest(context.Background(), digest)
	if err != nil {
		t.Fatalf("SignDigest() error = %v", err)
	}

	// Verify signature length (IEEE P1363 format: 2 * key size in bytes)
	expectedLen := 64 // 32 bytes for r + 32 bytes for s (P-256)
	if len(signature) != expectedLen {
		t.Errorf("SignDigest() signature length = %d, want %d", len(signature), expectedLen)
	}

	// Verify the signature is valid
	r, s, err := DecodeIEEEP1363(signature, elliptic.P256())
	if err != nil {
		t.Fatalf("DecodeIEEEP1363() error = %v", err)
	}

	if !ecdsa.Verify(&privateKey.PublicKey, digest, r, s) {
		t.Error("Signature verification failed")
	}
}

func TestECDSAKeyWrapper_DifferentCurves(t *testing.T) {
	tests := []struct {
		name      string
		curve     elliptic.Curve
		algorithm string
		keySize   int
	}{
		{"P-256", elliptic.P256(), "ES256", 64},
		{"P-384", elliptic.P384(), "ES384", 96},
		{"P-521", elliptic.P521(), "ES512", 132},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			wrapper := NewECDSAKeyWrapper(privateKey)

			if got := wrapper.Algorithm(); got != tt.algorithm {
				t.Errorf("Algorithm() = %q, want %q", got, tt.algorithm)
			}

			digest := make([]byte, 64) // Large enough for any curve
			rand.Read(digest)

			signature, err := wrapper.SignDigest(context.Background(), digest)
			if err != nil {
				t.Fatalf("SignDigest() error = %v", err)
			}

			if len(signature) != tt.keySize {
				t.Errorf("SignDigest() signature length = %d, want %d", len(signature), tt.keySize)
			}
		})
	}
}

func TestEdDSAKeyWrapper_SignDigest(t *testing.T) {
	// Generate a test Ed25519 key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	wrapper := NewEdDSAKeyWrapper(privateKey)

	// Test Algorithm
	if got := wrapper.Algorithm(); got != "Ed25519" {
		t.Errorf("Algorithm() = %q, want Ed25519", got)
	}

	// Test PublicKey
	pubKey := wrapper.PublicKey()
	if pubKey == nil {
		t.Error("PublicKey() returned nil")
	}
	if _, ok := pubKey.(ed25519.PublicKey); !ok {
		t.Errorf("PublicKey() returned %T, want ed25519.PublicKey", pubKey)
	}

	// Test SignDigest (for Ed25519, this is the full message, not a digest)
	message := []byte("test message for ed25519 signing")

	signature, err := wrapper.SignDigest(context.Background(), message)
	if err != nil {
		t.Fatalf("SignDigest() error = %v", err)
	}

	// Verify signature length (Ed25519 signatures are always 64 bytes)
	if len(signature) != ed25519.SignatureSize {
		t.Errorf("SignDigest() signature length = %d, want %d", len(signature), ed25519.SignatureSize)
	}

	// Verify the signature is valid
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), message, signature) {
		t.Error("Signature verification failed")
	}
}

func TestDecodeIEEEP1363_InvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		signature []byte
		curve     elliptic.Curve
		wantErr   bool
	}{
		{
			name:      "Valid P-256 signature",
			signature: make([]byte, 64),
			curve:     elliptic.P256(),
			wantErr:   false,
		},
		{
			name:      "Too short for P-256",
			signature: make([]byte, 63),
			curve:     elliptic.P256(),
			wantErr:   true,
		},
		{
			name:      "Too long for P-256",
			signature: make([]byte, 65),
			curve:     elliptic.P256(),
			wantErr:   true,
		},
		{
			name:      "Valid P-384 signature",
			signature: make([]byte, 96),
			curve:     elliptic.P384(),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecodeIEEEP1363(tt.signature, tt.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeIEEEP1363() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeDecodeIEEEP1363_RoundTrip(t *testing.T) {
	// Generate a key and create a real signature
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("Failed to generate random digest: %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Encode to IEEE P1363
	encoded, err := pki.EncodeECDSASignature(r, s, elliptic.P256())
	if err != nil {
		t.Fatalf("EncodeECDSASignature() error = %v", err)
	}

	// Decode back
	decodedR, decodedS, err := DecodeIEEEP1363(encoded, elliptic.P256())
	if err != nil {
		t.Fatalf("DecodeIEEEP1363() error = %v", err)
	}

	// Verify decoded values match originals
	if r.Cmp(decodedR) != 0 {
		t.Errorf("Decoded r doesn't match: got %s, want %s", decodedR.String(), r.String())
	}
	if s.Cmp(decodedS) != 0 {
		t.Errorf("Decoded s doesn't match: got %s, want %s", decodedS.String(), s.String())
	}

	// Verify signature still works
	if !ecdsa.Verify(&privateKey.PublicKey, digest, decodedR, decodedS) {
		t.Error("Signature verification failed after round-trip")
	}
}
