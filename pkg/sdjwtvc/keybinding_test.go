package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCreateKeyBindingJWT(t *testing.T) {
	// Generate a test key for key binding
	holderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate holder key: %v", err)
	}

	sdJWT := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.signature~disclosure1~disclosure2~"
	nonce := "test-nonce-123"
	audience := "https://verifier.example.com"
	alg := "sha-256"

	t.Run("creates_valid_kb_jwt", func(t *testing.T) {
		kbJWT, err := CreateKeyBindingJWT(sdJWT, nonce, audience, holderPrivateKey, alg)
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		// JWT should have 3 parts separated by dots
		parts := strings.Split(kbJWT, ".")
		if len(parts) != 3 {
			t.Errorf("Expected 3 JWT parts, got %d", len(parts))
		}

		// Decode and verify header
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("Failed to decode header: %v", err)
		}
		var header map[string]any
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			t.Fatalf("Failed to unmarshal header: %v", err)
		}

		if header["typ"] != "kb+jwt" {
			t.Errorf("Expected typ=kb+jwt, got %v", header["typ"])
		}
		if header["alg"] != "ES256" {
			t.Errorf("Expected alg=ES256, got %v", header["alg"])
		}

		// Decode and verify payload
		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("Failed to decode payload: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			t.Fatalf("Failed to unmarshal payload: %v", err)
		}

		if payload["nonce"] != nonce {
			t.Errorf("Expected nonce=%s, got %v", nonce, payload["nonce"])
		}
		if payload["aud"] != audience {
			t.Errorf("Expected aud=%s, got %v", audience, payload["aud"])
		}

		// Verify iat is recent (within last minute)
		if iat, ok := payload["iat"].(float64); ok {
			iatTime := time.Unix(int64(iat), 0)
			if time.Since(iatTime) > time.Minute {
				t.Errorf("iat timestamp is too old: %v", iatTime)
			}
		} else {
			t.Error("iat claim is missing or wrong type")
		}

		// Verify sd_hash exists and is a string
		if sdHash, ok := payload["sd_hash"].(string); ok {
			if len(sdHash) != 43 {
				t.Errorf("Expected sd_hash length 43 (SHA-256), got %d", len(sdHash))
			}
		} else {
			t.Error("sd_hash claim is missing or wrong type")
		}
	})

	t.Run("different_nonces_produce_different_kb_jwts", func(t *testing.T) {
		kbJWT1, err := CreateKeyBindingJWT(sdJWT, "nonce1", audience, holderPrivateKey, alg)
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		kbJWT2, err := CreateKeyBindingJWT(sdJWT, "nonce2", audience, holderPrivateKey, alg)
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		if kbJWT1 == kbJWT2 {
			t.Error("Different nonces should produce different KB-JWTs")
		}
	})

	t.Run("different_sd_jwts_produce_different_sd_hashes", func(t *testing.T) {
		sdJWT1 := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlcjEifQ.signature~disclosure1~"
		sdJWT2 := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlcjIifQ.signature~disclosure2~"

		kbJWT1, err := CreateKeyBindingJWT(sdJWT1, nonce, audience, holderPrivateKey, alg)
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		kbJWT2, err := CreateKeyBindingJWT(sdJWT2, nonce, audience, holderPrivateKey, alg)
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		// Extract sd_hash from both
		payload1 := extractPayload(t, kbJWT1)
		payload2 := extractPayload(t, kbJWT2)

		sdHash1 := payload1["sd_hash"].(string)
		sdHash2 := payload2["sd_hash"].(string)

		if sdHash1 == sdHash2 {
			t.Error("Different SD-JWTs should produce different sd_hash values")
		}
	})
}

func TestCalculateSDHash(t *testing.T) {
	t.Run("calculates_correct_hash_sha256", func(t *testing.T) {
		sdJWT := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.signature~disclosure~"

		hashMethod := sha256.New()
		hash, err := calculateSDHash(sdJWT, hashMethod)
		if err != nil {
			t.Fatalf("calculateSDHash failed: %v", err)
		}

		// Manually calculate expected hash
		h := sha256.New()
		h.Write([]byte(sdJWT))
		expected := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

		if hash != expected {
			t.Errorf("Hash mismatch:\nGot:      %s\nExpected: %s", hash, expected)
		}

		// Should be 43 characters for SHA-256
		if len(hash) != 43 {
			t.Errorf("Expected hash length 43, got %d", len(hash))
		}
	})

	t.Run("different_algorithms_produce_different_hashes", func(t *testing.T) {
		sdJWT := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.signature~"

		hash256, err := calculateSDHash(sdJWT, sha256.New())
		if err != nil {
			t.Fatalf("calculateSDHash SHA-256 failed: %v", err)
		}

		hash512, err := calculateSDHash(sdJWT, sha512.New())
		if err != nil {
			t.Fatalf("calculateSDHash SHA-512 failed: %v", err)
		}

		if hash256 == hash512 {
			t.Error("Different hash algorithms should produce different hashes")
		}

		// SHA-512 should be longer (86 characters vs 43)
		if len(hash512) <= len(hash256) {
			t.Errorf("SHA-512 hash should be longer than SHA-256: %d vs %d", len(hash512), len(hash256))
		}
	})
}

func TestGetHashFromAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      string
		wantErr  bool
		hashSize int // expected digest size in bytes
	}{
		{"SHA-256", "sha-256", false, 32},
		{"SHA-384", "sha-384", false, 48},
		{"SHA-512", "sha-512", false, 64},
		{"SHA3-256", "sha3-256", false, 32},
		{"SHA3-512", "sha3-512", false, 64},
		{"Unsupported", "md5", true, 0},
		{"Empty", "", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher, err := getHashFromAlgorithm(tt.alg)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify hash size by writing some data
			hasher.Write([]byte("test"))
			digest := hasher.Sum(nil)
			if len(digest) != tt.hashSize {
				t.Errorf("Expected hash size %d bytes, got %d", tt.hashSize, len(digest))
			}
		})
	}
}

func TestCombineWithKeyBinding(t *testing.T) {
	sdJWT := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.signature~disclosure1~disclosure2~"
	kbJWT := "eyJ0eXAiOiJrYitqd3QifQ.eyJub25jZSI6InRlc3QifQ.kbsignature"

	t.Run("combines_sd_jwt_and_kb_jwt", func(t *testing.T) {
		combined := CombineWithKeyBinding(sdJWT, kbJWT)

		expected := sdJWT + kbJWT
		if combined != expected {
			t.Errorf("Combination mismatch:\nGot:      %s\nExpected: %s", combined, expected)
		}

		// Should have trailing ~ before KB-JWT
		if !strings.HasSuffix(sdJWT, "~") {
			t.Error("SD-JWT should end with ~")
		}
		if !strings.Contains(combined, "~"+kbJWT) {
			t.Error("Combined format should have ~ before KB-JWT")
		}
	})

	t.Run("handles_sd_jwt_without_trailing_tilde", func(t *testing.T) {
		sdJWTNoTilde := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.signature~disclosure1~disclosure2"

		combined := CombineWithKeyBinding(sdJWTNoTilde, kbJWT)

		// Should end with ~kbJWT
		if !strings.HasSuffix(combined, "~"+kbJWT) {
			t.Error("Combined SD-JWT+KB should end with ~KB-JWT")
		}
	})
}

// Helper to extract and decode JWT payload
func extractPayload(t *testing.T, jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWT format")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	return payload
}

func TestCreateKeyBindingJWT_WithTransactionDataHashes(t *testing.T) {
	holderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate holder key: %v", err)
	}

	sdJWT := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.signature~disclosure1~"
	nonce := "test-nonce-123"
	audience := "https://verifier.example.com"
	alg := "sha-256"

	t.Run("includes_transaction_data_hashes", func(t *testing.T) {
		hashes := []string{"hash_aaa", "hash_bbb"}
		kbJWT, err := CreateKeyBindingJWT(sdJWT, nonce, audience, holderPrivateKey, alg,
			WithTransactionDataHashes(hashes))
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		payload := extractPayload(t, kbJWT)

		rawHashes, ok := payload["transaction_data_hashes"].([]any)
		if !ok {
			t.Fatal("transaction_data_hashes missing or wrong type")
		}
		if len(rawHashes) != 2 {
			t.Fatalf("expected 2 hashes, got %d", len(rawHashes))
		}
		if rawHashes[0] != "hash_aaa" || rawHashes[1] != "hash_bbb" {
			t.Errorf("unexpected hashes: %v", rawHashes)
		}

		algClaim, ok := payload["transaction_data_hashes_alg"].(string)
		if !ok {
			t.Fatal("transaction_data_hashes_alg missing or wrong type")
		}
		if algClaim != alg {
			t.Errorf("expected alg %s, got %s", alg, algClaim)
		}
	})

	t.Run("omits_claims_when_no_option", func(t *testing.T) {
		kbJWT, err := CreateKeyBindingJWT(sdJWT, nonce, audience, holderPrivateKey, alg)
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		payload := extractPayload(t, kbJWT)

		if _, ok := payload["transaction_data_hashes"]; ok {
			t.Error("transaction_data_hashes should be absent when no option is provided")
		}
		if _, ok := payload["transaction_data_hashes_alg"]; ok {
			t.Error("transaction_data_hashes_alg should be absent when no option is provided")
		}
	})

	t.Run("omits_claims_when_empty_hashes", func(t *testing.T) {
		kbJWT, err := CreateKeyBindingJWT(sdJWT, nonce, audience, holderPrivateKey, alg,
			WithTransactionDataHashes([]string{}))
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		payload := extractPayload(t, kbJWT)

		if _, ok := payload["transaction_data_hashes"]; ok {
			t.Error("transaction_data_hashes should be absent for empty slice")
		}
	})

	t.Run("preserves_standard_claims", func(t *testing.T) {
		hashes := []string{"hash_one"}
		kbJWT, err := CreateKeyBindingJWT(sdJWT, nonce, audience, holderPrivateKey, alg,
			WithTransactionDataHashes(hashes))
		if err != nil {
			t.Fatalf("CreateKeyBindingJWT failed: %v", err)
		}

		payload := extractPayload(t, kbJWT)

		if payload["nonce"] != nonce {
			t.Errorf("expected nonce %s, got %v", nonce, payload["nonce"])
		}
		if payload["aud"] != audience {
			t.Errorf("expected aud %s, got %v", audience, payload["aud"])
		}
		if _, ok := payload["sd_hash"].(string); !ok {
			t.Error("sd_hash missing")
		}
		if _, ok := payload["iat"].(float64); !ok {
			t.Error("iat missing")
		}
	})
}
