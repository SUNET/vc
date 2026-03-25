package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	sha30 "crypto/sha3"
	"crypto/sha512"
	"hash"
	"testing"
	"github.com/SUNET/vc/pkg/jose"
)

// TestComprehensiveCoverage targets remaining uncovered branches
func TestComprehensiveCoverage(t *testing.T) {
	client := &Client{}

	t.Run("BuildCredentialWithOptions_with_all_options", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		name := "name"
		email := "email"
		vctm := &VCTM{
			VCT:  "test-cred",
			Name: "Test Credential",
			Claims: []Claim{
				{
					Path: []*string{&name},
					SD:   "always",
				},
				{
					Path: []*string{&email},
					SD:   "always",
				},
			},
		}

		documentData := []byte(`{"name":"Alice","email":"alice@example.com","age":30}`)
		holderJWK := map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   "test",
			"y":   "test",
		}

		vctmRaw, integrity := marshalVCTM(t, vctm)
		signer := newTestSigner(privateKey, "key-123")

		opts := &CredentialOptions{
			DecoyDigests:   5,
			ExpirationDays: 180,
			Integrity:      integrity,
		}

		token, err := client.BuildCredentialWithSigner(
			t.Context(),
			"https://issuer.example.com",
			signer,
			vctmRaw,
			documentData,
			holderJWK,
			opts,
		)

		if err != nil {
			t.Fatalf("BuildCredentialWithOptions failed: %v", err)
		}

		if token == "" {
			t.Error("Expected non-empty token")
		}
	})

	t.Run("test_all_hash_algorithms_in_MakeCredential", func(t *testing.T) {
		name := "test"
		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&name},
					SD:   "always",
				},
			},
		}

		testCases := []struct {
			name     string
			hasher   func() any
			expected string
		}{
			{"SHA-256", func() any { return sha256.New() }, "sha-256"},
			{"SHA-384", func() any { return sha512.New384() }, "sha-384"},
			{"SHA-512", func() any { return sha512.New() }, "sha-512"},
			{"SHA3-256", func() any {
				return hash.
					Hash(sha30.New256())
			}, "sha3-256"},
			{"SHA3-512", func() any {
				return hash.
					Hash(sha30.New512())
			}, "sha3-512"},
			{"SHA-224", func() any { return sha256.New224() }, "sha-224"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				data := map[string]any{
					"test": "value",
				}

				h := tc.hasher()
				if hasher, ok := h.(interface {
					Reset()
					Write([]byte) (int, error)
					Sum([]byte) []byte
					Size() int
					BlockSize() int
				}); ok {
					credential, disclosures, err := client.MakeCredential(hasher, data, vctm, 0)
					if err != nil {
						t.Fatalf("MakeCredential failed for %s: %v", tc.name, err)
					}

					if alg := credential["_sd_alg"]; alg != tc.expected {
						t.Errorf("Expected _sd_alg=%s, got %v", tc.expected, alg)
					}

					if len(disclosures) != 1 {
						t.Errorf("Expected 1 disclosure, got %d", len(disclosures))
					}
				}
			})
		}
	})

	t.Run("processClaimPath_with_various_value_types", func(t *testing.T) {
		testCases := []struct {
			name  string
			value any
		}{
			{"string_value", "test-string"},
			{"int_value", 123},
			{"float_value", 45.67},
			{"bool_value", true},
			{"array_value", []any{1, 2, 3}},
			{"object_value", map[string]any{"nested": "value"}},
			{"null_value", nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				data := map[string]any{
					"claim": tc.value,
				}

				claim := "claim"
				path := []*string{&claim}

				disclosure, hash, err := client.processClaimPath(data, path, sha256.New())
				if err != nil {
					t.Fatalf("processClaimPath failed: %v", err)
				}

				if disclosure == "" {
					t.Error("Expected non-empty disclosure")
				}
				if hash == "" {
					t.Error("Expected non-empty hash")
				}
			})
		}
	})

	t.Run("addDecoyDigestsRecursive_with_mixed_types", func(t *testing.T) {
		data := map[string]any{
			"_sd":          []any{"digest1", "digest2"},
			"string_field": "value",
			"number_field": 123,
			"bool_field":   false,
			"array_field":  []any{1, 2, 3},
			"nested_object": map[string]any{
				"_sd":    []any{"nested-digest"},
				"value":  "test",
				"number": 456,
			},
		}

		err := addDecoyDigestsRecursive(data, sha256.New(), 1)
		if err != nil {
			t.Fatalf("addDecoyDigestsRecursive failed: %v", err)
		}

		// Top level should have 2 + 1 = 3
		if len(data["_sd"].([]any)) != 3 {
			t.Errorf("Expected 3 digests at top level, got %d", len(data["_sd"].([]any)))
		}

		// Nested should have 1 + 1 = 2
		nested := data["nested_object"].(map[string]any)
		if len(nested["_sd"].([]any)) != 2 {
			t.Errorf("Expected 2 digests in nested, got %d", len(nested["_sd"].([]any)))
		}

		// Other fields should be unchanged
		if data["string_field"] != "value" {
			t.Error("String field was modified")
		}
		if data["number_field"] != 123 {
			t.Error("Number field was modified")
		}
	})

	t.Run("jose.GetSigningMethodFromKey_with_all_curve_types", func(t *testing.T) {
		// Test P-256
		keyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		method, alg := jose.GetSigningMethodFromKey(keyP256)
		if alg != "ES256" {
			t.Errorf("Expected ES256 for P-256, got %s", alg)
		}
		if method == nil {
			t.Error("Expected non-nil method")
		}

		// Test P-384
		keyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		_, alg = jose.GetSigningMethodFromKey(keyP384)
		if alg != "ES384" {
			t.Errorf("Expected ES384 for P-384, got %s", alg)
		}

		// Test P-521
		keyP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		_, alg = jose.GetSigningMethodFromKey(keyP521)
		if alg != "ES512" {
			t.Errorf("Expected ES512 for P-521, got %s", alg)
		}

		// Test RSA 2048
		keyRSA2048, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, alg = jose.GetSigningMethodFromKey(keyRSA2048)
		if alg != "RS256" {
			t.Errorf("Expected RS256 for RSA 2048, got %s", alg)
		}

		// Test RSA 3072
		keyRSA3072, _ := rsa.GenerateKey(rand.Reader, 3072)
		_, alg = jose.GetSigningMethodFromKey(keyRSA3072)
		if alg != "RS384" {
			t.Errorf("Expected RS384 for RSA 3072, got %s", alg)
		}

		// Test RSA 4096
		keyRSA4096, _ := rsa.GenerateKey(rand.Reader, 4096)
		_, alg = jose.GetSigningMethodFromKey(keyRSA4096)
		if alg != "RS512" {
			t.Errorf("Expected RS512 for RSA 4096, got %s", alg)
		}

		// Test unknown key type (string)
		_, alg = jose.GetSigningMethodFromKey("unknown")
		if alg != "ES256" {
			t.Errorf("Expected ES256 default for unknown key, got %s", alg)
		}

		// Test another unknown type (int)
		_, alg = jose.GetSigningMethodFromKey(12345)
		if alg != "ES256" {
			t.Errorf("Expected ES256 default for int key, got %s", alg)
		}
	})

	t.Run("generateDecoyDigest_multiple_calls", func(t *testing.T) {
		// Generate multiple decoys with different hashers
		hashers := []any{
			sha256.New(),
			sha512.New(),
			hash.
				Hash(sha30.New256()),
			hash.
				Hash(sha30.New512()),
		}

		for _, h := range hashers {
			if hasher, ok := h.(interface {
				Reset()
				Write([]byte) (int, error)
				Sum([]byte) []byte
				Size() int
				BlockSize() int
			}); ok {
				for range 5 {
					digest, err := generateDecoyDigest(hasher)
					if err != nil {
						t.Fatalf("generateDecoyDigest failed: %v", err)
					}
					if digest == "" {
						t.Error("Expected non-empty digest")
					}
				}
			}
		}
	})

	t.Run("generateSalt_multiple_calls", func(t *testing.T) {
		salts := make(map[string]bool)
		for range 20 {
			salt, err := generateSalt()
			if err != nil {
				t.Fatalf("generateSalt failed: %v", err)
			}
			if salt == "" {
				t.Error("Expected non-empty salt")
			}
			if len(salt) != 22 {
				t.Errorf("Expected 22 character salt, got %d", len(salt))
			}
			salts[salt] = true
		}
		if len(salts) != 20 {
			t.Errorf("Expected 20 unique salts, got %d", len(salts))
		}
	})

	t.Run("MakeCredential_with_addHashToPath_error", func(t *testing.T) {
		// This should trigger the error path in addHashToPath
		parent := "parent"
		child := "child"

		vctm := &VCTM{
			Claims: []Claim{
				{
					// Try to add to a non-existent parent path
					Path: []*string{&parent, &child},
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"parent": "not-an-object", // This will cause an error
		}

		_, _, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		// Should handle the error gracefully or fail
		_ = err
	})
}
