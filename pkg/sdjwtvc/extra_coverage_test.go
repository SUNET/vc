package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"github.com/SUNET/vc/pkg/jose"
)

// TestGetSigningMethodFromKey_AllKeyTypes tests all key type branches
func TestGetSigningMethodFromKey_AllKeyTypes(t *testing.T) {
	t.Run("RSA_2048", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		method, alg := jose.GetSigningMethodFromKey(key)
		if alg != "RS256" {
			t.Errorf("Expected RS256, got %s", alg)
		}
		if method == nil {
			t.Error("Expected non-nil signing method")
		}
	})

	t.Run("RSA_3072", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 3072)
		method, alg := jose.GetSigningMethodFromKey(key)
		if alg != "RS384" {
			t.Errorf("Expected RS384, got %s", alg)
		}
		if method == nil {
			t.Error("Expected non-nil signing method")
		}
	})

	t.Run("RSA_4096", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 4096)
		method, alg := jose.GetSigningMethodFromKey(key)
		if alg != "RS512" {
			t.Errorf("Expected RS512, got %s", alg)
		}
		if method == nil {
			t.Error("Expected non-nil signing method")
		}
	})

	t.Run("ECDSA_P256", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		method, alg := jose.GetSigningMethodFromKey(key)
		if alg != "ES256" {
			t.Errorf("Expected ES256, got %s", alg)
		}
		if method == nil {
			t.Error("Expected non-nil signing method")
		}
	})

	t.Run("ECDSA_P384", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		method, alg := jose.GetSigningMethodFromKey(key)
		if alg != "ES384" {
			t.Errorf("Expected ES384, got %s", alg)
		}
		if method == nil {
			t.Error("Expected non-nil signing method")
		}
	})

	t.Run("ECDSA_P521", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		method, alg := jose.GetSigningMethodFromKey(key)
		if alg != "ES512" {
			t.Errorf("Expected ES512, got %s", alg)
		}
		if method == nil {
			t.Error("Expected non-nil signing method")
		}
	})

	t.Run("unknown_key_type", func(t *testing.T) {
		// Pass a string (unknown type)
		method, alg := jose.GetSigningMethodFromKey("invalid-key")
		// Should default to ES256
		if alg != "ES256" {
			t.Errorf("Expected ES256 default, got %s", alg)
		}
		if method == nil {
			t.Error("Expected non-nil signing method")
		}
	})
}

// TestMakeCredential_ComplexPaths tests complex claim processing
func TestMakeCredential_ComplexPaths(t *testing.T) {
	client := &Client{}

	t.Run("deeply_nested_claim", func(t *testing.T) {
		level1 := "level1"
		level2 := "level2"
		level3 := "level3"
		finalClaim := "secret"

		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&level1, &level2, &level3, &finalClaim},
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"level3": map[string]any{
						"secret": "hidden-value",
					},
				},
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		if len(disclosures) != 1 {
			t.Errorf("Expected 1 disclosure, got %d", len(disclosures))
		}

		// Check that _sd array was created at the right level
		level3Obj := credential["level1"].(map[string]any)["level2"].(map[string]any)["level3"].(map[string]any)
		if _, ok := level3Obj["_sd"]; !ok {
			t.Error("Expected _sd array in level3")
		}
	})

	t.Run("multiple_claims_at_different_levels", func(t *testing.T) {
		name := "name"
		address := "address"
		street := "street"

		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&name},
					SD:   "always",
				},
				{
					Path: []*string{&address, &street},
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"name": "John Doe",
			"address": map[string]any{
				"street": "123 Main St",
				"city":   "Springfield",
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 2)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		if len(disclosures) != 2 {
			t.Errorf("Expected 2 disclosures, got %d", len(disclosures))
		}

		// Check top-level _sd array
		if topSD, ok := credential["_sd"]; ok {
			arr := topSD.([]any)
			// 1 real + 2 decoys = 3
			if len(arr) != 3 {
				t.Errorf("Expected 3 digests in top-level _sd, got %d", len(arr))
			}
		} else {
			t.Error("Expected top-level _sd array")
		}

		// Check nested _sd array
		if addressObj, ok := credential["address"].(map[string]any); ok {
			if nestedSD, ok := addressObj["_sd"]; ok {
				arr := nestedSD.([]any)
				// 1 real + 2 decoys = 3
				if len(arr) != 3 {
					t.Errorf("Expected 3 digests in nested _sd, got %d", len(arr))
				}
			} else {
				t.Error("Expected _sd array in address object")
			}
		} else {
			t.Error("Expected address object")
		}
	})

	t.Run("claim_with_sd_never", func(t *testing.T) {
		name := "name"
		age := "age"

		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&name},
					SD:   "always",
				},
				{
					Path: []*string{&age},
					SD:   "never", // Should not be disclosed
				},
			},
		}

		data := map[string]any{
			"name": "John",
			"age":  30,
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		// Only name should be disclosed
		if len(disclosures) != 1 {
			t.Errorf("Expected 1 disclosure (only name), got %d", len(disclosures))
		}

		// Age should still be in the credential (not selectively disclosed)
		if _, ok := credential["age"]; !ok {
			t.Error("Expected age to remain in credential (SD=never)")
		}
	})

	t.Run("empty_path_in_vctm", func(t *testing.T) {
		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{}, // Empty path
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"name": "John",
		}

		// Should not process claims with empty paths
		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		// No disclosures should be created for empty path
		if len(disclosures) != 0 {
			t.Errorf("Expected 0 disclosures for empty path, got %d", len(disclosures))
		}

		// Original data should be unchanged (except for _sd_alg)
		if _, ok := credential["name"]; !ok {
			t.Error("Expected name to remain in credential")
		}
	})
}

// TestAddDecoyDigests_EdgeCases tests decoy digest edge cases
func TestAddDecoyDigests_EdgeCases(t *testing.T) {
	client := &Client{}

	t.Run("add_decoys_to_credential_with_arrays", func(t *testing.T) {
		data := map[string]any{
			"_sd": []any{"existing-digest"},
			"nested": map[string]any{
				"array_field": []any{"value1", "value2"},
				"_sd":         []any{"nested-digest"},
			},
		}

		err := client.addDecoyDigests(data, sha256.New(), 2)
		if err != nil {
			t.Fatalf("addDecoyDigests failed: %v", err)
		}

		// Top-level should have 1 + 2 = 3
		topSD := data["_sd"].([]any)
		if len(topSD) != 3 {
			t.Errorf("Expected 3 digests at top level, got %d", len(topSD))
		}

		// Nested should have 1 + 2 = 3
		nested := data["nested"].(map[string]any)
		nestedSD := nested["_sd"].([]any)
		if len(nestedSD) != 3 {
			t.Errorf("Expected 3 digests in nested, got %d", len(nestedSD))
		}

		// Array field should be unchanged
		arrayField := nested["array_field"].([]any)
		if len(arrayField) != 2 {
			t.Error("Array field should not be modified")
		}
	})

	t.Run("deeply_nested_sd_arrays", func(t *testing.T) {
		data := map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"level3": map[string]any{
						"_sd": []any{"deep-digest"},
					},
				},
			},
		}

		err := client.addDecoyDigests(data, sha256.New(), 1)
		if err != nil {
			t.Fatalf("addDecoyDigests failed: %v", err)
		}

		// Navigate to deep _sd array
		level3 := data["level1"].(map[string]any)["level2"].(map[string]any)["level3"].(map[string]any)
		deepSD := level3["_sd"].([]any)
		if len(deepSD) != 2 {
			t.Errorf("Expected 2 digests (1 original + 1 decoy) at deep level, got %d", len(deepSD))
		}
	})
}
