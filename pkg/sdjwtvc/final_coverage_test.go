package sdjwtvc

import (
	"crypto/sha256"
	sha30 "crypto/sha3"
	"crypto/sha512"
	"hash"
	"testing"
)

// TestHashAlgorithmComparison tests all hash comparison functions thoroughly
func TestHashAlgorithmComparison(t *testing.T) {
	t.Run("isSHA256_true", func(t *testing.T) {
		h := sha256.New()
		if !isSHA256(h) {
			t.Error("Expected isSHA256 to return true for SHA-256 hash")
		}
	})

	t.Run("isSHA256_false_with_SHA512", func(t *testing.T) {
		h := sha512.New()
		if isSHA256(h) {
			t.Error("Expected isSHA256 to return false for SHA-512 hash")
		}
	})

	t.Run("isSHA256_false_with_SHA3_256", func(t *testing.T) {
		h := hash.Hash(sha30.New256())
		if isSHA256(h) {
			t.Error("Expected isSHA256 to return false for SHA3-256 hash")
		}
	})

	t.Run("isSHA3_256_true", func(t *testing.T) {
		h := hash.Hash(sha30.New256())
		if !isSHA3_256(h) {
			t.Error("Expected isSHA3_256 to return true for SHA3-256 hash")
		}
	})

	t.Run("isSHA3_256_false_with_SHA256", func(t *testing.T) {
		h := sha256.New()
		if isSHA3_256(h) {
			t.Error("Expected isSHA3_256 to return false for SHA-256 hash")
		}
	})

	t.Run("isSHA3_256_false_with_wrong_size", func(t *testing.T) {
		h := sha512.New()
		if isSHA3_256(h) {
			t.Error("Expected isSHA3_256 to return false for SHA-512 hash")
		}
	})

	t.Run("isSHA512_true", func(t *testing.T) {
		h := sha512.New()
		if !isSHA512(h) {
			t.Error("Expected isSHA512 to return true for SHA-512 hash")
		}
	})

	t.Run("isSHA512_false_with_SHA256", func(t *testing.T) {
		h := sha256.New()
		if isSHA512(h) {
			t.Error("Expected isSHA512 to return false for SHA-256 hash")
		}
	})

	t.Run("isSHA512_false_with_SHA3_512", func(t *testing.T) {
		h := hash.Hash(sha30.New512())
		if isSHA512(h) {
			t.Error("Expected isSHA512 to return false for SHA3-512 hash")
		}
	})

	t.Run("isSHA3_512_true", func(t *testing.T) {
		h := hash.Hash(sha30.New512())
		if !isSHA3_512(h) {
			t.Error("Expected isSHA3_512 to return true for SHA3-512 hash")
		}
	})

	t.Run("isSHA3_512_false_with_SHA512", func(t *testing.T) {
		h := sha512.New()
		if isSHA3_512(h) {
			t.Error("Expected isSHA3_512 to return false for SHA-512 hash")
		}
	})

	t.Run("isSHA3_512_false_with_wrong_size", func(t *testing.T) {
		h := sha256.New()
		if isSHA3_512(h) {
			t.Error("Expected isSHA3_512 to return false for SHA-256 hash")
		}
	})
}

// TestGetHashAlgorithmName_AllCases tests all hash algorithm detection paths
func TestGetHashAlgorithmName_AllCases(t *testing.T) {
	t.Run("SHA256_explicit", func(t *testing.T) {
		h := sha256.New()
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha-256" {
			t.Errorf("Expected sha-256, got %s", name)
		}
	})

	t.Run("SHA3_256_explicit", func(t *testing.T) {
		h := hash.Hash(sha30.New256())
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha3-256" {
			t.Errorf("Expected sha3-256, got %s", name)
		}
	})

	t.Run("SHA384_explicit", func(t *testing.T) {
		h := sha512.New384()
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha-384" {
			t.Errorf("Expected sha-384, got %s", name)
		}
	})

	t.Run("SHA512_explicit", func(t *testing.T) {
		h := sha512.New()
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha-512" {
			t.Errorf("Expected sha-512, got %s", name)
		}
	})

	t.Run("SHA3_512_explicit", func(t *testing.T) {
		h := hash.Hash(sha30.New512())
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha3-512" {
			t.Errorf("Expected sha3-512, got %s", name)
		}
	})

	t.Run("SHA224_explicit", func(t *testing.T) {
		h := sha256.New224()
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha-224" {
			t.Errorf("Expected sha-224, got %s", name)
		}
	})
}

// TestMakeCredential_AllBranches tests all code paths
func TestMakeCredential_AllBranches(t *testing.T) {
	client := &Client{}

	t.Run("with_multiple_decoys_and_nested_structures", func(t *testing.T) {
		level1 := "level1"
		level2_a := "level2_a"
		level2_b := "level2_b"
		claim_a := "claim_a"
		claim_b := "claim_b"

		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&level1, &level2_a, &claim_a},
					SD:   "always",
				},
				{
					Path: []*string{&level1, &level2_b, &claim_b},
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"level1": map[string]any{
				"level2_a": map[string]any{
					"claim_a": "value_a",
					"other":   "data",
				},
				"level2_b": map[string]any{
					"claim_b": "value_b",
				},
			},
		}

		credential, disclosures, err := client.MakeCredential(sha512.New(), data, vctm, 3)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		if len(disclosures) != 2 {
			t.Errorf("Expected 2 disclosures, got %d", len(disclosures))
		}

		// Verify _sd_alg is set correctly
		if alg, ok := credential["_sd_alg"]; !ok || alg != "sha-512" {
			t.Errorf("Expected _sd_alg to be sha-512, got %v", alg)
		}
	})

	t.Run("with_SHA3_algorithms", func(t *testing.T) {
		name := "name"
		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&name},
					SD:   "always",
				},
			},
		}

		data256 := map[string]any{"name": "test"}
		_, _, err := client.MakeCredential(hash.
			Hash(sha30.New256()), data256, vctm, 1)
		if err != nil {
			t.Fatalf("MakeCredential with SHA3-256 failed: %v", err)
		}

		data512 := map[string]any{"name": "test"}
		_, _, err = client.MakeCredential(hash.
			Hash(sha30.New512()), data512, vctm, 1)
		if err != nil {
			t.Fatalf("MakeCredential with SHA3-512 failed: %v", err)
		}
	})
}

// TestAddDecoyDigestsRecursive_ComplexNesting tests deep nesting
func TestAddDecoyDigestsRecursive_ComplexNesting(t *testing.T) {
	data := map[string]any{
		"_sd": []any{"top-level"},
		"nested1": map[string]any{
			"_sd": []any{"nested1-digest"},
			"nested2": map[string]any{
				"_sd": []any{"nested2-digest"},
				"nested3": map[string]any{
					"_sd":   []any{"nested3-digest"},
					"value": "deep",
				},
			},
		},
	}

	err := addDecoyDigestsRecursive(data, sha256.New(), 2)
	if err != nil {
		t.Fatalf("addDecoyDigestsRecursive failed: %v", err)
	}

	// Check all levels have decoys added
	if len(data["_sd"].([]any)) != 3 { // 1 original + 2 decoys
		t.Errorf("Expected 3 digests at top level, got %d", len(data["_sd"].([]any)))
	}

	nested1 := data["nested1"].(map[string]any)
	if len(nested1["_sd"].([]any)) != 3 {
		t.Errorf("Expected 3 digests at nested1 level, got %d", len(nested1["_sd"].([]any)))
	}

	nested2 := nested1["nested2"].(map[string]any)
	if len(nested2["_sd"].([]any)) != 3 {
		t.Errorf("Expected 3 digests at nested2 level, got %d", len(nested2["_sd"].([]any)))
	}

	nested3 := nested2["nested3"].(map[string]any)
	if len(nested3["_sd"].([]any)) != 3 {
		t.Errorf("Expected 3 digests at nested3 level, got %d", len(nested3["_sd"].([]any)))
	}
}

// TestProcessClaimPath_AllPaths tests all branches in processClaimPath
func TestProcessClaimPath_AllPaths(t *testing.T) {
	client := &Client{}

	t.Run("claim_exists_at_nested_level", func(t *testing.T) {
		data := map[string]any{
			"person": map[string]any{
				"name": "John",
				"age":  30,
			},
		}

		person := "person"
		name := "name"
		path := []*string{&person, &name}

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

		// Verify claim was removed
		personObj := data["person"].(map[string]any)
		if _, exists := personObj["name"]; exists {
			t.Error("Expected name to be removed")
		}

		// Age should still be there
		if _, exists := personObj["age"]; !exists {
			t.Error("Expected age to remain")
		}
	})

	t.Run("claim_with_nested_object_value", func(t *testing.T) {
		data := map[string]any{
			"address": map[string]any{
				"street": "123 Main St",
				"city":   "Springfield",
				"postal": map[string]any{
					"code": "12345",
				},
			},
		}

		address := "address"
		path := []*string{&address}

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

		// Entire address should be removed
		if _, exists := data["address"]; exists {
			t.Error("Expected address to be removed")
		}
	})
}
