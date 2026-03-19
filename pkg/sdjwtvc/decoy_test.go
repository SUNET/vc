package sdjwtvc

import (
	"crypto/sha256"
	"testing"
)

func TestDecoyDigests(t *testing.T) {
	mockAttributeName := "name"

	vctm := &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeName},
				SD:   "always",
			},
		},
	}

	data := map[string]any{
		"name": "Alice",
		"age":  30,
	}

	client := &Client{}

	t.Run("no_decoy_digests", func(t *testing.T) {
		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		// Should have exactly 1 disclosure (name)
		if len(disclosures) != 1 {
			t.Errorf("Expected 1 disclosure, got %d", len(disclosures))
		}

		// Count _sd array elements - should be 1 (no decoys)
		sdArray, ok := credential["_sd"].([]any)
		if !ok {
			t.Fatal("_sd is not an array")
		}
		if len(sdArray) != 1 {
			t.Errorf("Expected 1 digest (no decoys), got %d", len(sdArray))
		}
	})

	t.Run("with_decoy_digests", func(t *testing.T) {
		credential, _, err := client.MakeCredential(sha256.New(), data, vctm, 3)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		// Count _sd array elements (should be 1 real + 3 decoys = 4)
		// The disclosures array only contains real disclosures, not decoys
		sdArray, ok := credential["_sd"].([]any)
		if !ok {
			t.Fatal("_sd is not an array")
		}
		if len(sdArray) != 4 {
			t.Errorf("Expected 4 digests (1 real + 3 decoys), got %d", len(sdArray))
		}

		// Verify all elements are strings
		for i, elem := range sdArray {
			if _, ok := elem.(string); !ok {
				t.Errorf("Element %d is not a string", i)
			}
		}
	})

	t.Run("decoy_digests_nested_objects", func(t *testing.T) {
		mockPersonal := "personal"
		mockPersonalName := "name"
		mockWork := "work"
		mockWorkTitle := "title"

		nestedVCTM := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&mockPersonal, &mockPersonalName},
					SD:   "always",
				},
				{
					Path: []*string{&mockWork, &mockWorkTitle},
					SD:   "always",
				},
			},
		}

		nestedData := map[string]any{
			"personal": map[string]any{
				"name": "Alice",
				"age":  30,
			},
			"work": map[string]any{
				"title":   "Engineer",
				"company": "TechCorp",
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), nestedData, nestedVCTM, 2)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		// Should have exactly 2 disclosures
		if len(disclosures) != 2 {
			t.Errorf("Expected 2 disclosures, got %d", len(disclosures))
		}

		// Check personal._sd array (1 real + 2 decoys = 3)
		personal, ok := credential["personal"].(map[string]any)
		if !ok {
			t.Fatal("personal is not an object")
		}
		personalSD, ok := personal["_sd"].([]any)
		if !ok {
			t.Fatal("personal._sd is not an array")
		}
		if len(personalSD) != 3 {
			t.Errorf("Expected 3 digests in personal._sd (1 real + 2 decoys), got %d", len(personalSD))
		}

		// Check work._sd array (1 real + 2 decoys = 3)
		work, ok := credential["work"].(map[string]any)
		if !ok {
			t.Fatal("work is not an object")
		}
		workSD, ok := work["_sd"].([]any)
		if !ok {
			t.Fatal("work._sd is not an array")
		}
		if len(workSD) != 3 {
			t.Errorf("Expected 3 digests in work._sd (1 real + 2 decoys), got %d", len(workSD))
		}
	})

	t.Run("decoy_digests_are_valid_base64url", func(t *testing.T) {
		credential, _, err := client.MakeCredential(sha256.New(), data, vctm, 5)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		sdArray := credential["_sd"].([]any)
		for i, elem := range sdArray {
			digest := elem.(string)
			// Base64url should not contain +, /, or =
			for _, char := range []string{"+", "/", "="} {
				if contains(digest, char) {
					t.Errorf("Digest %d contains invalid base64url character '%s': %s", i, char, digest)
				}
			}
			// Should be 43 characters for SHA-256 (256 bits / 6 bits per char ≈ 43)
			if len(digest) != 43 {
				t.Errorf("Digest %d has unexpected length %d, expected 43", i, len(digest))
			}
		}
	})
}

func TestGenerateDecoyDigest(t *testing.T) {
	hashMethod := sha256.New()

	t.Run("generates_unique_digests", func(t *testing.T) {
		digests := make(map[string]bool)
		for range 100 {
			digest, err := generateDecoyDigest(hashMethod)
			if err != nil {
				t.Fatalf("generateDecoyDigest failed: %v", err)
			}
			if digests[digest] {
				t.Errorf("Duplicate digest generated: %s", digest)
			}
			digests[digest] = true
		}

		if len(digests) != 100 {
			t.Errorf("Expected 100 unique digests, got %d", len(digests))
		}
	})

	t.Run("generates_valid_base64url", func(t *testing.T) {
		for range 10 {
			digest, err := generateDecoyDigest(hashMethod)
			if err != nil {
				t.Fatalf("generateDecoyDigest failed: %v", err)
			}

			// Should not contain base64 padding or standard base64 characters
			for _, char := range []string{"+", "/", "="} {
				if contains(digest, char) {
					t.Errorf("Digest contains invalid base64url character '%s': %s", char, digest)
				}
			}

			// Should be 43 characters for SHA-256
			if len(digest) != 43 {
				t.Errorf("Digest has unexpected length %d, expected 43: %s", len(digest), digest)
			}
		}
	})
}

func TestAddDecoyDigestsRecursive(t *testing.T) {
	hashMethod := sha256.New()

	t.Run("adds_decoys_to_single_sd_array", func(t *testing.T) {
		credential := map[string]any{
			"_sd": []any{
				"original-digest-1",
			},
			"_sd_alg": "sha-256",
			"name":    "Alice",
		}

		err := addDecoyDigestsRecursive(credential, hashMethod, 3)
		if err != nil {
			t.Fatalf("addDecoyDigestsRecursive failed: %v", err)
		}

		sdArray := credential["_sd"].([]any)
		if len(sdArray) != 4 {
			t.Errorf("Expected 4 total digests (1 original + 3 decoys), got %d", len(sdArray))
		}

		// Verify original digest is still present
		found := false
		for _, elem := range sdArray {
			if elem.(string) == "original-digest-1" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Original digest was not preserved")
		}
	})

	t.Run("adds_decoys_to_nested_sd_arrays", func(t *testing.T) {
		credential := map[string]any{
			"_sd": []any{
				"top-level-digest",
			},
			"_sd_alg": "sha-256",
			"nested": map[string]any{
				"_sd": []any{
					"nested-digest",
				},
				"value": 123,
			},
		}

		err := addDecoyDigestsRecursive(credential, hashMethod, 2)
		if err != nil {
			t.Fatalf("addDecoyDigestsRecursive failed: %v", err)
		}

		// Check top-level _sd array
		topSD := credential["_sd"].([]any)
		if len(topSD) != 3 {
			t.Errorf("Expected 3 digests in top-level _sd, got %d", len(topSD))
		}

		// Check nested _sd array
		nested := credential["nested"].(map[string]any)
		nestedSD := nested["_sd"].([]any)
		if len(nestedSD) != 3 {
			t.Errorf("Expected 3 digests in nested _sd, got %d", len(nestedSD))
		}
	})

	t.Run("handles_zero_decoys", func(t *testing.T) {
		credential := map[string]any{
			"_sd": []any{
				"original-digest",
			},
			"_sd_alg": "sha-256",
		}

		err := addDecoyDigestsRecursive(credential, hashMethod, 0)
		if err != nil {
			t.Fatalf("addDecoyDigestsRecursive failed: %v", err)
		}

		sdArray := credential["_sd"].([]any)
		if len(sdArray) != 1 {
			t.Errorf("Expected 1 digest (no decoys added), got %d", len(sdArray))
		}
	})

	t.Run("handles_deeply_nested_structures", func(t *testing.T) {
		credential := map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"level3": map[string]any{
						"_sd": []any{
							"deep-digest",
						},
					},
				},
			},
		}

		err := addDecoyDigestsRecursive(credential, hashMethod, 2)
		if err != nil {
			t.Fatalf("addDecoyDigestsRecursive failed: %v", err)
		}

		level3 := credential["level1"].(map[string]any)["level2"].(map[string]any)["level3"].(map[string]any)
		deepSD := level3["_sd"].([]any)
		if len(deepSD) != 3 {
			t.Errorf("Expected 3 digests in deeply nested _sd, got %d", len(deepSD))
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
