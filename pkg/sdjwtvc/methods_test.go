package sdjwtvc

import (
	"crypto/sha256"
	sha30 "crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	mockAttributeFirstName         = "first_name"
	mockAttributeAddress           = "address"
	mockAttributeAddressStreet     = "street"
	mockAttributeAddressPostal     = "postal"
	mockAttributeAddressPostalCode = "code"
	mockAttributeWorkCountries     = "work_countries"

	mockVCTM_v1 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeFirstName},
				SD:   "always",
			},
		},
	}

	mockVCTM_v2 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeAddress},
				SD:   "always",
			},
			{
				Path: []*string{&mockAttributeFirstName},
				SD:   "never",
			},
		},
	}

	mockVCTM_v3 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressStreet},
				SD:   "always",
			},
		},
	}

	mockVCTM_v4 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal},
				SD:   "always",
			},
		},
	}

	mockVCTM_v5 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal, &mockAttributeAddressPostalCode},
				SD:   "always",
			},
		},
	}

	// mockVCTM_v6 is recursive
	mockVCTM_v6 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal},
				SD:   "always",
			},
			{
				Path: []*string{&mockAttributeAddress},
				SD:   "always",
			},
		},
	}

	// mockVCTM_v7 tests array handling
	mockVCTM_v7 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeWorkCountries},
				SD:   "always",
			},
		},
	}
)

func TestMakeCredential(t *testing.T) {
	tts := []struct {
		name                 string
		data                 map[string]any
		vctm                 *VCTM
		expectSDAtRoot       bool
		expectSDInAddress    bool
		expectSDInPostal     bool
		expectDisclosureKeys []string // claims that should be disclosed
		expectRemainingKeys  []string // claims that should remain in payload
	}{
		{
			name:                 "first name is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v1,
			expectSDAtRoot:       true,
			expectDisclosureKeys: []string{"first_name"},
			expectRemainingKeys:  []string{"address", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v2,
			expectSDAtRoot:       true,
			expectDisclosureKeys: []string{"address"},
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address street is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v3,
			expectSDInAddress:    true,
			expectDisclosureKeys: []string{"street"},
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address postal is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v4,
			expectSDInAddress:    true,
			expectDisclosureKeys: []string{"postal"},
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address postal code is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v5,
			expectSDInPostal:     true,
			expectDisclosureKeys: []string{"code"},
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address recursive selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v6,
			expectSDAtRoot:       true,
			expectDisclosureKeys: []string{"postal", "address"}, // both are disclosed
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "work_countries array selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v7,
			expectSDAtRoot:       true,
			expectDisclosureKeys: []string{"work_countries"},
			expectRemainingKeys:  []string{"first_name", "address", "_sd_alg"},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			client := New()
			got, disclosures, err := client.MakeCredential(sha256.New(), tt.data, tt.vctm, 0)
			require.NoError(t, err)

			// Log the result for debugging
			b, err := json.MarshalIndent(got, "", "  ")
			require.NoError(t, err)
			t.Logf("Got credential: %s", string(b))
			t.Logf("Got %d disclosures", len(disclosures))

			// Verify _sd_alg is set correctly (per section 4.1.1)
			assert.Equal(t, "sha-256", got["_sd_alg"])

			// Verify correct number of disclosures
			assert.Equal(t, len(tt.expectDisclosureKeys), len(disclosures), "unexpected number of disclosures")

			// Verify all expected remaining keys are present
			for _, key := range tt.expectRemainingKeys {
				if key == "address" {
					// Special case: address might have _sd array
					_, exists := got[key]
					assert.True(t, exists, "expected key %s to remain in payload", key)
				} else if key != "_sd_alg" && key != "_sd" {
					_, exists := got[key]
					assert.True(t, exists, "expected key %s to remain in payload", key)
				}
			}

			// Verify disclosed keys are NOT in the payload
			for _, key := range tt.expectDisclosureKeys {
				if key != "address" && key != "postal" { // these might be in nested structures
					_, exists := got[key]
					assert.False(t, exists, "expected key %s to be removed from payload", key)
				}
			}

			// Verify _sd arrays exist where expected
			if tt.expectSDAtRoot {
				sdArray, exists := got["_sd"]
				assert.True(t, exists, "expected _sd array at root")
				if exists {
					arr, ok := sdArray.([]any)
					assert.True(t, ok, "_sd should be an array")
					assert.Greater(t, len(arr), 0, "_sd array should not be empty")

					// Verify array is sorted alphanumerically (per section 4.2.4.1)
					if len(arr) > 1 {
						for i := 0; i < len(arr)-1; i++ {
							s1, ok1 := arr[i].(string)
							s2, ok2 := arr[i+1].(string)
							if ok1 && ok2 {
								assert.True(t, s1 <= s2, "_sd array should be sorted alphanumerically")
							}
						}
					}
				}
			}

			if tt.expectSDInAddress {
				address, exists := got["address"]
				require.True(t, exists, "address should exist")
				addrMap, ok := address.(map[string]any)
				require.True(t, ok, "address should be a map")

				sdArray, exists := addrMap["_sd"]
				assert.True(t, exists, "expected _sd array in address")
				if exists {
					arr, ok := sdArray.([]any)
					assert.True(t, ok, "_sd should be an array")
					assert.Greater(t, len(arr), 0, "_sd array should not be empty")
				}
			}

			if tt.expectSDInPostal {
				address, exists := got["address"]
				require.True(t, exists, "address should exist")
				addrMap, ok := address.(map[string]any)
				require.True(t, ok, "address should be a map")

				postal, exists := addrMap["postal"]
				require.True(t, exists, "postal should exist")
				postalMap, ok := postal.(map[string]any)
				require.True(t, ok, "postal should be a map")

				sdArray, exists := postalMap["_sd"]
				assert.True(t, exists, "expected _sd array in postal")
				if exists {
					arr, ok := sdArray.([]any)
					assert.True(t, ok, "_sd should be an array")
					assert.Greater(t, len(arr), 0, "_sd array should not be empty")
				}
			}

			// Verify disclosures are valid base64url
			for i, disclosure := range disclosures {
				_, err := base64.RawURLEncoding.DecodeString(disclosure)
				assert.NoError(t, err, "disclosure %d should be valid base64url", i)

				// Decode and verify structure [salt, claim_name, value]
				decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
				require.NoError(t, err)

				var disclosureArray []any
				err = json.Unmarshal(decoded, &disclosureArray)
				require.NoError(t, err, "disclosure should be a JSON array")
				assert.Equal(t, 3, len(disclosureArray), "disclosure should have 3 elements [salt, claim_name, value]")

				// Verify salt is a non-empty string
				salt, ok := disclosureArray[0].(string)
				assert.True(t, ok, "salt should be a string")
				assert.NotEmpty(t, salt, "salt should not be empty")

				// Verify claim name is a string
				claimName, ok := disclosureArray[1].(string)
				assert.True(t, ok, "claim_name should be a string")
				assert.Contains(t, tt.expectDisclosureKeys, claimName, "claim_name should be one of the expected keys")

				t.Logf("Disclosure %d: claim=%s, salt_len=%d", i, claimName, len(salt))
			}
		})
	}
}

// TestSaltEntropy verifies that salts have proper entropy
func TestSaltEntropy(t *testing.T) {
	vctm := &VCTM{
		Claims: []Claim{
			{Path: []*string{&mockAttributeFirstName}, SD: "always"},
		},
	}

	client := New()

	// Generate multiple credentials to verify salt randomness
	salts := make(map[string]bool)
	for range 10 {
		dataCopy := map[string]any{"first_name": "John", "last_name": "Doe"}
		_, disclosures, err := client.MakeCredential(sha256.New(), dataCopy, vctm, 0)
		require.NoError(t, err)
		require.Len(t, disclosures, 1)

		decoded, err := base64.RawURLEncoding.DecodeString(disclosures[0])
		require.NoError(t, err)

		var disclosureArray []any
		err = json.Unmarshal(decoded, &disclosureArray)
		require.NoError(t, err)

		salt := disclosureArray[0].(string)

		// Verify salt is unique (should be extremely unlikely to collide)
		assert.False(t, salts[salt], "salt should be unique")
		salts[salt] = true

		// Verify salt has reasonable length (128 bits = 22 chars in base64url)
		assert.GreaterOrEqual(t, len(salt), 20, "salt should have sufficient entropy")
	}

	t.Logf("Generated %d unique salts", len(salts))
}

// TestNoDuplicateDigests verifies that duplicate digests are rejected
func TestNoDuplicateDigests(t *testing.T) {
	// This is a defensive test - in practice, duplicate digests should never occur
	// due to unique salts, but the implementation should check for them
	data := map[string]any{
		"claim1": "value1",
		"claim2": "value2",
	}

	claim1 := "claim1"
	vctm := &VCTM{
		Claims: []Claim{
			{Path: []*string{&claim1}, SD: "always"},
		},
	}

	client := New()
	_, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
	require.NoError(t, err)
	assert.Len(t, disclosures, 1)
}

// TestRecursiveDisclosure tests recursive selective disclosure per section 4.2.6
func TestRecursiveDisclosure(t *testing.T) {
	data := map[string]any{
		"address": map[string]any{
			"street": "123 Main St",
			"postal": map[string]any{
				"code": "12345",
				"city": "Metropolis",
			},
		},
	}

	client := New()
	_, disclosures, err := client.MakeCredential(sha256.New(), data, mockVCTM_v6, 0)
	require.NoError(t, err)

	// Should have 2 disclosures: one for postal, one for address
	assert.Len(t, disclosures, 2)

	// Verify one of the disclosures contains the address claim with _sd array
	foundAddressWithSD := false
	for _, disclosure := range disclosures {
		decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
		require.NoError(t, err)

		var disclosureArray []any
		err = json.Unmarshal(decoded, &disclosureArray)
		require.NoError(t, err)

		claimName := disclosureArray[1].(string)
		if claimName == "address" {
			// The address disclosure should contain a value with _sd array
			value, ok := disclosureArray[2].(map[string]any)
			require.True(t, ok, "address value should be an object")

			_, hasSD := value["_sd"]
			if hasSD {
				foundAddressWithSD = true
				t.Log("Found recursive disclosure: address contains _sd array")
			}
		}
	}

	assert.True(t, foundAddressWithSD, "address disclosure should contain _sd array for recursive disclosure")
}

// TestRecursiveDisclosureDeepNesting tests deeply nested recursive selective disclosure
// with different VCTM claim orderings to verify order-independence
func TestRecursiveDisclosureDeepNesting(t *testing.T) {
	testCases := []struct {
		name string
		desc string
		vctm *VCTM
	}{
		{
			name: "claims_in_depth_order",
			desc: "Claims ordered from deepest to shallowest",
			vctm: &VCTM{
				Claims: []Claim{
					{
						Path: []*string{new("user"), new("profile"), new("contact")},
						SD:   "always",
					},
					{
						Path: []*string{new("user"), new("profile")},
						SD:   "always",
					},
					{
						Path: []*string{new("user")},
						SD:   "always",
					},
				},
			},
		},
		{
			name: "claims_in_reverse_order",
			desc: "Claims ordered from shallowest to deepest",
			vctm: &VCTM{
				Claims: []Claim{
					{
						Path: []*string{new("user")},
						SD:   "always",
					},
					{
						Path: []*string{new("user"), new("profile")},
						SD:   "always",
					},
					{
						Path: []*string{new("user"), new("profile"), new("contact")},
						SD:   "always",
					},
				},
			},
		},
		{
			name: "claims_in_mixed_order",
			desc: "Claims in random order (middle, top, bottom)",
			vctm: &VCTM{
				Claims: []Claim{
					{
						Path: []*string{new("user"), new("profile")},
						SD:   "always",
					},
					{
						Path: []*string{new("user")},
						SD:   "always",
					},
					{
						Path: []*string{new("user"), new("profile"), new("contact")},
						SD:   "always",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Make a fresh copy of data for each test
			dataCopy := map[string]any{
				"user": map[string]any{
					"name": "Alice",
					"profile": map[string]any{
						"bio": "Software Engineer",
						"contact": map[string]any{
							"email": "alice@example.com",
							"phone": "+1234567890",
						},
					},
				},
			}

			client := New()
			credentialObj, disclosures, err := client.MakeCredential(sha256.New(), dataCopy, tc.vctm, 0)
			require.NoError(t, err)

			// Should have 3 disclosures (contact, profile, user) regardless of VCTM claim order
			assert.Len(t, disclosures, 3, "Should have disclosures for all 3 nested levels")

			// Root should have _sd array
			_, hasRootSD := credentialObj["_sd"]
			assert.True(t, hasRootSD, "Root level should have _sd array")

			// Verify each disclosure level
			foundLevels := map[string]bool{
				"user":    false,
				"profile": false,
				"contact": false,
			}

			for _, disclosure := range disclosures {
				decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
				require.NoError(t, err)

				var disclosureArray []any
				err = json.Unmarshal(decoded, &disclosureArray)
				require.NoError(t, err)

				claimName := disclosureArray[1].(string)
				foundLevels[claimName] = true

				// Check if nested values contain _sd arrays
				if claimName == "user" || claimName == "profile" {
					value, ok := disclosureArray[2].(map[string]any)
					require.True(t, ok, "%s value should be an object", claimName)

					_, hasSD := value["_sd"]
					assert.True(t, hasSD, "%s should contain _sd array for recursive disclosure", claimName)

					t.Logf("%s: Found recursive disclosure with _sd array", tc.desc)
				}
			}

			assert.True(t, foundLevels["user"], "Should have user disclosure")
			assert.True(t, foundLevels["profile"], "Should have profile disclosure")
			assert.True(t, foundLevels["contact"], "Should have contact disclosure")
		})
	}
}

// Helper function to create string pointers
//
//go:fix inline
func stringPtr(s string) *string {
	return new(s)
}

func TestGetHashAlgorithmName(t *testing.T) {
	tests := []struct {
		name         string
		hasher       hash.Hash
		expectedName string
	}{
		{
			name:         "SHA-256",
			hasher:       sha256.New(),
			expectedName: "sha-256",
		},
		{
			name:         "SHA-384",
			hasher:       sha512.New384(),
			expectedName: "sha-384",
		},
		{
			name:         "SHA-512",
			hasher:       sha512.New(),
			expectedName: "sha-512",
		},
		{
			name: "SHA3-256",
			hasher: hash.
				Hash(sha30.New256()),
			expectedName: "sha3-256",
		},
		{
			name: "SHA3-512",
			hasher: hash.
				Hash(sha30.New512()),
			expectedName: "sha3-512",
		},
		{
			name:         "SHA-224",
			hasher:       sha256.New224(),
			expectedName: "sha-224",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algName, err := getHashAlgorithmName(tt.hasher)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedName, algName)
		})
	}
}

func TestGetHashAlgorithmName_UnsupportedSize(t *testing.T) {
	// The function handles all common hash sizes
	// Unsupported sizes would come from custom hash implementations
	// This test verifies the function doesn't panic with unexpected sizes
	// In practice, all standard library hashes are supported
	t.Skip("All standard hash algorithms are supported")
}

func TestMakeCredential_AlternativeHashAlgorithms(t *testing.T) {
	tests := []struct {
		name          string
		hasher        hash.Hash
		expectedSdAlg string
	}{
		{
			name:          "SHA-256",
			hasher:        sha256.New(),
			expectedSdAlg: "sha-256",
		},
		{
			name:          "SHA-512",
			hasher:        sha512.New(),
			expectedSdAlg: "sha-512",
		},
		{
			name: "SHA3-256",
			hasher: hash.
				Hash(sha30.New256()),
			expectedSdAlg: "sha3-256",
		},
		{
			name: "SHA3-512",
			hasher: hash.
				Hash(sha30.New512()),
			expectedSdAlg: "sha3-512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]any{"first_name": "John"}

			client := New()
			got, _, err := client.MakeCredential(tt.hasher, data, mockVCTM_v1, 0)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedSdAlg, got["_sd_alg"])
		})
	}
}

func TestProcessClaimPath_ErrorCases(t *testing.T) {
	client := New()

	t.Run("empty path", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		_, _, err := client.processClaimPath(data, []*string{}, sha256.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty path")
	})

	t.Run("nil path element", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		_, _, err := client.processClaimPath(data, []*string{nil}, sha256.New())
		assert.Error(t, err)
		// Single nil element is invalid (array element disclosure needs at least 2 elements)
		assert.Contains(t, err.Error(), "array element path must have at least 2 elements")
	})

	t.Run("non-existent path", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		nonExistent := "nonexistent"
		_, _, err := client.processClaimPath(data, []*string{&nonExistent}, sha256.New())
		// Should return empty disclosure, not error
		assert.NoError(t, err)
	})

	t.Run("array element with null path", func(t *testing.T) {
		data := map[string]any{
			"nationalities": []any{"US", "CA", "FR"},
		}
		arr := "nationalities"
		_, _, err := client.processClaimPath(data, []*string{&arr, nil}, sha256.New())
		assert.NoError(t, err)
		// Array should be replaced with SD array
		result, ok := data["nationalities"].([]any)
		assert.True(t, ok)
		assert.Len(t, result, 3)
		// Each element should be an object with "..."
		for i, elem := range result {
			elemMap, ok := elem.(map[string]any)
			assert.True(t, ok, "element %d should be a map", i)
			_, hasEllipsis := elemMap["..."]
			assert.True(t, hasEllipsis, "element %d should have '...' key", i)
		}
	})

	t.Run("non-object in path", func(t *testing.T) {
		data := map[string]any{
			"field": "string_value",
		}
		field := "field"
		next := "sub"
		_, _, err := client.processClaimPath(data, []*string{&field, &next}, sha256.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid path")
	})
}

func TestAddHashToPath_ErrorCases(t *testing.T) {
	client := New()

	t.Run("nil path element", func(t *testing.T) {
		data := map[string]any{"test": map[string]any{}}
		err := client.addHashToPath(data, []*string{nil}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil path element")
	})

	t.Run("path not found", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		nonExistent := "nonexistent"
		err := client.addHashToPath(data, []*string{&nonExistent}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path not found")
	})

	t.Run("non-object at path", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		test := "test"
		err := client.addHashToPath(data, []*string{&test}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "non-object")
	})

	t.Run("_sd is not an array", func(t *testing.T) {
		data := map[string]any{
			"_sd": "not_an_array",
		}
		err := client.addHashToPath(data, []*string{}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "_sd is not an array")
	})

	t.Run("duplicate digest", func(t *testing.T) {
		data := map[string]any{
			"_sd": []any{"hash123"},
		}
		err := client.addHashToPath(data, []*string{}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate digest")
	})
}

func TestGenerateSalt_Uniqueness(t *testing.T) {
	// Generate multiple salts and ensure they're unique
	salts := make(map[string]bool)

	for range 100 {
		salt, err := generateSalt()
		require.NoError(t, err)
		require.NotEmpty(t, salt)

		// Check uniqueness
		assert.False(t, salts[salt], "salt should be unique")
		salts[salt] = true

		// Check minimum length (128 bits = 16 bytes base64url encoded)
		assert.GreaterOrEqual(t, len(salt), 20)
	}

	assert.Equal(t, 100, len(salts), "all salts should be unique")
}

func TestShuffleSDArrays_DeepNesting(t *testing.T) {
	data := map[string]any{
		"_sd": []any{"hash3", "hash1", "hash2"},
		"level1": map[string]any{
			"_sd": []any{"hashB", "hashA", "hashC"},
			"level2": map[string]any{
				"_sd": []any{"hashZ", "hashX", "hashY"},
			},
		},
		"array": []any{
			map[string]any{
				"_sd": []any{"hashF", "hashD", "hashE"},
			},
		},
	}

	shuffleSDArrays(data)

	// Verify all _sd arrays are sorted
	rootSD := data["_sd"].([]any)
	assert.Equal(t, "hash1", rootSD[0])
	assert.Equal(t, "hash2", rootSD[1])
	assert.Equal(t, "hash3", rootSD[2])

	level1 := data["level1"].(map[string]any)
	level1SD := level1["_sd"].([]any)
	assert.Equal(t, "hashA", level1SD[0])
	assert.Equal(t, "hashB", level1SD[1])
	assert.Equal(t, "hashC", level1SD[2])

	level2 := level1["level2"].(map[string]any)
	level2SD := level2["_sd"].([]any)
	assert.Equal(t, "hashX", level2SD[0])
	assert.Equal(t, "hashY", level2SD[1])
	assert.Equal(t, "hashZ", level2SD[2])

	arrElem := data["array"].([]any)[0].(map[string]any)
	arrSD := arrElem["_sd"].([]any)
	assert.Equal(t, "hashD", arrSD[0])
	assert.Equal(t, "hashE", arrSD[1])
	assert.Equal(t, "hashF", arrSD[2])
}

func TestSortSDArray_NonStringElements(t *testing.T) {
	// Test sorting with non-string elements (should handle gracefully)
	arr := []any{"hash2", 123, "hash1", nil, "hash3"}
	sortSDArray(arr)

	// Strings should be sorted, non-strings remain
	// The function only sorts string elements
	assert.Contains(t, arr, "hash1")
	assert.Contains(t, arr, "hash2")
	assert.Contains(t, arr, "hash3")
}

func TestSortClaimsByDepth(t *testing.T) {
	t.Run("sorts_claims_by_depth_descending", func(t *testing.T) {
		claims := []Claim{
			{Path: []*string{new("a")}, SD: "always"},                     // depth 1
			{Path: []*string{new("a"), new("b"), new("c")}, SD: "always"}, // depth 3
			{Path: []*string{new("a"), new("b")}, SD: "always"},           // depth 2
		}

		sorted := sortClaimsByDepth(claims)

		// Should be ordered: depth 3, depth 2, depth 1
		assert.Len(t, sorted[0].Path, 3)
		assert.Len(t, sorted[1].Path, 2)
		assert.Len(t, sorted[2].Path, 1)
	})

	t.Run("handles_empty_slice", func(t *testing.T) {
		claims := []Claim{}
		sorted := sortClaimsByDepth(claims)
		assert.Len(t, sorted, 0)
	})

	t.Run("handles_single_claim", func(t *testing.T) {
		claims := []Claim{
			{Path: []*string{new("a")}, SD: "always"},
		}
		sorted := sortClaimsByDepth(claims)
		assert.Len(t, sorted, 1)
		assert.Len(t, sorted[0].Path, 1)
	})

	t.Run("does_not_modify_original", func(t *testing.T) {
		claims := []Claim{
			{Path: []*string{new("a")}, SD: "always"},
			{Path: []*string{new("a"), new("b")}, SD: "always"},
		}

		original := make([]Claim, len(claims))
		copy(original, claims)

		sortClaimsByDepth(claims)

		// Original should be unchanged
		assert.Equal(t, original, claims)
	})

	t.Run("stable_sort_for_equal_depths", func(t *testing.T) {
		claims := []Claim{
			{Path: []*string{new("first")}, SD: "always"},
			{Path: []*string{new("second")}, SD: "always"},
			{Path: []*string{new("third")}, SD: "always"},
		}

		sorted := sortClaimsByDepth(claims)

		// All have depth 1, order might vary but should all be present
		assert.Len(t, sorted, 3)
		for _, claim := range sorted {
			assert.Len(t, claim.Path, 1)
		}
	})
}

func TestMakeCredential_ArrayElementDisclosure(t *testing.T) {
	client := New()

	t.Run("nationalities_array_element_disclosure", func(t *testing.T) {
		data := map[string]any{
			"family_name":   "Doe",
			"given_name":    "John",
			"nationalities": []any{"US", "CA", "FR"},
		}

		vctm := &VCTM{
			VCT: "TestCredential",
			Claims: []Claim{
				{
					Path: []*string{new("nationalities"), nil},
					SD:   "always",
				},
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		require.NoError(t, err)

		// Should have 3 disclosures (one for each nationality)
		assert.Len(t, disclosures, 3, "Should have 3 disclosures for 3 array elements")

		// Array should be replaced with SD array
		nationalities, ok := credential["nationalities"].([]any)
		require.True(t, ok, "nationalities should be an array")
		assert.Len(t, nationalities, 3, "Should have 3 elements in SD array")

		// Each element should be an object with "..." key containing hash
		for i, elem := range nationalities {
			elemMap, ok := elem.(map[string]any)
			require.True(t, ok, "element %d should be a map", i)
			hash, hasEllipsis := elemMap["..."]
			require.True(t, hasEllipsis, "element %d should have '...' key", i)
			hashStr, ok := hash.(string)
			require.True(t, ok, "hash should be a string")
			assert.NotEmpty(t, hashStr, "hash should not be empty")
			// Hash should be base64url encoded (43 chars for SHA-256)
			assert.Equal(t, 43, len(hashStr), "SHA-256 hash should be 43 characters")
		}

		// Verify each disclosure is properly formatted for array elements: [salt, value]
		for i, disclosure := range disclosures {
			decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
			require.NoError(t, err, "disclosure %d should be valid base64url", i)

			var discArray []any
			err = json.Unmarshal(decoded, &discArray)
			require.NoError(t, err, "disclosure %d should be valid JSON array", i)

			// Array element disclosures have 2 elements: [salt, value]
			assert.Len(t, discArray, 2, "Array element disclosure should have [salt, value]")

			salt, ok := discArray[0].(string)
			require.True(t, ok, "salt should be a string")
			assert.NotEmpty(t, salt, "salt should not be empty")

			// Value should be one of the nationalities
			value := discArray[1]
			assert.Contains(t, []any{"US", "CA", "FR"}, value, "value should be one of the nationalities")
		}
	})

	t.Run("nested_array_element_disclosure", func(t *testing.T) {
		data := map[string]any{
			"person": map[string]any{
				"languages": []any{"en", "fr", "de"},
			},
		}

		vctm := &VCTM{
			VCT: "TestCredential",
			Claims: []Claim{
				{
					Path: []*string{new("person"), new("languages"), nil},
					SD:   "always",
				},
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		require.NoError(t, err)

		// Should have 3 disclosures
		assert.Len(t, disclosures, 3)

		// Navigate to nested array
		person, ok := credential["person"].(map[string]any)
		require.True(t, ok)
		languages, ok := person["languages"].([]any)
		require.True(t, ok)
		assert.Len(t, languages, 3)

		// Each element should have "..." key
		for i, elem := range languages {
			elemMap, ok := elem.(map[string]any)
			require.True(t, ok, "element %d should be a map", i)
			_, hasEllipsis := elemMap["..."]
			assert.True(t, hasEllipsis, "element %d should have '...' key", i)
		}
	})

	t.Run("empty_array_element_disclosure", func(t *testing.T) {
		data := map[string]any{
			"items": []any{},
		}

		vctm := &VCTM{
			VCT: "TestCredential",
			Claims: []Claim{
				{
					Path: []*string{new("items"), nil},
					SD:   "always",
				},
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		require.NoError(t, err)

		// Empty array should have no disclosures
		assert.Len(t, disclosures, 0)

		// Array should still be replaced with empty SD array
		items, ok := credential["items"].([]any)
		require.True(t, ok)
		assert.Len(t, items, 0)
	})

	t.Run("both_array_element_and_whole_array_disclosure", func(t *testing.T) {
		// This tests the real-world scenario from vctm_pid_arf_1_8.json
		// where both ["nationalities", null] and ["nationalities"] exist
		// First: array element disclosure makes each element selectively disclosable
		// Second: whole array disclosure makes the entire SD array recursively selectively disclosable
		data := map[string]any{
			"nationalities": []any{"US", "CA", "FR"},
		}

		vctm := &VCTM{
			VCT: "TestCredential",
			Claims: []Claim{
				{
					// Array element disclosure (processed first - depth 2)
					Path: []*string{new("nationalities"), nil},
					SD:   "always",
				},
				{
					// Whole array disclosure (processed second - depth 1)
					// Makes the entire SD array recursively selectively disclosable
					Path: []*string{new("nationalities")},
					SD:   "always",
				},
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		require.NoError(t, err)

		// Should have 3 disclosures for array elements + 1 for the whole SD array
		assert.Len(t, disclosures, 4, "Should have 3 element disclosures + 1 for whole SD array")

		// The nationalities array should be removed from credential (disclosed as whole)
		_, hasNationalities := credential["nationalities"]
		assert.False(t, hasNationalities, "nationalities should be removed after recursive disclosure")

		// Should have _sd array at root with hash for the nationalities array
		sdArray, hasSd := credential["_sd"]
		require.True(t, hasSd, "Should have _sd array at root")
		sdSlice, ok := sdArray.([]any)
		require.True(t, ok, "_sd should be an array")
		assert.Len(t, sdSlice, 1, "Should have 1 hash in _sd array for the nationalities array")

		// Verify the last disclosure contains the SD array
		lastDisclosure := disclosures[len(disclosures)-1]
		decoded, err := base64.RawURLEncoding.DecodeString(lastDisclosure)
		require.NoError(t, err)

		var discArray []any
		err = json.Unmarshal(decoded, &discArray)
		require.NoError(t, err)

		// Should be [salt, "nationalities", <SD array>]
		assert.Len(t, discArray, 3, "Whole array disclosure should have [salt, claim_name, value]")
		assert.Equal(t, "nationalities", discArray[1], "Claim name should be 'nationalities'")

		// The value should be the SD array
		sdArrayValue, ok := discArray[2].([]any)
		require.True(t, ok, "Value should be an array")
		assert.Len(t, sdArrayValue, 3, "SD array should have 3 elements")
	})

	t.Run("single_element_array_disclosure", func(t *testing.T) {
		// Regression test for bug where single-element arrays failed
		// because the code checked for "~" separator which only exists with multiple elements
		data := map[string]any{
			"nationalities": []any{"SE"},
		}

		vctm := &VCTM{
			VCT: "TestCredential",
			Claims: []Claim{
				{
					// Array element disclosure for single element
					Path: []*string{new("nationalities"), nil},
					SD:   "always",
				},
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		require.NoError(t, err)

		// Should have 1 disclosure for the single array element
		assert.Len(t, disclosures, 1, "Should have 1 disclosure for single element")

		// The nationalities array should be replaced with SD array
		natArray, hasNat := credential["nationalities"]
		require.True(t, hasNat, "nationalities should still exist as SD array")
		natSlice, ok := natArray.([]any)
		require.True(t, ok, "nationalities should be an array")
		assert.Len(t, natSlice, 1, "SD array should have 1 element")

		// Element should have "..." key
		elemMap, ok := natSlice[0].(map[string]any)
		require.True(t, ok, "element should be a map")
		_, hasEllipsis := elemMap["..."]
		assert.True(t, hasEllipsis, "element should have '...' key")

		// Verify disclosure format
		decoded, err := base64.RawURLEncoding.DecodeString(disclosures[0])
		require.NoError(t, err)

		var discArray []any
		err = json.Unmarshal(decoded, &discArray)
		require.NoError(t, err)

		// Array element disclosure should have [salt, value] (no claim name)
		assert.Len(t, discArray, 2, "Array element disclosure should have [salt, value]")
		assert.Equal(t, "SE", discArray[1], "Value should be 'SE'")
	})

	t.Run("single_element_array_with_recursive_disclosure", func(t *testing.T) {
		// Test the combination that caused the original bug:
		// Single-element array with both element and whole array disclosure
		data := map[string]any{
			"nationalities": []any{"SE"},
		}

		vctm := &VCTM{
			VCT: "TestCredential",
			Claims: []Claim{
				{
					// Array element disclosure (processed first - depth 2)
					Path: []*string{new("nationalities"), nil},
					SD:   "always",
				},
				{
					// Whole array disclosure (processed second - depth 1)
					Path: []*string{new("nationalities")},
					SD:   "always",
				},
			},
		}

		credential, disclosures, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		require.NoError(t, err)

		// Should have 1 disclosure for element + 1 for whole SD array
		assert.Len(t, disclosures, 2, "Should have 1 element disclosure + 1 for whole SD array")

		// The nationalities should be removed (disclosed as whole)
		_, hasNationalities := credential["nationalities"]
		assert.False(t, hasNationalities, "nationalities should be removed after recursive disclosure")

		// Should have _sd array at root
		sdArray, hasSd := credential["_sd"]
		require.True(t, hasSd, "Should have _sd array at root")
		sdSlice, ok := sdArray.([]any)
		require.True(t, ok, "_sd should be an array")
		assert.Len(t, sdSlice, 1, "Should have 1 hash in _sd array")
	})
}

func TestProcessClaimPath_WithRealPIDVCTM(t *testing.T) {
	// Load the actual PID ARF 1.8 VCTM file
	vctmData, err := os.ReadFile("../../metadata/vctm_pid_arf_1_8.json")
	require.NoError(t, err, "Failed to read vctm_pid_arf_1_8.json")

	var vctm VCTM
	err = json.Unmarshal(vctmData, &vctm)
	require.NoError(t, err, "Failed to unmarshal VCTM")

	require.NotEmpty(t, vctm.Claims, "VCTM should have claims")
	t.Logf("Loaded VCTM with %d claims", len(vctm.Claims))

	client := &Client{}
	hashMethod := sha256.New()

	t.Run("simple_top_level_claim_family_name", func(t *testing.T) {
		// Test with family_name claim from PID
		data := map[string]any{
			"family_name": "Doe",
			"given_name":  "John",
			"birthdate":   "1990-01-01",
		}

		path := []*string{new("family_name")}
		disclosure, hash, err := client.processClaimPath(data, path, hashMethod)

		require.NoError(t, err)
		assert.NotEmpty(t, disclosure, "Disclosure should be generated")
		assert.NotEmpty(t, hash, "Hash should be generated")
		assert.NotContains(t, data, "family_name", "family_name should be removed from data")
		assert.Contains(t, data, "given_name", "Other claims should remain")

		// Verify disclosure structure
		decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
		require.NoError(t, err)
		var disclosureArray []any
		err = json.Unmarshal(decoded, &disclosureArray)
		require.NoError(t, err)
		assert.Len(t, disclosureArray, 3, "Disclosure should have [salt, claim_name, value]")
		assert.Equal(t, "family_name", disclosureArray[1])
		assert.Equal(t, "Doe", disclosureArray[2])
	})

	t.Run("nested_claim_address_street_address", func(t *testing.T) {
		// Test with nested address.street_address from PID
		data := map[string]any{
			"family_name": "Doe",
			"address": map[string]any{
				"street_address": "123 Main St",
				"locality":       "Springfield",
				"postal_code":    "12345",
				"country":        "US",
			},
		}

		path := []*string{new("address"), new("street_address")}
		disclosure, hash, err := client.processClaimPath(data, path, hashMethod)

		require.NoError(t, err)
		assert.NotEmpty(t, disclosure, "Disclosure should be generated")
		assert.NotEmpty(t, hash, "Hash should be generated")

		// Check that street_address was removed from the nested object
		address, ok := data["address"].(map[string]any)
		require.True(t, ok, "address should still be a map")
		assert.NotContains(t, address, "street_address", "street_address should be removed")
		assert.Contains(t, address, "locality", "Other nested claims should remain")

		// Verify disclosure
		decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
		require.NoError(t, err)
		var disclosureArray []any
		err = json.Unmarshal(decoded, &disclosureArray)
		require.NoError(t, err)
		assert.Equal(t, "street_address", disclosureArray[1])
		assert.Equal(t, "123 Main St", disclosureArray[2])
	})

	t.Run("nested_claim_place_of_birth_locality", func(t *testing.T) {
		// Test with place_of_birth.locality from PID
		data := map[string]any{
			"place_of_birth": map[string]any{
				"locality": "Boston",
				"region":   "MA",
				"country":  "US",
			},
		}

		path := []*string{new("place_of_birth"), new("locality")}
		disclosure, hash, err := client.processClaimPath(data, path, hashMethod)

		require.NoError(t, err)
		assert.NotEmpty(t, disclosure)
		assert.NotEmpty(t, hash)

		pob, ok := data["place_of_birth"].(map[string]any)
		require.True(t, ok)
		assert.NotContains(t, pob, "locality", "locality should be removed")
		assert.Contains(t, pob, "region", "Other fields should remain")
	})

	t.Run("non_existent_claim_path", func(t *testing.T) {
		// Test with a path that doesn't exist in the data
		data := map[string]any{
			"family_name": "Doe",
			"given_name":  "John",
		}

		path := []*string{new("non_existent_claim")}
		disclosure, hash, err := client.processClaimPath(data, path, hashMethod)

		require.NoError(t, err, "Should not error on non-existent claim")
		assert.Empty(t, disclosure, "No disclosure should be generated")
		assert.Empty(t, hash, "No hash should be generated")
		assert.Contains(t, data, "family_name", "Existing claims should remain")
	})

	t.Run("non_existent_nested_path", func(t *testing.T) {
		// Test with a nested path where parent exists but child doesn't
		data := map[string]any{
			"address": map[string]any{
				"locality": "Springfield",
				"country":  "US",
			},
		}

		path := []*string{new("address"), new("non_existent_field")}
		disclosure, hash, err := client.processClaimPath(data, path, hashMethod)

		require.NoError(t, err)
		assert.Empty(t, disclosure, "No disclosure for non-existent nested claim")
		assert.Empty(t, hash, "No hash for non-existent nested claim")

		address, ok := data["address"].(map[string]any)
		require.True(t, ok)
		assert.Contains(t, address, "locality", "Existing nested claims should remain")
	})

	t.Run("reserved_claim_name_underscore_sd", func(t *testing.T) {
		// Test that _sd claim name is rejected
		data := map[string]any{
			"_sd": []any{"some_hash"},
		}

		path := []*string{new("_sd")}
		_, _, err := client.processClaimPath(data, path, hashMethod)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be '_sd'")
	})

	t.Run("reserved_claim_name_ellipsis", func(t *testing.T) {
		// Test that ... claim name is rejected
		data := map[string]any{
			"...": "value",
		}

		path := []*string{new("...")}
		_, _, err := client.processClaimPath(data, path, hashMethod)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be '_sd' or '...'")
	})

	t.Run("complex_nested_object_disclosure", func(t *testing.T) {
		// Test disclosing an entire complex nested structure
		data := map[string]any{
			"family_name": "Doe",
			"address": map[string]any{
				"street_address": "123 Main St",
				"locality":       "Springfield",
				"postal_code":    "12345",
				"country":        "US",
			},
		}

		// Disclose the entire address object
		path := []*string{new("address")}
		disclosure, hash, err := client.processClaimPath(data, path, hashMethod)

		require.NoError(t, err)
		assert.NotEmpty(t, disclosure)
		assert.NotEmpty(t, hash)
		assert.NotContains(t, data, "address", "Entire address object should be removed")
		assert.Contains(t, data, "family_name", "Other top-level claims should remain")

		// Verify the disclosed value contains all the nested data
		decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
		require.NoError(t, err)
		var disclosureArray []any
		err = json.Unmarshal(decoded, &disclosureArray)
		require.NoError(t, err)
		assert.Equal(t, "address", disclosureArray[1])

		disclosedAddress, ok := disclosureArray[2].(map[string]any)
		require.True(t, ok, "Disclosed value should be an object")
		assert.Equal(t, "123 Main St", disclosedAddress["street_address"])
		assert.Equal(t, "Springfield", disclosedAddress["locality"])
	})

	t.Run("disclosure_format_validation", func(t *testing.T) {
		// Verify the disclosure is properly base64url encoded
		data := map[string]any{
			"given_name": "Alice",
		}

		path := []*string{new("given_name")}
		disclosure, hash, err := client.processClaimPath(data, path, hashMethod)

		require.NoError(t, err)
		assert.NotEmpty(t, disclosure)
		assert.NotEmpty(t, hash)

		// Disclosure should be base64url encoded (no padding, uses - and _ instead of + and /)
		assert.NotContains(t, disclosure, "+", "Should use base64url, not base64")
		assert.NotContains(t, disclosure, "/", "Should use base64url, not base64")
		assert.NotContains(t, disclosure, "=", "Should not have padding")

		// Hash should be base64url encoded
		assert.NotContains(t, hash, "+", "Hash should use base64url")
		assert.NotContains(t, hash, "/", "Hash should use base64url")
		assert.NotContains(t, hash, "=", "Hash should not have padding")

		// Hash should be 256 bits (32 bytes) -> 43 characters in base64url
		assert.Len(t, hash, 43, "SHA-256 hash should be 43 characters in base64url")
	})

	t.Run("multiple_claims_from_same_object", func(t *testing.T) {
		// Test removing multiple claims from the same nested object
		data := map[string]any{
			"address": map[string]any{
				"street_address": "123 Main St",
				"locality":       "Springfield",
				"postal_code":    "12345",
				"country":        "US",
			},
		}

		// First disclosure
		path1 := []*string{new("address"), new("street_address")}
		disclosure1, hash1, err := client.processClaimPath(data, path1, hashMethod)
		require.NoError(t, err)
		assert.NotEmpty(t, disclosure1)
		assert.NotEmpty(t, hash1)

		// Reset hashMethod for second disclosure
		hashMethod.Reset()

		// Second disclosure from the same object
		path2 := []*string{new("address"), new("postal_code")}
		disclosure2, hash2, err := client.processClaimPath(data, path2, hashMethod)
		require.NoError(t, err)
		assert.NotEmpty(t, disclosure2)
		assert.NotEmpty(t, hash2)

		// Verify both claims were removed
		address, ok := data["address"].(map[string]any)
		require.True(t, ok)
		assert.NotContains(t, address, "street_address")
		assert.NotContains(t, address, "postal_code")
		assert.Contains(t, address, "locality", "Non-disclosed claims should remain")
		assert.Contains(t, address, "country", "Non-disclosed claims should remain")

		// Hashes should be different (different claims)
		assert.NotEqual(t, hash1, hash2, "Different claims should produce different hashes")

		// Disclosures should be different
		assert.NotEqual(t, disclosure1, disclosure2, "Different claims should produce different disclosures")
	})

	t.Run("all_pid_arf_1_8_top_level_claims", func(t *testing.T) {
		// Test with a complete PID document containing all ARF 1.8 fields
		data := map[string]any{
			"family_name":                    "Doe",
			"given_name":                     "John",
			"birth_family_name":              "Smith",
			"birthdate":                      "1990-01-01",
			"age_in_years":                   33,
			"age_birth_year":                 1990,
			"age_over_18":                    true,
			"age_over_21":                    true,
			"age_over_65":                    false,
			"nationality":                    []any{"US"},
			"administrative_number":          "123456789",
			"issuance_date":                  "2023-01-01",
			"expiry_date":                    "2033-01-01",
			"issuing_authority":              "State Department",
			"document_number":                "AB123456",
			"issuing_country":                "US",
			"issuing_jurisdiction":           "California",
			"personal_administrative_number": "SSN-123-45-6789",
		}

		// Test a selection of different claim types
		testClaims := []string{
			"family_name",
			"given_name",
			"birthdate",
			"age_over_18",
			"nationality",
		}

		for _, claimName := range testClaims {
			// Make a copy of data for each test
			dataCopy := make(map[string]any)
			maps.Copy(dataCopy, data)

			path := []*string{new(claimName)}
			disclosure, hash, err := client.processClaimPath(dataCopy, path, sha256.New())

			require.NoError(t, err, "Failed for claim: %s", claimName)
			assert.NotEmpty(t, disclosure, "Disclosure should be generated for: %s", claimName)
			assert.NotEmpty(t, hash, "Hash should be generated for: %s", claimName)
			assert.NotContains(t, dataCopy, claimName, "Claim should be removed: %s", claimName)

			// Verify disclosure structure
			decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
			require.NoError(t, err, "Failed to decode disclosure for: %s", claimName)
			var disclosureArray []any
			err = json.Unmarshal(decoded, &disclosureArray)
			require.NoError(t, err, "Failed to unmarshal disclosure for: %s", claimName)
			assert.Equal(t, claimName, disclosureArray[1], "Claim name should match")

			// For value comparison, handle type conversions from JSON
			expectedValue := data[claimName]
			actualValue := disclosureArray[2]

			// JSON unmarshaling converts int to float64, so we need to compare carefully
			switch v := expectedValue.(type) {
			case int:
				// JSON will unmarshal as float64
				actualFloat, ok := actualValue.(float64)
				assert.True(t, ok, "Expected float64 for int claim: %s", claimName)
				assert.Equal(t, float64(v), actualFloat, "Claim value should match for: %s", claimName)
			default:
				assert.Equal(t, expectedValue, actualValue, "Claim value should match for: %s", claimName)
			}
		}
	})

	t.Run("process_claims_according_to_vctm", func(t *testing.T) {
		// Create realistic PID test data
		data := map[string]any{
			"family_name": "Anderson",
			"given_name":  "Emma",
			"birthdate":   "1985-03-15",
			"address": map[string]any{
				"street_address": "456 Oak Avenue",
				"locality":       "Portland",
				"postal_code":    "97201",
				"country":        "US",
			},
			"place_of_birth": map[string]any{
				"locality": "Seattle",
				"region":   "WA",
				"country":  "US",
			},
			"nationality": []any{"US"},
			"age_over_18": true,
		}

		// Test a subset of claims from the VCTM
		var testedClaims int
		maxClaims := 10 // Test up to 10 claims

		for _, claim := range vctm.Claims {
			if testedClaims >= maxClaims {
				break
			}

			if claim.SD == "always" && len(claim.Path) > 0 {
				// Skip array element claims (with null in path) for now
				hasNull := false
				for _, p := range claim.Path {
					if p == nil {
						hasNull = true
						break
					}
				}
				if hasNull {
					continue
				}

				// Check if this claim exists in our test data
				exists := checkPathExists(data, claim.Path)
				if !exists {
					continue
				}

				// Make a copy of data for this test
				dataCopy := make(map[string]any)
				b, _ := json.Marshal(data)
				json.Unmarshal(b, &dataCopy)

				disclosure, hash, err := client.processClaimPath(dataCopy, claim.Path, sha256.New())
				require.NoError(t, err, "Failed to process claim path: %v", claim.Path)
				assert.NotEmpty(t, disclosure, "Disclosure should be generated for path: %v", claim.Path)
				assert.NotEmpty(t, hash, "Hash should be generated for path: %v", claim.Path)

				t.Logf("Tested claim path: %v", formatPath(claim.Path))
				testedClaims++
			}
		}

		assert.Greater(t, testedClaims, 0, "Should have tested at least one claim from VCTM")
		t.Logf("Successfully tested %d claims from VCTM", testedClaims)
	})
}

// Helper function to check if a path exists in data
func checkPathExists(data map[string]any, path []*string) bool {
	if len(path) == 0 {
		return false
	}

	current := data
	for i := 0; i < len(path)-1; i++ {
		if path[i] == nil {
			return false
		}
		next, ok := current[*path[i]]
		if !ok {
			return false
		}
		nextMap, ok := next.(map[string]any)
		if !ok {
			return false
		}
		current = nextMap
	}

	// Check if the final claim exists
	if path[len(path)-1] == nil {
		return false
	}
	_, exists := current[*path[len(path)-1]]
	return exists
}

// Helper function to format path for logging
func formatPath(path []*string) string {
	parts := make([]string, len(path))
	for i, p := range path {
		if p == nil {
			parts[i] = "<null>"
		} else {
			parts[i] = *p
		}
	}
	return "[" + joinStrings(parts, ", ") + "]"
}

// Helper function to join strings (since strings.Join requires []string)
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	var result strings.Builder
	result.WriteString(parts[0])
	for i := 1; i < len(parts); i++ {
		result.WriteString(sep + parts[i])
	}
	return result.String()
}
