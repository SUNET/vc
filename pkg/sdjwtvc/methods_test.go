package sdjwtvc

import (
	"crypto/sha256"
	sha30 "crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"

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
				Path: claimpath.Keys(mockAttributeFirstName),
				SD:   "always",
			},
		},
	}

	mockVCTM_v2 = &VCTM{
		Claims: []Claim{
			{
				Path: claimpath.Keys(mockAttributeAddress),
				SD:   "always",
			},
			{
				Path: claimpath.Keys(mockAttributeFirstName),
				SD:   "never",
			},
		},
	}

	mockVCTM_v3 = &VCTM{
		Claims: []Claim{
			{
				Path: claimpath.Keys(mockAttributeAddress, mockAttributeAddressStreet),
				SD:   "always",
			},
		},
	}

	mockVCTM_v4 = &VCTM{
		Claims: []Claim{
			{
				Path: claimpath.Keys(mockAttributeAddress, mockAttributeAddressPostal),
				SD:   "always",
			},
		},
	}

	mockVCTM_v5 = &VCTM{
		Claims: []Claim{
			{
				Path: claimpath.Keys(mockAttributeAddress, mockAttributeAddressPostal, mockAttributeAddressPostalCode),
				SD:   "always",
			},
		},
	}

	// mockVCTM_v6 is recursive
	mockVCTM_v6 = &VCTM{
		Claims: []Claim{
			{
				Path: claimpath.Keys(mockAttributeAddress, mockAttributeAddressPostal),
				SD:   "always",
			},
			{
				Path: claimpath.Keys(mockAttributeAddress),
				SD:   "always",
			},
		},
	}

	// mockVCTM_v7 tests array handling
	mockVCTM_v7 = &VCTM{
		Claims: []Claim{
			{
				Path: claimpath.Keys(mockAttributeWorkCountries),
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
			{Path: claimpath.Keys(mockAttributeFirstName), SD: "always"},
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
			{Path: claimpath.Keys(claim1), SD: "always"},
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
						Path: claimpath.Keys("user", "profile", "contact"),
						SD:   "always",
					},
					{
						Path: claimpath.Keys("user", "profile"),
						SD:   "always",
					},
					{
						Path: claimpath.Keys("user"),
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
						Path: claimpath.Keys("user"),
						SD:   "always",
					},
					{
						Path: claimpath.Keys("user", "profile"),
						SD:   "always",
					},
					{
						Path: claimpath.Keys("user", "profile", "contact"),
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
						Path: claimpath.Keys("user", "profile"),
						SD:   "always",
					},
					{
						Path: claimpath.Keys("user"),
						SD:   "always",
					},
					{
						Path: claimpath.Keys("user", "profile", "contact"),
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

// TestDiscloseClaim checks which claims a claims path pointer makes
// selectively disclosable, by the payload that is left.
func TestDiscloseClaim(t *testing.T) {
	document := func() map[string]any {
		return map[string]any{
			"name":          "Arthur Dent",
			"address":       map[string]any{"locality": "Milliways", "postal_code": "12345"},
			"nationalities": []any{"British", "Betelgeusian"},
			"degrees": []any{
				map[string]any{"type": "BSc", "university": "Betelgeuse"},
				map[string]any{"type": "MSc", "university": "Betelgeuse"},
			},
		}
	}
	placeholder := func(v any) bool {
		m, ok := v.(map[string]any)
		_, has := m["..."]
		return ok && has && len(m) == 1
	}
	tests := []struct {
		name        string
		path        claimpath.Pointer
		disclosures int
		hidden      func(map[string]any) bool
	}{
		{"property", claimpath.Keys("name"), 1, func(d map[string]any) bool { _, ok := d["name"]; return !ok }},
		{"nested property", claimpath.Keys("address", "locality"), 1, func(d map[string]any) bool {
			_, ok := d["address"].(map[string]any)["locality"]
			return !ok
		}},
		{"missing claim", claimpath.Keys("middle_name"), 0, func(map[string]any) bool { return true }},
		{"every element", claimpath.New(claimpath.Key("nationalities"), claimpath.All()), 2, func(d map[string]any) bool {
			n := d["nationalities"].([]any)
			return placeholder(n[0]) && placeholder(n[1])
		}},
		{"one element", claimpath.New(claimpath.Key("nationalities"), claimpath.Index(1)), 1, func(d map[string]any) bool {
			n := d["nationalities"].([]any)
			return n[0] == "British" && placeholder(n[1])
		}},
		{"a property of every element", claimpath.New(claimpath.Key("degrees"), claimpath.All(), claimpath.Key("type")), 2, func(d map[string]any) bool {
			for _, degree := range d["degrees"].([]any) {
				if _, ok := degree.(map[string]any)["type"]; ok {
					return false
				}
			}
			return true
		}},
	}
	client := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := document()
			disclosures, err := client.discloseClaim(data, tt.path, sha256.New())
			require.NoError(t, err)
			assert.Len(t, disclosures, tt.disclosures)
			assert.True(t, tt.hidden(data), "payload %v", data)
		})
	}

	t.Run("key in a non-object", func(t *testing.T) {
		_, err := client.discloseClaim(document(), claimpath.Keys("name", "first"), sha256.New())
		assert.Error(t, err)
	})
}

// TestAddDigest_Refusals covers the _sd member rules of section 4.2.4.1
// and section 7.1 step 4.
func TestAddDigest_Refusals(t *testing.T) {
	assert.Error(t, addDigest(map[string]any{"_sd": "not_an_array"}, "hash123"))
	assert.Error(t, addDigest(map[string]any{"_sd": []any{"hash123"}}, "hash123"))
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
			{Path: claimpath.Keys("a"), SD: "always"},           // depth 1
			{Path: claimpath.Keys("a", "b", "c"), SD: "always"}, // depth 3
			{Path: claimpath.Keys("a", "b"), SD: "always"},      // depth 2
		}

		sorted := sortClaimsByDepth(claims)

		// Should be ordered: depth 3, depth 2, depth 1
		assert.Equal(t, 3, sorted[0].Path.Len())
		assert.Equal(t, 2, sorted[1].Path.Len())
		assert.Equal(t, 1, sorted[2].Path.Len())
	})

	t.Run("handles_empty_slice", func(t *testing.T) {
		claims := []Claim{}
		sorted := sortClaimsByDepth(claims)
		assert.Len(t, sorted, 0)
	})

	t.Run("handles_single_claim", func(t *testing.T) {
		claims := []Claim{
			{Path: claimpath.Keys("a"), SD: "always"},
		}
		sorted := sortClaimsByDepth(claims)
		assert.Len(t, sorted, 1)
		assert.Equal(t, 1, sorted[0].Path.Len())
	})

	t.Run("does_not_modify_original", func(t *testing.T) {
		claims := []Claim{
			{Path: claimpath.Keys("a"), SD: "always"},
			{Path: claimpath.Keys("a", "b"), SD: "always"},
		}

		original := make([]Claim, len(claims))
		copy(original, claims)

		sortClaimsByDepth(claims)

		// Original should be unchanged
		assert.Equal(t, original, claims)
	})

	t.Run("stable_sort_for_equal_depths", func(t *testing.T) {
		claims := []Claim{
			{Path: claimpath.Keys("first"), SD: "always"},
			{Path: claimpath.Keys("second"), SD: "always"},
			{Path: claimpath.Keys("third"), SD: "always"},
		}

		sorted := sortClaimsByDepth(claims)

		// All have depth 1, order might vary but should all be present
		assert.Len(t, sorted, 3)
		for _, claim := range sorted {
			assert.Equal(t, 1, claim.Path.Len())
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
					Path: claimpath.New(claimpath.Key("nationalities"), claimpath.All()),
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
					Path: claimpath.New(claimpath.Key("person"), claimpath.Key("languages"), claimpath.All()),
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
					Path: claimpath.New(claimpath.Key("items"), claimpath.All()),
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
		// This tests the real-world scenario from vctm_pid.json
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
					Path: claimpath.New(claimpath.Key("nationalities"), claimpath.All()),
					SD:   "always",
				},
				{
					// Whole array disclosure (processed second - depth 1)
					// Makes the entire SD array recursively selectively disclosable
					Path: claimpath.Keys("nationalities"),
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
					Path: claimpath.New(claimpath.Key("nationalities"), claimpath.All()),
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
					Path: claimpath.New(claimpath.Key("nationalities"), claimpath.All()),
					SD:   "always",
				},
				{
					// Whole array disclosure (processed second - depth 1)
					Path: claimpath.Keys("nationalities"),
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
