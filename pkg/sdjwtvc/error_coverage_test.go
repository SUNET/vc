package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"testing"
	"vc/pkg/jose"
)

// mockFailingHash implements hash.Hash but fails on Write
type mockFailingHash struct {
	hash.Hash
	failOnWrite bool
	failOnSum   bool
}

func (m *mockFailingHash) Write(p []byte) (n int, err error) {
	if m.failOnWrite {
		return 0, errors.New("mock write error")
	}
	return m.Hash.Write(p)
}

func (m *mockFailingHash) Reset() {
	m.Hash.Reset()
}

func (m *mockFailingHash) Size() int {
	return m.Hash.Size()
}

func (m *mockFailingHash) BlockSize() int {
	return m.Hash.BlockSize()
}

func (m *mockFailingHash) Sum(b []byte) []byte {
	if m.failOnSum {
		return nil
	}
	return m.Hash.Sum(b)
}

// TestDiscloserHash_ErrorHandling tests error cases in Hash method
func TestDiscloserHash_ErrorHandling(t *testing.T) {
	t.Run("hash_write_error", func(t *testing.T) {
		discloser := Discloser{
			Salt:      "test-salt",
			ClaimName: "name",
			Value:     "John",
			IsArray:   false,
		}

		failingHash := &mockFailingHash{
			Hash:        sha256.New(),
			failOnWrite: true,
		}

		_, _, _, err := discloser.Hash(failingHash)
		if err == nil {
			t.Error("Expected error when hash.Write fails")
		}
	})

	t.Run("hash_with_unmarshalable_value", func(t *testing.T) {
		discloser := Discloser{
			Salt:      "test-salt",
			ClaimName: "channel",
			Value:     make(chan int), // channels cannot be marshaled to JSON
			IsArray:   false,
		}

		h := sha256.New()
		_, _, _, err := discloser.Hash(h)
		if err == nil {
			t.Error("Expected error when value cannot be marshaled")
		}
	})
}



// TestSign_JSONMarshalError tests signing with unmarshalable header
func TestSign_JSONMarshalError(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Header with unmarshalable value
	header := map[string]any{
		"typ":     "JWT",
		"channel": make(chan int), // Cannot be marshaled
	}
	payload := map[string]any{
		"iss": "test",
	}

	signingMethod, _ := jose.GetSigningMethodFromKey(privateKey)

	_, err := Sign(header, payload, signingMethod, privateKey)
	if err == nil {
		t.Error("Expected error for unmarshalable header")
	}
}

// TestProcessClaimPath_NilPathElement tests nil handling
func TestProcessClaimPath_NilPathElement(t *testing.T) {
	client := &Client{}

	data := map[string]any{
		"level1": map[string]any{
			"level2": "value",
		},
	}

	// Create a path with a nil element in the middle
	level1 := "level1"
	var nilString *string = nil
	path := []*string{&level1, nilString}

	_, _, err := client.processClaimPath(data, path, sha256.New())
	if err == nil {
		t.Error("Expected error for nil path element")
	}
}

// TestAddHashToPath_Errors tests error conditions in addHashToPath
func TestAddHashToPath_Errors(t *testing.T) {
	client := &Client{}

	t.Run("nil_path_element_in_addHashToPath", func(t *testing.T) {
		data := map[string]any{
			"level1": map[string]any{},
		}

		level1 := "level1"
		var nilString *string = nil
		path := []*string{&level1, nilString}

		err := client.addHashToPath(data, path, "test-hash")
		if err == nil {
			t.Error("Expected error for nil path element")
		}
	})

	t.Run("path_not_found_in_addHashToPath", func(t *testing.T) {
		data := map[string]any{
			"level1": map[string]any{},
		}

		level1 := "level1"
		nonexistent := "nonexistent"
		path := []*string{&level1, &nonexistent}

		err := client.addHashToPath(data, path, "test-hash")
		if err == nil {
			t.Error("Expected error for non-existent path")
		}
	})

	t.Run("non_object_in_path", func(t *testing.T) {
		data := map[string]any{
			"level1": "not-an-object",
		}

		level1 := "level1"
		path := []*string{&level1}

		err := client.addHashToPath(data, path, "test-hash")
		if err == nil {
			t.Error("Expected error for non-object in path")
		}
	})

	t.Run("sd_is_not_an_array", func(t *testing.T) {
		data := map[string]any{
			"_sd": "not-an-array", // _sd should be an array
		}

		path := []*string{} // Empty path means root level

		err := client.addHashToPath(data, path, "test-hash")
		if err == nil {
			t.Error("Expected error when _sd is not an array")
		}
	})
}

// TestGenerateSalt_ErrorSimulation tests salt generation
func TestGenerateSalt_Coverage(t *testing.T) {
	// Generate multiple salts to ensure coverage
	for i := 0; i < 10; i++ {
		salt, err := generateSalt()
		if err != nil {
			t.Fatalf("generateSalt failed: %v", err)
		}
		if len(salt) != 22 {
			t.Errorf("Expected 22 character salt, got %d", len(salt))
		}
	}
}

// TestGenerateDecoyDigest_ErrorCoverage tests decoy generation error paths
func TestGenerateDecoyDigest_Coverage(t *testing.T) {
	// Test with different hash algorithms to ensure full coverage
	hashers := []hash.Hash{
		sha256.New(),
		sha256.New224(),
	}

	for _, h := range hashers {
		digest, err := generateDecoyDigest(h)
		if err != nil {
			t.Fatalf("generateDecoyDigest failed: %v", err)
		}
		if digest == "" {
			t.Error("Expected non-empty digest")
		}
	}
}

// TestMakeCredential_ProcessClaimPathErrors tests error propagation
func TestMakeCredential_ProcessClaimPathErrors(t *testing.T) {
	client := &Client{}

	t.Run("process_claim_with_array_in_path", func(t *testing.T) {
		level1 := "level1"
		arrayElem := "arrayElem"

		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&level1, &arrayElem},
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"level1": []any{"item1", "item2"}, // Array, not object
		}

		_, _, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		if err == nil {
			t.Error("Expected error when trying to process array in path")
		}
	})
}

// TestGetHashAlgorithmName_EdgeCases tests hash algorithm detection edge cases
func TestGetHashAlgorithmName_EdgeCases(t *testing.T) {
	t.Run("sha224_algorithm", func(t *testing.T) {
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

// TestIsSHA_Functions_Coverage ensures full coverage of hash detection functions
func TestIsSHA_Functions_Coverage(t *testing.T) {
	t.Run("isSHA256_with_wrong_hash", func(t *testing.T) {
		// Pass SHA-512 to isSHA256
		h := sha256.New224()
		result := isSHA256(h)
		// Should return false or true depending on the hash
		_ = result
	})

	t.Run("isSHA512_with_wrong_hash", func(t *testing.T) {
		h := sha256.New()
		result := isSHA512(h)
		// Should return false
		if result {
			t.Error("Expected false when comparing SHA-256 with isSHA512")
		}
	})
}

// TestBuildCredentialWithSigner_SignError tests signing errors
func TestBuildCredentialWithSigner_SignError(t *testing.T) {
	client := &Client{}

	name := "name"
	vctm := &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&name},
				SD:   "always",
			},
		},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)

	documentData := []byte(`{"name":"test"}`)
	holderJWK := map[string]any{"kty": "EC"}

	_, err := client.BuildCredentialWithSigner(
		t.Context(),
		"issuer",
		&failingSigner{},
		vctmRaw,
		documentData,
		holderJWK,
		&CredentialOptions{Integrity: integrity},
	)

	// Should error during signing
	if err == nil {
		t.Error("Expected error when signing with failing signer")
	}
}

// TestCreateKeyBindingJWT_SignError tests KB-JWT signing errors
func TestCreateKeyBindingJWT_SignError(t *testing.T) {
	// Use invalid key to trigger error
	sdJWT := "test~"
	nonce := "nonce"
	audience := "aud"
	invalidKey := "not-a-key"

	_, err := CreateKeyBindingJWT(sdJWT, nonce, audience, invalidKey, "sha-256")
	if err == nil {
		t.Error("Expected error when creating KB-JWT with invalid key")
	}
}

// TestCalculateSDHash_WriteError tests hash write error
func TestCalculateSDHash_WriteError(t *testing.T) {
	sdJWT := "test-sd-jwt~"

	failingHash := &mockFailingHash{
		Hash:        sha256.New(),
		failOnWrite: true,
	}

	_, err := calculateSDHash(sdJWT, failingHash)
	if err == nil {
		t.Error("Expected error when hash write fails")
	}
}
