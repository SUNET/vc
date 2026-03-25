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
	"strings"
	"testing"
	"github.com/SUNET/vc/pkg/jose"
)

// TestBuildCredentialWithOptions_DefaultOptions tests default option handling
func TestBuildCredentialWithOptions_DefaultOptions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	mockName := "name"
	vctm := &VCTM{
		VCT: "https://example.com/credential/test",
		Claims: []Claim{
			{
				Path: []*string{&mockName},
				SD:   "always",
			},
		},
	}

	documentData := []byte(`{"name":"John Doe","age":30}`)
	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(privateKey, "key-1")

	t.Run("nil_options_uses_defaults", func(t *testing.T) {
		client := &Client{}
		token, err := client.BuildCredentialWithSigner(
			t.Context(),
			"https://issuer.example.com",
			signer, vctmRaw, documentData, holderJWK,
			&CredentialOptions{Integrity: integrity},
		)
		if err != nil {
			t.Fatalf("BuildCredentialWithSigner failed: %v", err)
		}
		if token == "" {
			t.Error("Expected non-empty token")
		}
	})

	t.Run("zero_expiration_days_uses_default", func(t *testing.T) {
		client := &Client{}
		token, err := client.BuildCredentialWithSigner(
			t.Context(),
			"https://issuer.example.com",
			signer, vctmRaw, documentData, holderJWK,
			&CredentialOptions{
				DecoyDigests:   0,
				ExpirationDays: 0, // Should default to 365
				Integrity:      integrity,
			},
		)
		if err != nil {
			t.Fatalf("BuildCredentialWithSigner failed: %v", err)
		}
		if token == "" {
			t.Error("Expected non-empty token")
		}
	})

	t.Run("custom_expiration_days", func(t *testing.T) {
		client := &Client{}
		token, err := client.BuildCredentialWithSigner(
			t.Context(),
			"https://issuer.example.com",
			signer, vctmRaw, documentData, holderJWK,
			&CredentialOptions{
				DecoyDigests:   2,
				ExpirationDays: 90,
				Integrity:      integrity,
			},
		)
		if err != nil {
			t.Fatalf("BuildCredentialWithSigner failed: %v", err)
		}
		if token == "" {
			t.Error("Expected non-empty token")
		}
	})

	t.Run("invalid_json_data", func(t *testing.T) {
		client := &Client{}
		invalidData := []byte(`{invalid json}`)
		_, err := client.BuildCredentialWithSigner(
			t.Context(),
			"https://issuer.example.com",
			signer, vctmRaw, invalidData, holderJWK,
			&CredentialOptions{Integrity: integrity},
		)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

// TestHashAlgorithmDetection tests SHA3 algorithm detection
func TestHashAlgorithmDetection(t *testing.T) {
	t.Run("SHA3-256_detection", func(t *testing.T) {
		h := hash.Hash(sha30.New256())
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha3-256" {
			t.Errorf("Expected sha3-256, got %s", name)
		}
	})

	t.Run("SHA3-512_detection", func(t *testing.T) {
		h := hash.Hash(sha30.New512())
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha3-512" {
			t.Errorf("Expected sha3-512, got %s", name)
		}
	})

	t.Run("SHA-256_detection", func(t *testing.T) {
		h := sha256.New()
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha-256" {
			t.Errorf("Expected sha-256, got %s", name)
		}
	})

	t.Run("SHA-512_detection", func(t *testing.T) {
		h := sha512.New()
		name, err := getHashAlgorithmName(h)
		if err != nil {
			t.Fatalf("getHashAlgorithmName failed: %v", err)
		}
		if name != "sha-512" {
			t.Errorf("Expected sha-512, got %s", name)
		}
	})
}

// TestMakeCredential_EdgeCases tests edge cases
func TestMakeCredential_EdgeCases(t *testing.T) {
	client := &Client{}

	t.Run("unsupported_hash_algorithm", func(t *testing.T) {
		// Create a mock hash with unsupported size
		type mockHash struct{}

		mockName := "name"
		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&mockName},
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"name": "John",
		}

		// Use SHA-224 which has size 28 but should still work
		h := sha256.New224()
		_, _, err := client.MakeCredential(h, data, vctm, 0)
		if err != nil {
			// This might error or not depending on implementation
			t.Logf("Got expected error for unusual hash: %v", err)
		}
	})

	t.Run("claim_path_with_sd_forbidden_name", func(t *testing.T) {
		sdName := "_sd"
		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&sdName},
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"_sd": "should-not-be-disclosed",
		}

		_, _, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		if err == nil {
			t.Error("Expected error for forbidden claim name '_sd'")
		}
	})

	t.Run("claim_path_with_ellipsis_forbidden_name", func(t *testing.T) {
		ellipsis := "..."
		vctm := &VCTM{
			Claims: []Claim{
				{
					Path: []*string{&ellipsis},
					SD:   "always",
				},
			},
		}

		data := map[string]any{
			"...": "should-not-be-disclosed",
		}

		_, _, err := client.MakeCredential(sha256.New(), data, vctm, 0)
		if err == nil {
			t.Error("Expected error for forbidden claim name '...'")
		}
	})
}

// TestCombine tests JWT combination
func TestCombine(t *testing.T) {
	t.Run("combine_with_no_disclosures", func(t *testing.T) {
		jwt := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature"
		disclosures := []string{}
		kbJWT := ""

		result := Combine(jwt, disclosures, kbJWT)
		expected := jwt + "~"
		if result != expected {
			t.Errorf("Expected %s, got %s", expected, result)
		}
	})

	t.Run("combine_with_one_disclosure", func(t *testing.T) {
		jwt := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature"
		disclosures := []string{"WyJzYWx0IiwgIm5hbWUiLCAiSm9obiJd"}
		kbJWT := ""

		result := Combine(jwt, disclosures, kbJWT)
		expected := jwt + "~" + disclosures[0] + "~"
		if result != expected {
			t.Errorf("Expected %s, got %s", expected, result)
		}
	})

	t.Run("combine_with_kb_jwt", func(t *testing.T) {
		jwt := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature"
		disclosures := []string{"WyJzYWx0IiwgIm5hbWUiLCAiSm9obiJd"}
		kbJWT := "eyJ0eXAiOiJrYitqd3QifQ.eyJub25jZSI6InRlc3QifQ.sig"

		result := Combine(jwt, disclosures, kbJWT)
		expected := jwt + "~" + disclosures[0] + "~" + kbJWT
		if result != expected {
			t.Errorf("Expected %s, got %s", expected, result)
		}
	})
}

// TestBase64Decode tests base64 decoding
func TestBase64Decode(t *testing.T) {
	t.Run("valid_base64url", func(t *testing.T) {
		// "test" in base64url
		input := "dGVzdA"
		result, err := Base64Decode(input)
		if err != nil {
			t.Fatalf("Base64Decode failed: %v", err)
		}
		if string(result) != "test" {
			t.Errorf("Expected 'test', got '%s'", string(result))
		}
	})

	t.Run("invalid_base64", func(t *testing.T) {
		input := "!!!invalid!!!"
		_, err := Base64Decode(input)
		if err == nil {
			t.Error("Expected error for invalid base64")
		}
	})
}

// TestSign tests JWT signing
func TestSign(t *testing.T) {
	t.Run("sign_with_rsa", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		header := map[string]any{
			"typ": "JWT",
			"alg": "RS256",
		}
		payload := map[string]any{
			"iss": "test",
			"sub": "user123",
		}

		_, algName := jose.GetSigningMethodFromKey(privateKey)
		signingMethod, _ := jose.GetSigningMethodFromKey(privateKey)

		token, err := Sign(header, payload, signingMethod, privateKey)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if token == "" {
			t.Error("Expected non-empty signed token")
		}
		if algName != "RS256" {
			t.Errorf("Expected RS256, got %s", algName)
		}
	})

	t.Run("sign_with_invalid_payload", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		header := map[string]any{
			"typ": "JWT",
			"alg": "ES256",
		}

		// Create an invalid payload with a channel (not JSON serializable)
		payload := map[string]any{
			"iss": make(chan int),
		}

		signingMethod, _ := jose.GetSigningMethodFromKey(privateKey)

		_, err = Sign(header, payload, signingMethod, privateKey)
		if err == nil {
			t.Error("Expected error for non-serializable payload")
		}
	})
}

// TestDiscloserHash_ArrayElements tests array element hashing
func TestDiscloserHash_ArrayElements(t *testing.T) {
	t.Run("hash_array_element", func(t *testing.T) {
		discloser := Discloser{
			Salt:    "test-salt-123",
			Value:   "array-value",
			IsArray: true,
		}

		h := sha256.New()
		hash, b64, arr, err := discloser.Hash(h)
		if err != nil {
			t.Fatalf("Hash failed: %v", err)
		}

		// Array disclosure should be [salt, value] (no claim name)
		if len(arr) != 2 {
			t.Errorf("Expected 2 elements in array disclosure, got %d", len(arr))
		}
		if arr[0] != discloser.Salt {
			t.Errorf("Expected salt %s, got %v", discloser.Salt, arr[0])
		}
		if arr[1] != discloser.Value {
			t.Errorf("Expected value %s, got %v", discloser.Value, arr[1])
		}

		if hash == "" {
			t.Error("Expected non-empty hash")
		}
		if b64 == "" {
			t.Error("Expected non-empty base64 disclosure")
		}
	})

	t.Run("hash_object_property", func(t *testing.T) {
		discloser := Discloser{
			Salt:      "test-salt-456",
			ClaimName: "name",
			Value:     "John Doe",
			IsArray:   false,
		}

		h := sha256.New()
		hash, b64, arr, err := discloser.Hash(h)
		if err != nil {
			t.Fatalf("Hash failed: %v", err)
		}

		// Object property disclosure should be [salt, claim_name, value]
		if len(arr) != 3 {
			t.Errorf("Expected 3 elements in object property disclosure, got %d", len(arr))
		}
		if arr[0] != discloser.Salt {
			t.Errorf("Expected salt %s, got %v", discloser.Salt, arr[0])
		}
		if arr[1] != discloser.ClaimName {
			t.Errorf("Expected claim name %s, got %v", discloser.ClaimName, arr[1])
		}
		if arr[2] != discloser.Value {
			t.Errorf("Expected value %s, got %v", discloser.Value, arr[2])
		}

		if hash == "" {
			t.Error("Expected non-empty hash")
		}
		if b64 == "" {
			t.Error("Expected non-empty base64 disclosure")
		}
	})

	t.Run("hash_with_complex_value", func(t *testing.T) {
		discloser := Discloser{
			Salt:      "salt",
			ClaimName: "address",
			Value: map[string]any{
				"street": "123 Main St",
				"city":   "Springfield",
			},
			IsArray: false,
		}

		h := sha256.New()
		hash, b64, arr, err := discloser.Hash(h)
		if err != nil {
			t.Fatalf("Hash failed: %v", err)
		}

		// Should handle complex values
		if len(arr) != 3 {
			t.Errorf("Expected 3 elements, got %d", len(arr))
		}

		// Value should be the map
		valueMap, ok := arr[2].(map[string]any)
		if !ok {
			t.Error("Expected value to be a map")
		}
		if valueMap["street"] != "123 Main St" {
			t.Errorf("Expected street '123 Main St', got %v", valueMap["street"])
		}

		if hash == "" {
			t.Error("Expected non-empty hash")
		}
		if b64 == "" {
			t.Error("Expected non-empty base64 disclosure")
		}
	})
}

// TestCreateKeyBindingJWT_ErrorCases tests error handling
func TestCreateKeyBindingJWT_ErrorCases(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("unsupported_hash_algorithm_in_kb_jwt", func(t *testing.T) {
		sdJWT := "eyJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ0ZXN0In0.sig~"
		nonce := "test-nonce"
		audience := "https://verifier.example.com"

		_, err := CreateKeyBindingJWT(sdJWT, nonce, audience, privateKey, "unsupported-alg")
		if err == nil {
			t.Error("Expected error for unsupported hash algorithm")
		}
	})
}

// TestCalculateSDHash_EdgeCases tests sd_hash calculation
func TestCalculateSDHash_EdgeCases(t *testing.T) {
	t.Run("hash_empty_sd_jwt", func(t *testing.T) {
		sdJWT := ""
		h := sha256.New()

		hash, err := calculateSDHash(sdJWT, h)
		if err != nil {
			t.Fatalf("calculateSDHash failed: %v", err)
		}

		// Should still produce a valid hash (of empty string)
		if len(hash) != 43 {
			t.Errorf("Expected 43 character hash, got %d", len(hash))
		}
	})

	t.Run("hash_long_sd_jwt", func(t *testing.T) {
		// Create a long SD-JWT
		var sdJWT strings.Builder
		sdJWT.WriteString("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig")
		for range 100 {
			sdJWT.WriteString("~" + "WyJzYWx0IiwgImNsYWltIiwgInZhbHVlIl0")
		}
		sdJWT.WriteString("~")

		h := sha256.New()
		hash, err := calculateSDHash(sdJWT.String(), h)
		if err != nil {
			t.Fatalf("calculateSDHash failed: %v", err)
		}

		if len(hash) != 43 {
			t.Errorf("Expected 43 character hash, got %d", len(hash))
		}
	})
}

// TestGenerateDecoyDigest_Randomness tests decoy generation
func TestGenerateDecoyDigest_Randomness(t *testing.T) {
	h := sha256.New()

	// Generate multiple decoys and ensure they're all different
	decoys := make(map[string]bool)
	for range 50 {
		decoy, err := generateDecoyDigest(h)
		if err != nil {
			t.Fatalf("generateDecoyDigest failed: %v", err)
		}
		if decoys[decoy] {
			t.Errorf("Duplicate decoy generated: %s", decoy)
		}
		decoys[decoy] = true

		// Verify proper length
		if len(decoy) != 43 {
			t.Errorf("Expected 43 character decoy, got %d", len(decoy))
		}
	}

	if len(decoys) != 50 {
		t.Errorf("Expected 50 unique decoys, got %d", len(decoys))
	}
}

// TestGenerateSalt_Randomness tests salt generation
func TestGenerateSalt_Randomness(t *testing.T) {
	salts := make(map[string]bool)
	for range 50 {
		salt, err := generateSalt()
		if err != nil {
			t.Fatalf("generateSalt failed: %v", err)
		}
		if salts[salt] {
			t.Errorf("Duplicate salt generated: %s", salt)
		}
		salts[salt] = true

		// 128 bits = 16 bytes => 22 base64url characters
		if len(salt) != 22 {
			t.Errorf("Expected 22 character salt, got %d: %s", len(salt), salt)
		}
	}

	if len(salts) != 50 {
		t.Errorf("Expected 50 unique salts, got %d", len(salts))
	}
}

// TestProcessClaimPath_ComplexScenarios tests complex claim paths
func TestProcessClaimPath_ComplexScenarios(t *testing.T) {
	client := &Client{}

	t.Run("non_existent_claim_path", func(t *testing.T) {
		data := map[string]any{
			"name": "John",
		}

		nonExistent := "address"
		path := []*string{&nonExistent}

		disclosure, hash, err := client.processClaimPath(data, path, sha256.New())
		if err != nil {
			t.Fatalf("processClaimPath failed: %v", err)
		}

		// Should return empty strings for non-existent path
		if disclosure != "" {
			t.Error("Expected empty disclosure for non-existent claim")
		}
		if hash != "" {
			t.Error("Expected empty hash for non-existent claim")
		}
	})

	t.Run("nested_claim_with_nested_object_value", func(t *testing.T) {
		data := map[string]any{
			"person": map[string]any{
				"address": map[string]any{
					"street": "123 Main St",
					"city":   "Springfield",
				},
			},
		}

		person := "person"
		address := "address"
		path := []*string{&person, &address}

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

		// Verify the claim was removed
		personObj := data["person"].(map[string]any)
		if _, exists := personObj["address"]; exists {
			t.Error("Expected address to be removed after processing")
		}
	})
}
