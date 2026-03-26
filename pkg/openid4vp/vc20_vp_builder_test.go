package openid4vp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestVPBuilder_BuildVC20Presentation_EdDSA(t *testing.T) {
	// Generate holder key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	// Create a properly formatted test credential JSON
	// Note: The credential must be a valid JSON-LD document
	testCredentialJSON := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {
			"id": "did:example:subject"
		}
	}`

	// Build VP
	builder := NewVPBuilder(
		WithHolderDID("did:key:z6MkTest"),
		WithDefaultCryptosuite(CryptosuiteEdDSA2022),
	)

	opts := &VPBuildOptions{
		HolderDID:          "did:key:z6MkTest",
		VerificationMethod: "did:key:z6MkTest#key-1",
		Nonce:              "test-nonce-12345",
		Domain:             "https://verifier.example.com",
		Cryptosuite:        CryptosuiteEdDSA2022,
		Created:            time.Now().UTC(),
	}

	vpBytes, err := builder.BuildVC20Presentation(
		[][]byte{[]byte(testCredentialJSON)},
		privKey,
		opts,
	)
	if err != nil {
		t.Fatalf("failed to build VP: %v", err)
	}

	// Verify VP structure
	var vp map[string]any
	if err := json.Unmarshal(vpBytes, &vp); err != nil {
		t.Fatalf("failed to parse VP: %v", err)
	}

	// Check required fields
	if _, ok := vp["@context"]; !ok {
		t.Error("VP missing @context")
	}

	if types, ok := vp["type"].([]any); !ok || len(types) == 0 {
		t.Error("VP missing type")
	} else {
		hasVP := false
		for _, typ := range types {
			if typ == "VerifiablePresentation" {
				hasVP = true
				break
			}
		}
		if !hasVP {
			t.Error("VP type does not include VerifiablePresentation")
		}
	}

	if holder, ok := vp["holder"].(string); !ok || holder != opts.HolderDID {
		t.Errorf("VP holder mismatch: got %v, want %s", vp["holder"], opts.HolderDID)
	}

	// Check proof
	proof, ok := vp["proof"].(map[string]any)
	if !ok {
		t.Fatal("VP missing proof")
	}

	if proof["type"] != "DataIntegrityProof" {
		t.Errorf("unexpected proof type: %v", proof["type"])
	}

	if proof["cryptosuite"] != CryptosuiteEdDSA2022 {
		t.Errorf("unexpected cryptosuite: %v", proof["cryptosuite"])
	}

	if proof["challenge"] != opts.Nonce {
		t.Errorf("proof challenge mismatch: got %v, want %s", proof["challenge"], opts.Nonce)
	}

	if proof["domain"] != opts.Domain {
		t.Errorf("proof domain mismatch: got %v, want %s", proof["domain"], opts.Domain)
	}

	if proof["proofPurpose"] != "authentication" {
		t.Errorf("unexpected proofPurpose: %v", proof["proofPurpose"])
	}
}

func TestVPBuilder_BuildVC20Presentation_ECDSA(t *testing.T) {
	// Generate holder key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Create a properly formatted test credential JSON
	testCredentialJSON := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {
			"id": "did:example:subject"
		}
	}`

	// Build VP
	builder := NewVPBuilder()

	opts := &VPBuildOptions{
		HolderDID:          "did:jwk:test",
		VerificationMethod: "did:jwk:test#0",
		Nonce:              "ecdsa-nonce",
		Domain:             "https://verifier.example.com",
		Cryptosuite:        CryptosuiteECDSA2019,
	}

	vpBytes, err := builder.BuildVC20Presentation(
		[][]byte{[]byte(testCredentialJSON)},
		privKey,
		opts,
	)
	if err != nil {
		t.Fatalf("failed to build VP with ECDSA: %v", err)
	}

	// Verify structure
	var vp map[string]any
	if err := json.Unmarshal(vpBytes, &vp); err != nil {
		t.Fatalf("failed to parse VP: %v", err)
	}

	proof := vp["proof"].(map[string]any)
	if proof["cryptosuite"] != CryptosuiteECDSA2019 {
		t.Errorf("unexpected cryptosuite: %v", proof["cryptosuite"])
	}
}

func TestVPBuilder_BuildVC20Presentation_MultipleCredentials(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	cred1JSON := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer1",
		"credentialSubject": {"id": "did:example:subject1"}
	}`
	cred2JSON := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer2",
		"credentialSubject": {"id": "did:example:subject2"}
	}`

	builder := NewVPBuilder()
	opts := &VPBuildOptions{
		HolderDID:   "did:key:holder",
		Nonce:       "multi-cred-nonce",
		Cryptosuite: CryptosuiteEdDSA2022,
	}

	vpBytes, err := builder.BuildVC20Presentation(
		[][]byte{[]byte(cred1JSON), []byte(cred2JSON)},
		privKey,
		opts,
	)
	if err != nil {
		t.Fatalf("failed to build VP with multiple credentials: %v", err)
	}

	var vp map[string]any
	if err := json.Unmarshal(vpBytes, &vp); err != nil {
		t.Fatalf("failed to unmarshal VP: %v", err)
	}

	// Check credentials array
	creds, ok := vp["verifiableCredential"].([]any)
	if !ok {
		t.Fatal("VP missing verifiableCredential array")
	}
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}
}

func TestVPBuilder_BuildVC20Presentation_Errors(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	builder := NewVPBuilder()

	t.Run("no credentials", func(t *testing.T) {
		_, err := builder.BuildVC20Presentation([][]byte{}, privKey, &VPBuildOptions{HolderDID: "did:example:test"})
		if err == nil {
			t.Error("expected error for empty credentials")
		}
	})

	t.Run("nil private key", func(t *testing.T) {
		credBytes := []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`)
		_, err := builder.BuildVC20Presentation([][]byte{credBytes}, nil, &VPBuildOptions{HolderDID: "did:example:test"})
		if err == nil {
			t.Error("expected error for nil private key")
		}
	})

	t.Run("nil options", func(t *testing.T) {
		credBytes := []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`)
		_, err := builder.BuildVC20Presentation([][]byte{credBytes}, privKey, nil)
		if err == nil {
			t.Error("expected error for nil options")
		}
	})

	t.Run("missing holder DID", func(t *testing.T) {
		credBytes := []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`)
		_, err := builder.BuildVC20Presentation([][]byte{credBytes}, privKey, &VPBuildOptions{})
		if err == nil {
			t.Error("expected error for missing holder DID")
		}
	})

	t.Run("wrong key type", func(t *testing.T) {
		credBytes := []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`)
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		opts := &VPBuildOptions{
			HolderDID:   "did:example:test",
			Cryptosuite: CryptosuiteEdDSA2022, // EdDSA suite with ECDSA key
		}
		_, err := builder.BuildVC20Presentation([][]byte{credBytes}, ecKey, opts)
		if err == nil {
			t.Error("expected error for wrong key type")
		}
	})
}

func TestVPBuilder_DefaultOptions(t *testing.T) {
	builder := NewVPBuilder(
		WithHolderDID("did:example:default-holder"),
		WithDefaultCryptosuite(CryptosuiteECDSA2019),
	)

	if builder.holderDID != "did:example:default-holder" {
		t.Errorf("unexpected default holder DID: %s", builder.holderDID)
	}

	if builder.defaultCryptosuite != CryptosuiteECDSA2019 {
		t.Errorf("unexpected default cryptosuite: %s", builder.defaultCryptosuite)
	}
}

// TestVPBuilder_UnsupportedCryptosuite tests error handling for unsupported cryptosuites.
func TestVPBuilder_UnsupportedCryptosuite(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	builder := NewVPBuilder()

	credBytes := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer"
	}`)

	opts := &VPBuildOptions{
		HolderDID:   "did:example:holder",
		Cryptosuite: "unknown-cryptosuite",
	}

	_, err := builder.BuildVC20Presentation([][]byte{credBytes}, privKey, opts)
	if err == nil {
		t.Error("expected error for unsupported cryptosuite")
	}
	if err != nil && !containsStr(err.Error(), "unsupported cryptosuite") {
		t.Errorf("expected error containing 'unsupported cryptosuite', got: %v", err)
	}
}

// TestVPBuilder_ECDSAWithEdDSAKey tests error when using ECDSA cryptosuite with Ed25519 key.
func TestVPBuilder_ECDSAWithEdDSAKey(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	builder := NewVPBuilder()

	credBytes := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer"
	}`)

	opts := &VPBuildOptions{
		HolderDID:   "did:example:holder",
		Cryptosuite: CryptosuiteECDSA2019, // ECDSA suite with Ed25519 key
	}

	_, err := builder.BuildVC20Presentation([][]byte{credBytes}, privKey, opts)
	if err == nil {
		t.Error("expected error when using ECDSA cryptosuite with Ed25519 key")
	}
	if err != nil && !containsStr(err.Error(), "private key is not") {
		t.Errorf("expected error about key type mismatch, got: %v", err)
	}
}

// TestVPBuilder_UsesDefaultCryptosuite tests that default cryptosuite is used when not specified.
func TestVPBuilder_UsesDefaultCryptosuite(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	builder := NewVPBuilder(
		WithDefaultCryptosuite(CryptosuiteECDSA2019),
	)

	credBytes := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer"
	}`)

	opts := &VPBuildOptions{
		HolderDID:          "did:example:holder",
		VerificationMethod: "did:example:holder#key-1",
		Nonce:              "test-nonce",
		// No Cryptosuite specified - should use default
	}

	vpBytes, err := builder.BuildVC20Presentation([][]byte{credBytes}, privKey, opts)
	if err != nil {
		t.Fatalf("failed to build VP: %v", err)
	}

	var vp map[string]any
	if err := json.Unmarshal(vpBytes, &vp); err != nil {
		t.Fatalf("failed to unmarshal VP: %v", err)
	}

	proof := vp["proof"].(map[string]any)
	if proof["cryptosuite"] != CryptosuiteECDSA2019 {
		t.Errorf("expected default cryptosuite %s, got %v", CryptosuiteECDSA2019, proof["cryptosuite"])
	}
}

// TestVPBuilder_UsesDefaultHolderDID tests that default holder DID is used when not in options.
func TestVPBuilder_UsesDefaultHolderDID(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	builder := NewVPBuilder(
		WithHolderDID("did:example:default-holder"),
		WithDefaultCryptosuite(CryptosuiteECDSA2019),
	)

	credBytes := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer"
	}`)

	opts := &VPBuildOptions{
		VerificationMethod: "did:example:holder#key-1",
		Nonce:              "test-nonce",
		// No HolderDID in options - should use default
	}

	vpBytes, err := builder.BuildVC20Presentation([][]byte{credBytes}, privKey, opts)
	if err != nil {
		t.Fatalf("failed to build VP: %v", err)
	}

	var vp map[string]any
	if err := json.Unmarshal(vpBytes, &vp); err != nil {
		t.Fatalf("failed to unmarshal VP: %v", err)
	}

	if vp["holder"] != "did:example:default-holder" {
		t.Errorf("expected default holder DID, got %v", vp["holder"])
	}
}

// TestVPBuilder_MalformedCredentialJSON tests handling of malformed credential JSON.
func TestVPBuilder_MalformedCredentialJSON(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	builder := NewVPBuilder()

	// Malformed JSON (not valid JSON at all)
	malformedJSON := []byte(`{not valid json`)

	opts := &VPBuildOptions{
		HolderDID:          "did:example:holder",
		VerificationMethod: "did:example:holder#key-1",
		Nonce:              "test-nonce",
		Cryptosuite:        CryptosuiteEdDSA2022,
	}

	_, err := builder.BuildVC20Presentation([][]byte{malformedJSON}, privKey, opts)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

// TestVPBuilder_CustomCreatedTime tests that custom created time is used.
func TestVPBuilder_CustomCreatedTime(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	builder := NewVPBuilder()

	credBytes := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer"
	}`)

	customTime := time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC)
	opts := &VPBuildOptions{
		HolderDID:          "did:example:holder",
		VerificationMethod: "did:example:holder#key-1",
		Nonce:              "test-nonce",
		Cryptosuite:        CryptosuiteEdDSA2022,
		Created:            customTime,
	}

	vpBytes, err := builder.BuildVC20Presentation([][]byte{credBytes}, privKey, opts)
	if err != nil {
		t.Fatalf("failed to build VP: %v", err)
	}

	var vp map[string]any
	if err := json.Unmarshal(vpBytes, &vp); err != nil {
		t.Fatalf("failed to unmarshal VP: %v", err)
	}

	proof := vp["proof"].(map[string]any)
	created, ok := proof["created"].(string)
	if !ok {
		t.Fatal("proof missing created timestamp")
	}

	// Parse and verify time
	parsedTime, err := time.Parse(time.RFC3339, created)
	if err != nil {
		t.Fatalf("failed to parse created time: %v", err)
	}

	if !parsedTime.Equal(customTime) {
		t.Errorf("expected created time %v, got %v", customTime, parsedTime)
	}
}

// containsStr is a helper function to check if a string contains a substring.
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
