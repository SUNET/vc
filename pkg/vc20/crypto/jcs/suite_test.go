package jcs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Test constants to avoid duplicating literals
const (
	testVerificationMethodIssuer = "did:example:issuer#key-1"
	testVerificationMethodKey    = "did:example:key"
	testVerificationMethodDIDKey = "did:key"
	testDocID                    = "test-doc"
	testProofPurposeAssertion    = "assertionMethod"
)

// Test error message formats
const (
	errSignFailed = "Sign failed: %v"
)

func TestNewSuite(t *testing.T) {
	suite := NewSuite()
	if suite == nil {
		t.Fatal("NewSuite returned nil")
	}
}

func TestCanonicalizeBasic(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected string
	}{
		{
			name:     "simple object",
			input:    map[string]any{"b": 2, "a": 1},
			expected: `{"a":1,"b":2}`,
		},
		{
			name:     "nested object",
			input:    map[string]any{"z": map[string]any{"b": 2, "a": 1}, "a": 1},
			expected: `{"a":1,"z":{"a":1,"b":2}}`,
		},
		{
			name:     "with string",
			input:    map[string]any{"name": "test", "id": 1},
			expected: `{"id":1,"name":"test"}`,
		},
		{
			name:     "empty object",
			input:    map[string]any{},
			expected: `{}`,
		},
		{
			name:     "with array",
			input:    map[string]any{"items": []any{3, 1, 2}},
			expected: `{"items":[3,1,2]}`,
		},
		{
			name:     "with boolean and null",
			input:    map[string]any{"active": true, "deleted": false, "meta": nil},
			expected: `{"active":true,"deleted":false,"meta":null}`,
		},
		{
			name:     "unicode strings",
			input:    map[string]any{"greeting": "Hello, 世界"},
			expected: `{"greeting":"Hello, 世界"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Canonicalize(tt.input)
			if err != nil {
				t.Fatalf("Canonicalize failed: %v", err)
			}
			if string(result) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, string(result))
			}
		})
	}
}

func TestCanonicalizeWithStruct(t *testing.T) {
	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	input := TestStruct{Name: "test", Value: 42}
	result, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	expected := `{"name":"test","value":42}`
	if string(result) != expected {
		t.Errorf("expected %s, got %s", expected, string(result))
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	suite := NewSuite()

	document := map[string]any{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]any{
			"id":   "did:example:subject",
			"name": "Test Subject",
		},
	}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "assertionMethod",
		Created:            time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	proof, ok := signed["proof"].(map[string]any)
	if !ok {
		t.Fatal("signed document missing proof")
	}

	if proof["type"] != ProofTypeDataIntegrity {
		t.Errorf("expected proof type %s, got %v", ProofTypeDataIntegrity, proof["type"])
	}
	if proof["cryptosuite"] != CryptosuiteEdDSAJCS2022 {
		t.Errorf("expected cryptosuite %s, got %v", CryptosuiteEdDSAJCS2022, proof["cryptosuite"])
	}
	if proof["verificationMethod"] != opts.VerificationMethod {
		t.Errorf("expected verificationMethod %s, got %v", opts.VerificationMethod, proof["verificationMethod"])
	}
	if proof["proofValue"] == nil || proof["proofValue"] == "" {
		t.Error("proof missing proofValue")
	}

	err = suite.Verify(signed, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestVerifyFailsWithWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	suite := NewSuite()

	document := map[string]any{
		"id":   testDocID,
		"data": "test data",
	}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	err = suite.Verify(signed, wrongPub)
	if err == nil {
		t.Fatal("Verify should fail with wrong key")
	}
}

func TestVerifyFailsWithTamperedDocument(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	suite := NewSuite()

	document := map[string]any{
		"id":   testDocID,
		"data": "original data",
	}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	signed["data"] = "tampered data"

	err = suite.Verify(signed, pub)
	if err == nil {
		t.Fatal("Verify should fail with tampered document")
	}
}

func TestSignWithOptionalFields(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	suite := NewSuite()

	document := map[string]any{
		"id": testDocID,
	}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "authentication",
		Domain:             "example.com",
		Challenge:          "abc123",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	proof, ok := signed["proof"].(map[string]any)
	if !ok {
		t.Fatal("signed document missing proof")
	}

	if proof["domain"] != "example.com" {
		t.Errorf("expected domain example.com, got %v", proof["domain"])
	}
	if proof["challenge"] != "abc123" {
		t.Errorf("expected challenge abc123, got %v", proof["challenge"])
	}
}

func TestRoundTripWithJSON(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	suite := NewSuite()

	document := map[string]any{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]any{
			"id":    "did:example:subject",
			"name":  "Test Subject",
			"score": 42,
		},
	}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	jsonBytes, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var unmarshaled map[string]any
	if err := json.Unmarshal(jsonBytes, &unmarshaled); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	err = suite.Verify(unmarshaled, pub)
	if err != nil {
		t.Fatalf("Verify after JSON round-trip failed: %v", err)
	}
}

// Test Sign validation errors
func TestSignValidationErrors(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()
	document := map[string]any{"id": "test"}

	tests := []struct {
		name     string
		doc      any
		key      ed25519.PrivateKey
		opts     *SignOptions
		errMatch string
	}{
		{
			name:     "nil document",
			doc:      nil,
			key:      priv,
			opts:     &SignOptions{VerificationMethod: testVerificationMethodDIDKey, ProofPurpose: "assertionMethod"},
			errMatch: "document is nil",
		},
		{
			name:     "nil key",
			doc:      document,
			key:      nil,
			opts:     &SignOptions{VerificationMethod: testVerificationMethodDIDKey, ProofPurpose: "assertionMethod"},
			errMatch: "private key is nil",
		},
		{
			name:     "nil options",
			doc:      document,
			key:      priv,
			opts:     nil,
			errMatch: "sign options are nil",
		},
		{
			name:     "missing verificationMethod",
			doc:      document,
			key:      priv,
			opts:     &SignOptions{ProofPurpose: "assertionMethod"},
			errMatch: "verificationMethod is required",
		},
		{
			name:     "missing proofPurpose",
			doc:      document,
			key:      priv,
			opts:     &SignOptions{VerificationMethod: testVerificationMethodDIDKey},
			errMatch: "proofPurpose is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := suite.Sign(tt.doc, tt.key, tt.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.errMatch != "" && !strings.Contains(err.Error(), tt.errMatch) {
				t.Errorf("expected error containing %q, got %q", tt.errMatch, err.Error())
			}
		})
	}
}

// Test Verify validation errors
func TestVerifyValidationErrors(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	tests := []struct {
		name     string
		doc      map[string]any
		key      ed25519.PublicKey
		errMatch string
	}{
		{
			name:     "nil public key",
			doc:      map[string]any{"id": "test", "proof": map[string]any{"type": ProofTypeDataIntegrity, "cryptosuite": CryptosuiteEdDSAJCS2022}},
			key:      nil,
			errMatch: "public key is nil",
		},
		{
			name:     "missing proof",
			doc:      map[string]any{"id": "test"},
			key:      pub,
			errMatch: "document has no proof",
		},
		{
			name:     "wrong proof type",
			doc:      map[string]any{"id": "test", "proof": map[string]any{"type": "WrongType", "cryptosuite": CryptosuiteEdDSAJCS2022, "proofValue": "z123"}},
			key:      pub,
			errMatch: "not an eddsa-jcs-2022 proof",
		},
		{
			name:     "wrong cryptosuite",
			doc:      map[string]any{"id": "test", "proof": map[string]any{"type": ProofTypeDataIntegrity, "cryptosuite": "wrong-suite", "proofValue": "z123"}},
			key:      pub,
			errMatch: "proof is not an eddsa-jcs-2022 proof",
		},
		{
			name:     "missing proofValue",
			doc:      map[string]any{"id": "test", "proof": map[string]any{"type": ProofTypeDataIntegrity, "cryptosuite": CryptosuiteEdDSAJCS2022}},
			key:      pub,
			errMatch: "proof is missing proofValue",
		},
		{
			name:     "invalid proofValue encoding",
			doc:      map[string]any{"id": "test", "proof": map[string]any{"type": ProofTypeDataIntegrity, "cryptosuite": CryptosuiteEdDSAJCS2022, "proofValue": "not-multibase"}},
			key:      pub,
			errMatch: "failed to decode proofValue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := suite.Verify(tt.doc, tt.key)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.errMatch != "" && !strings.Contains(err.Error(), tt.errMatch) {
				t.Errorf("expected error containing %q, got %q", tt.errMatch, err.Error())
			}
		})
	}
}

// Test with proof array
func TestVerifyWithProofArray(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	document := map[string]any{
		"id":   testDocID,
		"data": "test data",
	}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	// Convert single proof to array with other proofs
	jcsProof := signed["proof"]
	signed["proof"] = []any{
		map[string]any{"type": "OtherProof", "proofValue": "xxx"},
		jcsProof,
		map[string]any{"type": "AnotherProof", "proofValue": "yyy"},
	}

	err = suite.Verify(signed, pub)
	if err != nil {
		t.Fatalf("Verify failed with proof array: %v", err)
	}
}

// Test findJCSProof with array containing no JCS proof
func TestFindJCSProofNotFound(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	doc := map[string]any{
		"id": "test",
		"proof": []any{
			map[string]any{"type": "OtherProof", "proofValue": "xxx"},
			map[string]any{"type": "AnotherProof", "proofValue": "yyy"},
		},
	}

	err := suite.Verify(doc, pub)
	if err == nil {
		t.Fatal("expected error for missing JCS proof")
	}
}

// Test invalid proof format
func TestFindJCSProofInvalidFormat(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	doc := map[string]any{
		"id":    "test",
		"proof": "invalid-string-proof",
	}

	err := suite.Verify(doc, pub)
	if err == nil {
		t.Fatal("expected error for invalid proof format")
	}
}

// Test Sign preserves existing proof as array
func TestSignPreservesExistingProofArray(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	existingProofs := []any{
		map[string]any{"type": "Proof1", "proofValue": "value1"},
		map[string]any{"type": "Proof2", "proofValue": "value2"},
	}

	document := map[string]any{
		"id":    testDocID,
		"proof": existingProofs,
	}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	proofArray, ok := signed["proof"].([]any)
	if !ok {
		t.Fatal("expected proof to be an array")
	}

	if len(proofArray) != 3 {
		t.Errorf("expected 3 proofs (2 existing + 1 new), got %d", len(proofArray))
	}
}

// Test Sign preserves existing single proof
func TestSignPreservesExistingSingleProof(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	existingProof := map[string]any{
		"type":       "ExistingProof",
		"proofValue": "existing-value",
	}

	document := map[string]any{
		"id":    testDocID,
		"proof": existingProof,
	}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	proofArray, ok := signed["proof"].([]any)
	if !ok {
		t.Fatal("expected proof to be converted to an array")
	}

	if len(proofArray) != 2 {
		t.Errorf("expected 2 proofs, got %d", len(proofArray))
	}

	firstProof := proofArray[0].(map[string]any)
	if firstProof["type"] != "ExistingProof" {
		t.Error("existing proof was not preserved first")
	}
}

// Test toMap with struct
func TestToMapWithStruct(t *testing.T) {
	type TestDoc struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	document := TestDoc{ID: "test-123", Name: "Test Document"}

	opts := &SignOptions{
		VerificationMethod: testVerificationMethodIssuer,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf("Sign with struct failed: %v", err)
	}

	if signed["id"] != "test-123" {
		t.Errorf("expected id test-123, got %v", signed["id"])
	}

	err = suite.Verify(signed, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

// Test Verify with struct document
func TestVerifyWithStructDocument(t *testing.T) {
	type SignedDoc struct {
		ID    string         `json:"id"`
		Proof map[string]any `json:"proof"`
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	// First sign a document
	document := map[string]any{"id": "test-struct"}
	opts := &SignOptions{
		VerificationMethod: testVerificationMethodKey,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	// Convert to struct and verify
	structDoc := SignedDoc{
		ID:    signed["id"].(string),
		Proof: signed["proof"].(map[string]any),
	}

	err = suite.Verify(structDoc, pub)
	if err != nil {
		t.Fatalf("Verify with struct failed: %v", err)
	}
}

// Test VerifyWithProof directly
func TestVerifyWithProofDirect(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	document := map[string]any{"id": "test", "data": "value"}
	opts := &SignOptions{
		VerificationMethod: testVerificationMethodKey,
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}

	proof := signed["proof"].(map[string]any)
	err = suite.VerifyWithProof(signed, proof, pub)
	if err != nil {
		t.Fatalf("VerifyWithProof failed: %v", err)
	}
}

// Test invalid signature length
func TestVerifyInvalidSignatureLength(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	// z followed by short base58 data (not 64 bytes)
	doc := map[string]any{
		"id": "test",
		"proof": map[string]any{
			"type":        ProofTypeDataIntegrity,
			"cryptosuite": CryptosuiteEdDSAJCS2022,
			"proofValue":  "z2J", // Valid multibase but short signature
		},
	}

	err := suite.Verify(doc, pub)
	if err == nil {
		t.Fatal("expected error for invalid signature length")
	}
}

// Test getString with non-string value
func TestGetStringWithNonString(t *testing.T) {
	m := map[string]any{
		"string": "value",
		"number": 42,
		"object": map[string]any{},
	}

	if s, ok := getString(m, "string"); !ok || s != "value" {
		t.Error("getString failed for string value")
	}

	if _, ok := getString(m, "number"); ok {
		t.Error("getString should return false for number")
	}

	if _, ok := getString(m, "object"); ok {
		t.Error("getString should return false for object")
	}

	if _, ok := getString(m, "missing"); ok {
		t.Error("getString should return false for missing key")
	}
}

// Test Sign with auto-generated created time
func TestSignAutoCreatedTime(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	suite := NewSuite()

	document := map[string]any{"id": "test"}
	opts := &SignOptions{
		VerificationMethod: testVerificationMethodKey,
		ProofPurpose:       "assertionMethod",
		// Created is zero, should be auto-generated
	}

	before := time.Now().UTC().Add(-time.Second) // Add buffer for timing
	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf(errSignFailed, err)
	}
	after := time.Now().UTC().Add(time.Second) // Add buffer for timing

	proof := signed["proof"].(map[string]any)
	created, ok := proof["created"].(string)
	if !ok {
		t.Fatal("missing created timestamp")
	}

	createdTime, err := time.Parse(time.RFC3339, created)
	if err != nil {
		t.Fatalf("invalid created timestamp format: %v", err)
	}

	if createdTime.Before(before) || createdTime.After(after) {
		t.Errorf("created timestamp %v not in expected range [%v, %v]", createdTime, before, after)
	}
}

// Test constants
func TestConstants(t *testing.T) {
	if CryptosuiteEdDSAJCS2022 != "eddsa-jcs-2022" {
		t.Errorf("unexpected CryptosuiteEdDSAJCS2022 value: %s", CryptosuiteEdDSAJCS2022)
	}
	if ProofTypeDataIntegrity != "DataIntegrityProof" {
		t.Errorf("unexpected ProofTypeDataIntegrity value: %s", ProofTypeDataIntegrity)
	}
}

// Test isJCSProof
func TestIsJCSProof(t *testing.T) {
	tests := []struct {
		name     string
		proof    map[string]any
		expected bool
	}{
		{
			name:     "valid JCS proof",
			proof:    map[string]any{"type": ProofTypeDataIntegrity, "cryptosuite": CryptosuiteEdDSAJCS2022},
			expected: true,
		},
		{
			name:     "wrong type",
			proof:    map[string]any{"type": "Other", "cryptosuite": CryptosuiteEdDSAJCS2022},
			expected: false,
		},
		{
			name:     "wrong cryptosuite",
			proof:    map[string]any{"type": ProofTypeDataIntegrity, "cryptosuite": "other"},
			expected: false,
		},
		{
			name:     "missing type",
			proof:    map[string]any{"cryptosuite": CryptosuiteEdDSAJCS2022},
			expected: false,
		},
		{
			name:     "missing cryptosuite",
			proof:    map[string]any{"type": ProofTypeDataIntegrity},
			expected: false,
		},
		{
			name:     "empty proof",
			proof:    map[string]any{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isJCSProof(tt.proof)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
