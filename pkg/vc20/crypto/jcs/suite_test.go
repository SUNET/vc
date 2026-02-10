package jcs

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

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

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
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
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
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
	_, priv, _ := ed25519.GenerateKey(nil)
	wrongPub, _, _ := ed25519.GenerateKey(nil)

	suite := NewSuite()

	document := map[string]any{
		"id":   "test-doc",
		"data": "test data",
	}

	opts := &SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	err = suite.Verify(signed, wrongPub)
	if err == nil {
		t.Fatal("Verify should fail with wrong key")
	}
}

func TestVerifyFailsWithTamperedDocument(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	suite := NewSuite()

	document := map[string]any{
		"id":   "test-doc",
		"data": "original data",
	}

	opts := &SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	signed["data"] = "tampered data"

	err = suite.Verify(signed, pub)
	if err == nil {
		t.Fatal("Verify should fail with tampered document")
	}
}

func TestSignWithOptionalFields(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)

	suite := NewSuite()

	document := map[string]any{
		"id": "test-doc",
	}

	opts := &SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "authentication",
		Domain:             "example.com",
		Challenge:          "abc123",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
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
	pub, priv, _ := ed25519.GenerateKey(nil)

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
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
	}

	signed, err := suite.Sign(document, priv, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
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
