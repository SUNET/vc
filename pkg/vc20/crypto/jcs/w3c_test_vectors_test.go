// Package jcs tests using official W3C test vectors from the
// Data Integrity EdDSA Cryptosuites v1.0 specification.
// Reference: https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022
package jcs

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"maps"
	"testing"

	"github.com/multiformats/go-multibase"
)

// W3C Test Vectors from Section B.3: Representation: eddsa-jcs-2022
// https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022

// Test keys from the specification
const (
	// Public key: multicodec ed25519-pub (0xed) + 32 bytes
	w3cPublicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
	// Secret key: multicodec ed25519-priv (0x1300) + 32 bytes (seed only)
	w3cSecretKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"

	// Common W3C @context URLs
	w3cCredentialsContextV2  = "https://www.w3.org/ns/credentials/v2"
	w3cCredentialsExamplesV2 = "https://www.w3.org/ns/credentials/examples/v2"

	// W3C test vector values
	w3cTestVerificationMethod = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
	w3cTestCreated            = "2023-02-24T23:36:38Z"
)

// Expected intermediate values from the specification
const (
	// EXAMPLE 31: Canonical Credential without Proof
	expectedCanonicalCredential = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"credentialSubject":{"alumniOf":"The School of Examples","id":"did:example:abcdefgh"},"description":"A minimum viable example of an Alumni Credential.","id":"urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33","issuer":"https://vc.example/issuers/5678","name":"Alumni Credential","type":["VerifiableCredential","AlumniCredential"],"validFrom":"2023-01-01T00:00:00Z"}`

	// EXAMPLE 32: Hash of Canonical Credential without Proof (hex)
	expectedCredentialHash = "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"

	// EXAMPLE 34: Canonical Proof Options Document
	expectedCanonicalProofOptions = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"created":"2023-02-24T23:36:38Z","cryptosuite":"eddsa-jcs-2022","proofPurpose":"assertionMethod","type":"DataIntegrityProof","verificationMethod":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"}`

	// EXAMPLE 35: Hash of Canonical Proof Options Document (hex) - truncated in spec, using known hash
	expectedProofHash = "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db"

	// EXAMPLE 36: Combine hashes of Proof Options and Credential (hex)
	expectedCombinedHash = "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"

	// EXAMPLE 37: Signature of Combined Hashes (hex)
	expectedSignature = "407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b80351da3f253d725c6f00b07c9e5448d50b3ef78012b9ab54255116d069c6dd2808"

	// EXAMPLE 38: Signature of Combined Hashes base58-btc
	expectedProofValue = "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"
)

// Unsigned credential from EXAMPLE 30
var w3cUnsignedCredential = map[string]any{
	keyContext: []any{
		w3cCredentialsContextV2,
		w3cCredentialsExamplesV2,
	},
	"id":          "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
	"type":        []any{"VerifiableCredential", "AlumniCredential"},
	"name":        "Alumni Credential",
	"description": "A minimum viable example of an Alumni Credential.",
	"issuer":      "https://vc.example/issuers/5678",
	"validFrom":   "2023-01-01T00:00:00Z",
	"credentialSubject": map[string]any{
		"id":       "did:example:abcdefgh",
		"alumniOf": "The School of Examples",
	},
}

// Signed credential from EXAMPLE 39
var w3cSignedCredential = map[string]any{
	keyContext: []any{
		w3cCredentialsContextV2,
		w3cCredentialsExamplesV2,
	},
	"id":          "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
	"type":        []any{"VerifiableCredential", "AlumniCredential"},
	"name":        "Alumni Credential",
	"description": "A minimum viable example of an Alumni Credential.",
	"issuer":      "https://vc.example/issuers/5678",
	"validFrom":   "2023-01-01T00:00:00Z",
	"credentialSubject": map[string]any{
		"id":       "did:example:abcdefgh",
		"alumniOf": "The School of Examples",
	},
	keyProof: map[string]any{
		"type":               ProofTypeDataIntegrity,
		"cryptosuite":        CryptosuiteEdDSAJCS2022,
		"created":            w3cTestCreated,
		"verificationMethod": w3cTestVerificationMethod,
		"proofPurpose":       "assertionMethod",
		keyContext: []any{
			w3cCredentialsContextV2,
			w3cCredentialsExamplesV2,
		},
		"proofValue": expectedProofValue,
	},
}

// decodeMultibaseKey decodes a multibase-encoded Ed25519 key.
// Ed25519 public keys use 0xed (237) prefix, private keys use 0x1300 (4864) prefix.
// Multicodec prefixes are varint-encoded, so we properly decode the varint length.
func decodeMultibaseKey(multibaseKey string) ([]byte, error) {
	_, keyBytes, err := multibase.Decode(multibaseKey)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("empty key bytes")
	}
	// Decode the multicodec varint prefix to determine prefix length
	codec, prefixLen := binary.Uvarint(keyBytes)
	if prefixLen <= 0 {
		return nil, fmt.Errorf("failed to decode multicodec prefix")
	}
	// Validate expected codecs: 0xed for ed25519-pub, 0x1300 for ed25519-priv
	if codec != 0xed && codec != 0x1300 {
		return nil, fmt.Errorf("unexpected multicodec: 0x%x (expected 0xed or 0x1300)", codec)
	}
	if prefixLen >= len(keyBytes) {
		return nil, fmt.Errorf("key bytes too short after prefix")
	}
	return keyBytes[prefixLen:], nil
}

func getW3CKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pubKeyBytes, err := decodeMultibaseKey(w3cPublicKeyMultibase)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		t.Fatalf("Invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	privKeyBytes, err := decodeMultibaseKey(w3cSecretKeyMultibase)
	if err != nil {
		t.Fatalf("Failed to decode private key: %v", err)
	}

	// The secret key is just the seed (32 bytes), need to derive full key
	if len(privKeyBytes) == ed25519.SeedSize {
		return ed25519.PublicKey(pubKeyBytes), ed25519.NewKeyFromSeed(privKeyBytes)
	}

	// If it's already 64 bytes, it's seed + public
	if len(privKeyBytes) == ed25519.PrivateKeySize {
		return ed25519.PublicKey(pubKeyBytes), ed25519.PrivateKey(privKeyBytes)
	}

	t.Fatalf("Invalid private key size: %d", len(privKeyBytes))
	return nil, nil
}

// TestW3CCanonicalizeCredential verifies our JCS canonicalization matches the W3C test vector.
func TestW3CCanonicalizeCredential(t *testing.T) {
	canonical, err := Canonicalize(w3cUnsignedCredential)
	if err != nil {
		t.Fatalf("Failed to canonicalize: %v", err)
	}

	if string(canonical) != expectedCanonicalCredential {
		t.Errorf("Canonical form mismatch.\nExpected: %s\nGot:      %s", expectedCanonicalCredential, string(canonical))
	}
}

// TestW3CCredentialHash verifies our hash of the canonicalized credential matches the W3C test vector.
func TestW3CCredentialHash(t *testing.T) {
	canonical, err := Canonicalize(w3cUnsignedCredential)
	if err != nil {
		t.Fatalf("Failed to canonicalize: %v", err)
	}

	hash := sha256.Sum256(canonical)
	hashHex := hex.EncodeToString(hash[:])

	if hashHex != expectedCredentialHash {
		t.Errorf("Credential hash mismatch.\nExpected: %s\nGot:      %s", expectedCredentialHash, hashHex)
	}
}

// TestW3CProofOptionsHash verifies the proof options hash matches the W3C test vector.
func TestW3CProofOptionsHash(t *testing.T) {
	// Proof options from EXAMPLE 33
	proofOptions := buildW3CProofOptions()

	canonical, err := Canonicalize(proofOptions)
	if err != nil {
		t.Fatalf("Failed to canonicalize proof options: %v", err)
	}

	if string(canonical) != expectedCanonicalProofOptions {
		t.Errorf("Canonical proof options mismatch.\nExpected: %s\nGot:      %s", expectedCanonicalProofOptions, string(canonical))
	}

	hash := sha256.Sum256(canonical)
	hashHex := hex.EncodeToString(hash[:])

	if hashHex != expectedProofHash {
		t.Errorf("Proof options hash mismatch.\nExpected: %s\nGot:      %s", expectedProofHash, hashHex)
	}
}

// TestW3CCombinedHash verifies the combined hash (proofHash || docHash) matches the W3C test vector.
func TestW3CCombinedHash(t *testing.T) {
	proofOptions := buildW3CProofOptions()

	proofCanonical, err := Canonicalize(proofOptions)
	if err != nil {
		t.Fatalf("Failed to canonicalize proof options: %v", err)
	}

	docCanonical, err := Canonicalize(w3cUnsignedCredential)
	if err != nil {
		t.Fatalf("Failed to canonicalize credential: %v", err)
	}

	proofHash := sha256.Sum256(proofCanonical)
	docHash := sha256.Sum256(docCanonical)

	// Per spec Section 3.3.4: hashData = proofConfigHash || transformedDocumentHash
	combined := append(proofHash[:], docHash[:]...)
	combinedHex := hex.EncodeToString(combined)

	if combinedHex != expectedCombinedHash {
		t.Errorf("Combined hash mismatch.\nExpected: %s\nGot:      %s", expectedCombinedHash, combinedHex)
	}
}

// buildW3CProofOptions creates the standard W3C test vector proof options.
func buildW3CProofOptions() map[string]any {
	return map[string]any{
		"type":               ProofTypeDataIntegrity,
		"cryptosuite":        CryptosuiteEdDSAJCS2022,
		"created":            w3cTestCreated,
		"verificationMethod": w3cTestVerificationMethod,
		"proofPurpose":       "assertionMethod",
		keyContext: []any{
			w3cCredentialsContextV2,
			w3cCredentialsExamplesV2,
		},
	}
}

// TestW3CVerifySignedCredential verifies the W3C signed credential using our implementation.
func TestW3CVerifySignedCredential(t *testing.T) {
	pubKey, _ := getW3CKeys(t)

	suite := NewSuite()
	err := suite.Verify(w3cSignedCredential, pubKey)
	if err != nil {
		t.Fatalf("Failed to verify W3C signed credential: %v", err)
	}
}

// TestW3CSignatureBytes verifies the signature value from the W3C test vector.
func TestW3CSignatureBytes(t *testing.T) {
	// Decode the proofValue from the signed credential
	_, sigBytes, err := multibase.Decode(expectedProofValue)
	if err != nil {
		t.Fatalf("Failed to decode proofValue: %v", err)
	}

	sigHex := hex.EncodeToString(sigBytes)
	if sigHex != expectedSignature {
		t.Errorf("Signature bytes mismatch.\nExpected: %s\nGot:      %s", expectedSignature, sigHex)
	}
}

// TestW3CRoundTrip tests that we can sign and verify a document with the W3C keys.
func TestW3CRoundTrip(t *testing.T) {
	pubKey, privKey := getW3CKeys(t)

	suite := NewSuite()

	// Sign the unsigned credential
	opts := &SignOptions{
		VerificationMethod: w3cTestVerificationMethod,
		ProofPurpose:       testProofPurposeAssertion,
	}

	signed, err := suite.Sign(w3cUnsignedCredential, privKey, opts)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify the signed credential
	if err := suite.Verify(signed, pubKey); err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	// Check that proof contains @context
	proof, ok := signed["proof"].(map[string]any)
	if !ok {
		t.Fatal("signed document has no proof")
	}
	if _, hasCtx := proof[keyContext]; !hasCtx {
		t.Error("proof is missing @context (required by W3C spec)")
	}
}

// TestW3CContextSupersetAllowed tests that verification succeeds when document @context is a superset
// that starts with the proof @context values (per W3C spec step 4.1).
func TestW3CContextSupersetAllowed(t *testing.T) {
	pubKey, _ := getW3CKeys(t)

	// Create a modified credential where document @context has extra entries
	modifiedCredential := make(map[string]any)
	maps.Copy(modifiedCredential, w3cSignedCredential)
	// Add an extra context entry that wasn't there when signed
	modifiedCredential[keyContext] = []any{
		w3cCredentialsContextV2,
		w3cCredentialsExamplesV2,
		"https://example.com/extra-context",
	}

	suite := NewSuite()

	// This should still verify because document @context STARTS with proof @context
	// Per spec step 4.1: "Check that the securedDocument.@context starts with all values
	// contained in the proofOptions.@context in the same order"
	err := suite.Verify(modifiedCredential, pubKey)
	if err != nil {
		t.Fatalf("Verification should succeed when doc @context starts with proof @context: %v", err)
	}
}

// TestW3CContextOrderMismatch tests that verification fails when @context order doesn't match.
func TestW3CContextOrderMismatch(t *testing.T) {
	pubKey, _ := getW3CKeys(t)

	// Create a modified credential with @context in wrong order
	modifiedCredential := make(map[string]any)
	maps.Copy(modifiedCredential, w3cSignedCredential)
	// Reverse the context order
	modifiedCredential[keyContext] = []any{
		w3cCredentialsExamplesV2,
		w3cCredentialsContextV2,
	}

	suite := NewSuite()
	err := suite.Verify(modifiedCredential, pubKey)
	if err == nil {
		t.Error("Verification should fail when @context order doesn't match proof @context")
	}
}

// TestW3CContextMissing tests that verification fails when document lacks @context but proof has it.
func TestW3CContextMissing(t *testing.T) {
	pubKey, _ := getW3CKeys(t)

	// Create a modified credential without @context
	modifiedCredential := make(map[string]any)
	for k, v := range w3cSignedCredential {
		if k != keyContext {
			modifiedCredential[k] = v
		}
	}

	suite := NewSuite()
	err := suite.Verify(modifiedCredential, pubKey)
	if err == nil {
		t.Error("Verification should fail when document lacks @context but proof has it")
	}
}
