// Package jcs implements the EdDSA Cryptosuite using JSON Canonicalization Scheme (JCS)
// as defined in the W3C Data Integrity EdDSA Cryptosuites v1.0 specification.
//
// This implements the eddsa-jcs-2022 cryptosuite which uses:
// - JSON Canonicalization Scheme (RFC 8785) for document canonicalization
// - SHA-256 for hashing
// - Ed25519 for signatures
//
// Reference: https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022
package jcs

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-json-experiment/json/jsontext"
	"github.com/multiformats/go-multibase"
)

const (
	// CryptosuiteEdDSAJCS2022 is the identifier for the eddsa-jcs-2022 cryptosuite
	CryptosuiteEdDSAJCS2022 = "eddsa-jcs-2022"

	// ProofTypeDataIntegrity is the W3C Data Integrity proof type
	ProofTypeDataIntegrity = "DataIntegrityProof"

	// JSON-LD keys
	keyContext    = "@context"
	keyProof      = "proof"
	keyProofValue = "proofValue"
)

// Suite implements the eddsa-jcs-2022 cryptosuite for W3C Data Integrity proofs.
type Suite struct{}

// NewSuite creates a new eddsa-jcs-2022 cryptosuite instance.
func NewSuite() *Suite {
	return &Suite{}
}

// SignOptions contains options for creating a Data Integrity proof.
type SignOptions struct {
	VerificationMethod string
	ProofPurpose       string
	Created            time.Time
	Domain             string
	Challenge          string
}

// DataIntegrityProof represents a W3C Data Integrity proof.
type DataIntegrityProof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	Created            string `json:"created"`
	ProofValue         string `json:"proofValue"`
	Domain             string `json:"domain,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
}

// Sign creates a Data Integrity proof for a JSON document using eddsa-jcs-2022.
func (s *Suite) Sign(document any, key ed25519.PrivateKey, opts *SignOptions) (map[string]any, error) {
	if err := validateSignInputs(document, key, opts); err != nil {
		return nil, err
	}

	docMap, err := toMap(document)
	if err != nil {
		return nil, fmt.Errorf("failed to convert document to map: %w", err)
	}

	docWithoutProof := copyMapWithoutKey(docMap, keyProof)
	proofConfig := buildProofConfig(opts, docWithoutProof)

	proofValue, err := createSignature(docWithoutProof, proofConfig, key)
	if err != nil {
		return nil, err
	}
	proofConfig[keyProofValue] = proofValue

	return buildSignedDocument(docMap, proofConfig), nil
}

// validateSignInputs validates the inputs for the Sign method.
func validateSignInputs(document any, key ed25519.PrivateKey, opts *SignOptions) error {
	if document == nil {
		return fmt.Errorf("document is nil")
	}
	if key == nil {
		return fmt.Errorf("private key is nil")
	}
	if opts == nil {
		return fmt.Errorf("sign options are nil")
	}
	if opts.VerificationMethod == "" {
		return fmt.Errorf("verificationMethod is required")
	}
	if opts.ProofPurpose == "" {
		return fmt.Errorf("proofPurpose is required")
	}
	return nil
}

// buildProofConfig creates the proof configuration object.
func buildProofConfig(opts *SignOptions, docWithoutProof map[string]any) map[string]any {
	created := opts.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}

	proofConfig := map[string]any{
		"type":               ProofTypeDataIntegrity,
		"cryptosuite":        CryptosuiteEdDSAJCS2022,
		"verificationMethod": opts.VerificationMethod,
		"proofPurpose":       opts.ProofPurpose,
		"created":            created.Format(time.RFC3339),
	}

	if opts.Domain != "" {
		proofConfig["domain"] = opts.Domain
	}
	if opts.Challenge != "" {
		proofConfig["challenge"] = opts.Challenge
	}

	// Per W3C eddsa-jcs-2022 spec Section 3.3.1 step 2:
	// If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context
	if ctx, ok := docWithoutProof[keyContext]; ok {
		proofConfig[keyContext] = ctx
	}

	return proofConfig
}

// createSignature generates the signature for the document and proof config.
func createSignature(docWithoutProof, proofConfig map[string]any, key ed25519.PrivateKey) (string, error) {
	docCanonical, err := Canonicalize(docWithoutProof)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize document: %w", err)
	}

	proofCanonical, err := Canonicalize(proofConfig)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize proof config: %w", err)
	}

	docHash := sha256.Sum256(docCanonical)
	proofHash := sha256.Sum256(proofCanonical)
	combined := append(proofHash[:], docHash[:]...)

	signature := ed25519.Sign(key, combined)

	proofValue, err := multibase.Encode(multibase.Base58BTC, signature)
	if err != nil {
		return "", fmt.Errorf("failed to encode signature: %w", err)
	}

	return proofValue, nil
}

// buildSignedDocument creates the result document with the proof attached.
func buildSignedDocument(docMap, proofConfig map[string]any) map[string]any {
	result := copyMapWithoutKey(docMap, keyProof)

	existingProof, ok := docMap[keyProof]
	if !ok {
		result[keyProof] = proofConfig
		return result
	}

	switch p := existingProof.(type) {
	case []any:
		// Copy the slice to avoid mutating the original document
		newProofs := make([]any, len(p)+1)
		copy(newProofs, p)
		newProofs[len(p)] = proofConfig
		result[keyProof] = newProofs
	case map[string]any:
		result[keyProof] = []any{p, proofConfig}
	default:
		result[keyProof] = proofConfig
	}

	return result
}

// copyMapWithoutKey creates a shallow copy of a map excluding a specific key.
func copyMapWithoutKey(src map[string]any, excludeKey string) map[string]any {
	result := make(map[string]any)
	for k, v := range src {
		if k != excludeKey {
			result[k] = v
		}
	}
	return result
}

// Verify verifies an eddsa-jcs-2022 Data Integrity proof on a document.
func (s *Suite) Verify(document any, publicKey ed25519.PublicKey) error {
	docMap, err := toMap(document)
	if err != nil {
		return fmt.Errorf("failed to convert document to map: %w", err)
	}

	proof, err := findJCSProof(docMap)
	if err != nil {
		return err
	}

	return s.VerifyWithProof(docMap, proof, publicKey)
}

// VerifyWithProof verifies a document with a specific proof object.
func (s *Suite) VerifyWithProof(document map[string]any, proof map[string]any, publicKey ed25519.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("public key is nil")
	}

	signatureBytes, err := validateAndDecodeProof(proof)
	if err != nil {
		return err
	}

	docWithoutProof := copyMapWithoutKey(document, keyProof)
	proofConfig := copyMapWithoutKey(proof, keyProofValue)

	if err := validateContext(docWithoutProof, proofConfig); err != nil {
		return err
	}

	return verifySignature(docWithoutProof, proofConfig, signatureBytes, publicKey)
}

// validateAndDecodeProof validates the proof structure and decodes the signature.
func validateAndDecodeProof(proof map[string]any) ([]byte, error) {
	proofType, _ := getString(proof, "type")
	if proofType != ProofTypeDataIntegrity {
		return nil, fmt.Errorf("invalid proof type: expected %s, got %s", ProofTypeDataIntegrity, proofType)
	}

	cryptosuite, _ := getString(proof, "cryptosuite")
	if cryptosuite != CryptosuiteEdDSAJCS2022 {
		return nil, fmt.Errorf("invalid cryptosuite: expected %s, got %s", CryptosuiteEdDSAJCS2022, cryptosuite)
	}

	proofValue, ok := getString(proof, keyProofValue)
	if !ok || proofValue == "" {
		return nil, fmt.Errorf("proof is missing proofValue")
	}

	_, signatureBytes, err := multibase.Decode(proofValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode proofValue: %w", err)
	}

	if len(signatureBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", ed25519.SignatureSize, len(signatureBytes))
	}

	return signatureBytes, nil
}

// validateContext validates @context per W3C eddsa-jcs-2022 spec Section 3.3.2 steps 4.1-4.2.
func validateContext(docWithoutProof, proofConfig map[string]any) error {
	proofCtx, ok := proofConfig[keyContext]
	if !ok {
		return nil
	}

	docCtx, hasDocCtx := docWithoutProof[keyContext]
	if !hasDocCtx {
		return fmt.Errorf("proof has @context but document does not")
	}
	if !contextStartsWith(docCtx, proofCtx) {
		return fmt.Errorf("document @context does not start with proof @context values")
	}
	// Set unsecuredDocument.@context equal to proofOptions.@context
	docWithoutProof[keyContext] = proofCtx
	return nil
}

// verifySignature verifies the Ed25519 signature.
func verifySignature(docWithoutProof, proofConfig map[string]any, signatureBytes []byte, publicKey ed25519.PublicKey) error {
	docCanonical, err := Canonicalize(docWithoutProof)
	if err != nil {
		return fmt.Errorf("failed to canonicalize document: %w", err)
	}

	proofCanonical, err := Canonicalize(proofConfig)
	if err != nil {
		return fmt.Errorf("failed to canonicalize proof config: %w", err)
	}

	docHash := sha256.Sum256(docCanonical)
	proofHash := sha256.Sum256(proofCanonical)
	combined := append(proofHash[:], docHash[:]...)

	if !ed25519.Verify(publicKey, combined, signatureBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// Canonicalize applies JSON Canonicalization Scheme (RFC 8785) to the input.
func Canonicalize(data any) ([]byte, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	val := jsontext.Value(jsonBytes)
	if err := val.Canonicalize(); err != nil {
		return nil, fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	return []byte(val), nil
}

// toMap converts any type to map[string]any via JSON marshaling/unmarshaling.
func toMap(data any) (map[string]any, error) {
	if m, ok := data.(map[string]any); ok {
		return m, nil
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// findJCSProof finds the first eddsa-jcs-2022 proof in a document.
func findJCSProof(doc map[string]any) (map[string]any, error) {
	proofVal, ok := doc[keyProof]
	if !ok {
		return nil, fmt.Errorf("document has no proof")
	}

	switch p := proofVal.(type) {
	case map[string]any:
		if isJCSProof(p) {
			return p, nil
		}
		return nil, fmt.Errorf("proof is not an eddsa-jcs-2022 proof")
	case []any:
		for _, item := range p {
			if proofMap, ok := item.(map[string]any); ok && isJCSProof(proofMap) {
				return proofMap, nil
			}
		}
		return nil, fmt.Errorf("no eddsa-jcs-2022 proof found in proof array")
	default:
		return nil, fmt.Errorf("invalid proof format")
	}
}

// isJCSProof checks if a proof object is an eddsa-jcs-2022 proof.
func isJCSProof(proof map[string]any) bool {
	proofType, _ := getString(proof, "type")
	cryptosuite, _ := getString(proof, "cryptosuite")
	return proofType == ProofTypeDataIntegrity && cryptosuite == CryptosuiteEdDSAJCS2022
}

// getString safely gets a string value from a map.
func getString(m map[string]any, key string) (string, bool) {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s, true
		}
	}
	return "", false
}

// contextStartsWith checks if docCtx starts with proofCtx values in the same order.
// This implements the W3C eddsa-jcs-2022 spec Section 3.3.2 step 4.1.
func contextStartsWith(docCtx, proofCtx any) bool {
	// Normalize both to slices for comparison
	docSlice := normalizeContext(docCtx)
	proofSlice := normalizeContext(proofCtx)

	if len(proofSlice) > len(docSlice) {
		return false
	}

	for i, proofVal := range proofSlice {
		if !contextValuesEqual(docSlice[i], proofVal) {
			return false
		}
	}

	return true
}

// normalizeContext converts a @context value to a slice of values.
func normalizeContext(ctx any) []any {
	if ctx == nil {
		return nil
	}
	if slice, ok := ctx.([]any); ok {
		return slice
	}
	// Handle []string (common in Go code)
	if strSlice, ok := ctx.([]string); ok {
		result := make([]any, len(strSlice))
		for i, s := range strSlice {
			result[i] = s
		}
		return result
	}
	// Single value context
	return []any{ctx}
}

// contextValuesEqual compares two @context values for equality.
func contextValuesEqual(a, b any) bool {
	// For strings, direct comparison
	if aStr, ok := a.(string); ok {
		if bStr, ok := b.(string); ok {
			return aStr == bStr
		}
		return false
	}
	// For objects (maps), compare JSON representation
	if aMap, ok := a.(map[string]any); ok {
		if bMap, ok := b.(map[string]any); ok {
			aJSON, err1 := json.Marshal(aMap)
			bJSON, err2 := json.Marshal(bMap)
			if err1 != nil || err2 != nil {
				return false
			}
			return string(aJSON) == string(bJSON)
		}
	}
	return false
}
