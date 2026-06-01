package eddsa

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
	"github.com/SUNET/vc/pkg/vc20/crypto/common"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
)

const (
	Cryptosuite2022 = "eddsa-rdfc-2022"
	ProofType       = credential.ProofTypeDataIntegrity
)

// Suite implements the EdDSA Cryptosuite v1.0 (eddsa-rdfc-2022)
type Suite struct{}

// NewSuite creates a new EdDSA cryptosuite
func NewSuite() *Suite {
	return &Suite{}
}

// SignOptions contains options for signing
type SignOptions struct {
	VerificationMethod string
	ProofPurpose       string
	Created            time.Time
	Domain             string
	Challenge          string
}

// Sign signs a credential using eddsa-rdfc-2022
func (s *Suite) Sign(cred *credential.RDFCredential, key ed25519.PrivateKey, opts *SignOptions) (*credential.RDFCredential, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if opts == nil {
		return nil, fmt.Errorf("sign options are nil")
	}

	// 1. Get canonical document hash (without proof)
	credWithoutProof, err := cred.CredentialWithoutProof()
	if err != nil {
		return nil, fmt.Errorf("failed to get credential without proof: %w", err)
	}

	// 2. Create proof configuration
	created := opts.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}

	proofConfig := map[string]any{
		"@context":           credential.ContextV2,
		"type":               ProofType,
		"cryptosuite":        Cryptosuite2022,
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

	// 3. Canonicalize and hash proof configuration
	proofConfigBytes, err := json.Marshal(proofConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proof config: %w", err)
	}

	ldOpts := credential.NewJSONLDOptions("")
	ldOpts.Algorithm = ld.AlgorithmURDNA2015

	proofCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDF credential for proof config: %w", err)
	}

	// 4. Get canonical forms and hash
	docCanonical, err := credWithoutProof.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form of document: %w", err)
	}

	proofCanonical, err := proofCred.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form of proof config: %w", err)
	}

	// Hash the canonical forms
	docHash := sha256.Sum256([]byte(docCanonical))
	proofHash := sha256.Sum256([]byte(proofCanonical))

	// Concatenate: proofHash + docHash (per spec)
	combined := append(proofHash[:], docHash[:]...)

	// 5. Sign with Ed25519
	signature := ed25519.Sign(key, combined)

	// 6. Encode signature (multibase base58-btc)
	proofValue, err := multibase.Encode(multibase.Base58BTC, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	// 7. Add proof to credential
	var credMap map[string]any
	originalJSON := cred.OriginalJSON()
	if originalJSON != "" {
		if err := json.Unmarshal([]byte(originalJSON), &credMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal original credential: %w", err)
		}
	} else {
		jsonBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, fmt.Errorf("failed to convert credential to JSON: %w", err)
		}
		if err := json.Unmarshal(jsonBytes, &credMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal converted credential: %w", err)
		}
	}

	// Add proofValue to proofConfig
	proofConfig["proofValue"] = proofValue

	// Add proof to credential (handle existing proofs)
	if existingProof, ok := credMap["proof"]; ok {
		if proofs, ok := existingProof.([]any); ok {
			credMap["proof"] = append(proofs, proofConfig)
		} else {
			credMap["proof"] = []any{existingProof, proofConfig}
		}
	} else {
		credMap["proof"] = proofConfig
	}

	// Create new RDFCredential
	newCredBytes, err := json.Marshal(credMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new credential: %w", err)
	}

	return credential.NewRDFCredentialFromJSON(newCredBytes, ldOpts)
}

// Verify verifies a credential using eddsa-rdfc-2022
func (s *Suite) Verify(cred *credential.RDFCredential, key ed25519.PublicKey) error {
	if cred == nil {
		return fmt.Errorf("credential is nil")
	}
	if key == nil {
		return fmt.Errorf("public key is nil")
	}

	// 1. Extract proof object
	proofCred, err := cred.ProofObject()
	if err != nil {
		return fmt.Errorf("failed to get proof object: %w", err)
	}

	// Convert proof to JSON to extract values
	proofJSONBytes, err := json.Marshal(proofCred)
	if err != nil {
		return fmt.Errorf("failed to convert proof to JSON: %w", err)
	}

	var proofJSON any
	if err := json.Unmarshal(proofJSONBytes, &proofJSON); err != nil {
		return fmt.Errorf("failed to unmarshal proof JSON: %w", err)
	}

	// Compact the proof JSON to ensure we have short keys
	proc := ld.NewJsonLdProcessor()
	compactOpts := credential.NewJSONLDOptions("")
	context := map[string]any{
		"@context": credential.ContextV2,
	}

	compactedProof, err := proc.Compact(proofJSON, context, compactOpts)
	if err != nil {
		return fmt.Errorf("failed to compact proof JSON: %w", err)
	}

	proofMap := compactedProof

	// Find proof node
	proofNode := common.FindProofNode(proofMap, ProofType)
	if proofNode == nil {
		return fmt.Errorf("proof node not found in proof object")
	}

	// Get proofValue
	proofValue, ok := proofNode["proofValue"].(string)
	if !ok {
		return fmt.Errorf("proofValue not found or not a string")
	}

	// 2. Decode proofValue (multibase)
	_, signature, err := multibase.Decode(proofValue)
	if err != nil {
		return fmt.Errorf("failed to decode proofValue: %w", err)
	}

	// 3. Fix VC graph structure if needed (workaround for json-gold bug)
	if err := cred.NormalizeVerifiableCredentialGraph(); err != nil {
		return fmt.Errorf("failed to normalize VC graph: %w", err)
	}

	// 4. Canonicalize document (without proof)
	// Determine if we are verifying a VP or VC to remove the correct proof
	targetType := "VerifiableCredential"

	// Check original JSON for type
	originalJSON := cred.OriginalJSON()
	if originalJSON != "" {
		var credMap map[string]any
		if err := json.Unmarshal([]byte(originalJSON), &credMap); err == nil {
			if common.HasType(credMap, "VerifiablePresentation") {
				targetType = "VerifiablePresentation"
			}
		}
	}

	credWithoutProof, err := cred.CredentialWithoutProofForTypes(targetType)
	if err != nil {
		return fmt.Errorf("failed to get credential without proof: %w", err)
	}

	docCanonical, err := credWithoutProof.CanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form of document: %w", err)
	}

	// 5. Create proof configuration (remove proofValue)
	delete(proofNode, "proofValue")

	// Ensure context
	if _, ok := proofNode["@context"]; !ok {
		// Try to use context from credential if available
		if ctx, err := cred.Context(); err == nil && ctx != nil {
			proofNode["@context"] = ctx
		} else {
			proofNode["@context"] = credential.ContextV2
		}
	}

	proofConfigBytes, err := json.Marshal(proofNode)
	if err != nil {
		return fmt.Errorf("failed to marshal proof config: %w", err)
	}

	ldOpts := credential.NewJSONLDOptions("")
	ldOpts.Algorithm = ld.AlgorithmURDNA2015

	proofConfigCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return fmt.Errorf("failed to create RDF credential for proof config: %w", err)
	}

	proofCanonical, err := proofConfigCred.CanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form of proof config: %w", err)
	}

	// 6. Hash
	docHash := sha256.Sum256([]byte(docCanonical))
	proofHash := sha256.Sum256([]byte(proofCanonical))

	// Standard is proofHash + docHash
	combined := append(proofHash[:], docHash[:]...)

	if !ed25519.Verify(key, combined, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
