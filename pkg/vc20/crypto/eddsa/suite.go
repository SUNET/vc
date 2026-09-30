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

	// WHICH proof, and it has to be the one the document attaches to
	// ITSELF. ProofObject() keeps proof quads and drops the links that say
	// whose proof is whose, so the answer is read off the document instead
	// - see rootProofGraphs.
	//
	// Taking the first proof found is not merely arbitrary here, it is
	// forgeable. Verify removes EVERY proof when hashing, so moving a proof
	// from the presentation onto the embedded credential leaves the hash
	// unchanged: someone holding a legitimately signed presentation could
	// move the holder proof down, delete the presentation's own proof, and
	// have the misplaced proof verify with the holder's key against a
	// document the holder never signed in that shape.
	//
	// So a document that attaches no proof to itself is REFUSED rather than
	// checked against whatever proof it happens to contain.
	rootGraphs := rootProofGraphs(cred)
	if len(rootGraphs) == 0 {
		return fmt.Errorf("the document carries no proof of its own to verify")
	}

	// Canonicalize the document the SAME way Sign does.
	//
	// Sign hashes CredentialWithoutProof() - every proof gone - of the
	// document as given. Verify did two things differently, and each one
	// broke a different presentation:
	//
	//   - It removed only proofs attached to nodes of a target type read
	//     from OriginalJSON(). That works while OriginalJSON() is the
	//     compact document the caller passed in. It is EXPANDED JSON-LD - a
	//     JSON array - for a credential re-parsed from MarshalJSON output,
	//     and then the map[string]any unmarshal fails, the error is
	//     swallowed, and the target silently stays "VerifiableCredential".
	//     For a presentation that removes the EMBEDDED credential's issuer
	//     proof and leaves the presentation's own proof - the one being
	//     verified - in the canonicalized document.
	//
	//   - It called NormalizeVerifiableCredentialGraph(), which Sign does
	//     not. That rewrites the verifiableCredential graph, so any
	//     presentation with a credential IN it canonicalized differently
	//     here than it did when it was signed - which is every presentation
	//     openid4vp.VPBuilder produces, in every serialization.
	//
	// Measured against the old code: a presentation carrying NO credential
	// verified unless it had been re-parsed from expanded JSON; one carrying
	// a credential failed in every form, including straight from Sign's
	// return value. ecdsa-rdfc-2019 does neither of these things and has
	// always worked, which is why only the EdDSA half was affected.
	//
	// NOTE: removing every proof means a presentation's signature does not
	// cover an embedded credential's issuer proof. That is pre-existing and
	// true of ECDSA too; changing it means changing both suites' signing
	// side as well, which is not this fix.
	//
	// Once, not once per proof. Every proof is checked against the SAME
	// proof-free document - that is what "remove every proof when hashing"
	// means - so a document with several root proofs used to repeat the
	// most expensive step, JSON-LD canonicalization, for each of them. The
	// proof CONFIGURATION hash stays per proof, since that is the part
	// that differs.
	credWithoutProof, err := cred.CredentialWithoutProof()
	if err != nil {
		return fmt.Errorf("failed to get credential without proof: %w", err)
	}

	docCanonical, err := credWithoutProof.CanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form of document: %w", err)
	}
	docHash := sha256.Sum256([]byte(docCanonical))

	// EVERY proof the root links, not just the first. Sign appends rather
	// than replaces, so a document signed by two keys carries two root
	// proofs - and checking only the first fails the second signature
	// against its own public key.
	//
	// Each is tried in turn and the first that verifies wins; the last
	// failure is what gets reported, since a document whose proofs all fail
	// is a document that did not verify.
	var lastErr error
	for _, graphName := range rootGraphs {
		proofNode := common.FindProofNodeInGraphs(proofMap, ProofType, []string{graphName})
		if proofNode == nil {
			lastErr = fmt.Errorf("the document's own proof link names no complete proof")
			continue
		}
		if err := s.verifyProofNode(cred, proofNode, key, docHash); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("the document's own proof link names no complete proof")
	}
	return lastErr
}

// verifyProofNode checks one proof node against the key, over the document
// with every proof removed.
//
// docHash is that document's hash, computed once by Verify: it is the same
// for every proof on the document, so recomputing it per proof repeats the
// canonicalization for nothing.
func (s *Suite) verifyProofNode(cred *credential.RDFCredential, proofNode map[string]any, key ed25519.PublicKey, docHash [sha256.Size]byte) error {

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

	// Create the proof configuration (remove proofValue)
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

	// 6. Hash. The document half arrived already hashed.
	proofHash := sha256.Sum256([]byte(proofCanonical))

	// Standard is proofHash + docHash
	combined := append(proofHash[:], docHash[:]...)

	if !ed25519.Verify(key, combined, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
