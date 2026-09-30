package ecdsa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"maps"
	"math/big"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
	vccrypto "github.com/SUNET/vc/pkg/vc20/crypto"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
)

const (
	Cryptosuite2019 = "ecdsa-rdfc-2019"
	ProofType       = credential.ProofTypeDataIntegrity
)

// Suite implements the ECDSA Cryptosuite v1.0
type Suite struct{}

// NewSuite creates a new ECDSA cryptosuite
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

// Sign signs a credential using ecdsa-rdfc-2019
func (s *Suite) Sign(ctx context.Context, cred *credential.RDFCredential, key *ecdsa.PrivateKey, opts *SignOptions) (*credential.RDFCredential, error) {
	if key == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	// Wrap the raw key and delegate to SignWithSigner
	wrapper := vccrypto.NewECDSAKeyWrapper(key)
	return s.SignWithSigner(ctx, cred, wrapper, opts)
}

// buildProofConfig creates the initial proof configuration map.
func buildProofConfig(opts *SignOptions) map[string]any {
	created := opts.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}

	config := map[string]any{
		"@context":           credential.ContextV2,
		"type":               ProofType,
		"cryptosuite":        Cryptosuite2019,
		"verificationMethod": opts.VerificationMethod,
		"proofPurpose":       opts.ProofPurpose,
		"created":            created.Format(time.RFC3339),
	}

	if opts.Domain != "" {
		config["domain"] = opts.Domain
	}
	if opts.Challenge != "" {
		config["challenge"] = opts.Challenge
	}

	return config
}

// getCredentialAsMap converts an RDFCredential to a map for manipulation.
func getCredentialAsMap(cred *credential.RDFCredential) (map[string]any, error) {
	var credMap map[string]any
	originalJSON := cred.OriginalJSON()

	if originalJSON != "" {
		if err := json.Unmarshal([]byte(originalJSON), &credMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal original credential: %w", err)
		}
		return credMap, nil
	}

	// Convert from RDF
	jsonBytes, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to convert credential to JSON: %w", err)
	}
	if err := json.Unmarshal(jsonBytes, &credMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal converted credential: %w", err)
	}
	return credMap, nil
}

// addProofToCredential adds a proof to the credential map, handling existing proofs.
func addProofToCredential(credMap map[string]any, proof map[string]any) {
	existingProof, hasProof := credMap["proof"]
	if !hasProof {
		credMap["proof"] = proof
		return
	}

	if proofs, ok := existingProof.([]any); ok {
		credMap["proof"] = append(proofs, proof)
	} else {
		credMap["proof"] = []any{existingProof, proof}
	}
}

// hashForCurve returns a new hash instance appropriate for the given curve.
// P-256 uses SHA-256, P-384 uses SHA-384, P-521 uses SHA-512.
func hashForCurve(curve elliptic.Curve) hash.Hash {
	switch curve {
	case elliptic.P384():
		return sha512.New384()
	case elliptic.P521():
		return sha512.New()
	default:
		return sha256.New()
	}
}

// hashCombinedData hashes the combined proof+document hash to produce a
// curve-appropriate digest size. This ensures the full combined data is
// cryptographically bound in the signature.
func hashCombinedData(combined []byte, pubKey crypto.PublicKey) []byte {
	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		// Fallback to SHA-256 if we can't determine the curve
		h := sha256.Sum256(combined)
		return h[:]
	}

	hasher := hashForCurve(ecPub.Curve)
	hasher.Write(combined)
	return hasher.Sum(nil)
}

// SignWithSigner signs a credential using ecdsa-rdfc-2019 with a VCSigner.
// This method supports both raw keys (via wrappers) and HSM-backed keys (via pki.RawSigner).
func (s *Suite) SignWithSigner(ctx context.Context, cred *credential.RDFCredential, signer vccrypto.VCSigner, opts *SignOptions) (*credential.RDFCredential, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}
	if opts == nil {
		return nil, fmt.Errorf("sign options are nil")
	}

	// 1. Get canonical document hash - the document this proof SECURES,
	// which is the document with the root's own proofs removed and every
	// embedded proof DELIBERATELY left where it is: an embedded
	// credential's issuer proof is content this signature covers. See
	// credential.RootProofs.
	// Refuse a document that would verify in one serialization and not
	// another before signing it. See CheckRootSurvivesFlattening.
	if err := cred.CheckRootSurvivesFlattening(); err != nil {
		return nil, err
	}

	_, credWithoutProof, err := cred.RootProofs()
	if err != nil {
		return nil, fmt.Errorf("failed to get the document the proof secures: %w", err)
	}

	// 2. Create proof configuration using helper
	proofConfig := buildProofConfig(opts)

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

	// 4. Combine hashes
	docCanonical, err := credWithoutProof.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form of document: %w", err)
	}

	proofCanonical, err := proofCred.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form of proof config: %w", err)
	}

	docHashBytes := sha256.Sum256([]byte(docCanonical))
	proofHashBytes := sha256.Sum256([]byte(proofCanonical))
	combined := append(proofHashBytes[:], docHashBytes[:]...)

	// 5. Hash combined data to curve-appropriate size before signing.
	// This ensures both proofHash and docHash are cryptographically bound
	// in the signature (raw ECDSA would truncate to curve order size).
	digest := hashCombinedData(combined, signer.PublicKey())

	// 6. Sign using the VCSigner
	signature, err := signer.SignDigest(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// 7. Encode signature (multibase base58-btc)
	proofValue, err := multibase.Encode(multibase.Base58BTC, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	// 7. Add proof to credential using helpers
	credMap, err := getCredentialAsMap(cred)
	if err != nil {
		return nil, err
	}

	proofConfig["proofValue"] = proofValue
	addProofToCredential(credMap, proofConfig)

	// Create new RDFCredential
	newCredBytes, err := json.Marshal(credMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new credential: %w", err)
	}

	return credential.NewRDFCredentialFromJSON(newCredBytes, ldOpts)
}

// Verify verifies a credential using ecdsa-rdfc-2019.
func (s *Suite) Verify(cred *credential.RDFCredential, key *ecdsa.PublicKey) error {
	_, err := s.VerifyProof(cred, key)
	return err
}

// VerifyProof verifies a credential using ecdsa-rdfc-2019 and returns the
// proof that actually verified.
//
// WHICH proof is not a detail the caller can infer. A document may carry
// several root proofs and this tries each, so a caller that reads metadata
// off "the proof" - the first one in the array, say - can report a
// proofPurpose, a created or a verificationMethod from a proof that FAILED.
// An attacker only has to prepend one.
func (s *Suite) VerifyProof(cred *credential.RDFCredential, key *ecdsa.PublicKey) (map[string]any, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	// The proofs the document attaches to ITSELF, and the document they
	// secure. Read off the document rather than searched for anywhere in
	// the proof object, so a proof moved onto an embedded credential is not
	// a candidate - which is what an unqualified search used to make it.
	//
	// It would not verify either: hashing removes only the ROOT's proofs,
	// so a moved proof stays in the secured document and the hash changes
	// with it. See credential.RootProofs and
	// TestRelocatingAProofChangesTheSecuredDocument.
	// The same root-stability check Sign applies. Verification needs it
	// MORE than signing does: a signed document can be re-rooted by the
	// holder - the embedded credential lifted to the top level, the
	// presentation pushed under @included, and the presentation's proof
	// moved onto the credential - and removing the new root's proof then
	// reproduces the original unsecured RDF, so the signature verifies as
	// the credential's own. A document that names one root as written and
	// another once serialized through RDF is refused.
	if err := cred.CheckRootSurvivesFlattening(); err != nil {
		return nil, err
	}

	proofs, credWithoutProof, err := cred.RootProofs()
	if err != nil {
		return nil, err
	}
	if len(proofs) == 0 {
		return nil, fmt.Errorf("the document carries no proof of its own to verify")
	}

	docCanonical, err := credWithoutProof.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form of document: %w", err)
	}
	docHashBytes := sha256.Sum256([]byte(docCanonical))

	var lastErr error
	for _, expanded := range proofs {
		proofNode, err := s.verifyRootProof(cred, expanded, key, docHashBytes)
		if err != nil {
			lastErr = err
			continue
		}
		return proofNode, nil
	}

	return nil, lastErr
}

// verifyRootProof checks one of the document's own proofs against the key,
// over the document that proof secures.
func (s *Suite) verifyRootProof(cred *credential.RDFCredential, expanded any, key *ecdsa.PublicKey, docHashBytes [sha256.Size]byte) (map[string]any, error) {
	proofNode, err := credential.CompactRootProof(expanded)
	if err != nil {
		return nil, err
	}
	// A DataIntegrityProof of THIS suite. The type says the node is a proof
	// at all; the cryptosuite says which procedure produced the signature.
	if !credential.HasProofType(proofNode, ProofType) {
		return nil, fmt.Errorf("the document's own proof link names a %v, not a %s", proofNode["type"], ProofType)
	}
	if suite, _ := proofNode["cryptosuite"].(string); suite != Cryptosuite2019 {
		return nil, fmt.Errorf("the document's own proof declares cryptosuite %q, not %s", suite, Cryptosuite2019)
	}

	proofValue, ok := proofNode["proofValue"].(string)
	if !ok {
		return nil, fmt.Errorf("proofValue not found or not a string")
	}

	// 2. Build the proof configuration on a COPY, so the caller's proof
	// node keeps the signature that was checked.
	proofConfig := maps.Clone(proofNode)
	delete(proofConfig, "proofValue")

	// Ensure context is present for correct RDF conversion
	if _, ok := proofConfig["@context"]; !ok {
		proofConfig["@context"] = credential.ContextV2
	}

	// 3. Canonicalize proof configuration
	proofConfigBytes, err := json.Marshal(proofConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proof config: %w", err)
	}

	ldOpts := credential.NewJSONLDOptions("")
	// ldOpts.Format = "application/n-quads" // Do not set format, we want RDFDataset
	ldOpts.Algorithm = ld.AlgorithmURDNA2015

	proofConfigCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDF credential for proof config: %w", err)
	}

	proofCanonical, err := proofConfigCred.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form of proof config: %w", err)
	}

	// 4. Hash. The document half arrived already hashed: every proof the
	// root carries secures the same document.
	proofHashBytes := sha256.Sum256([]byte(proofCanonical))

	combined := append(proofHashBytes[:], docHashBytes[:]...)

	// Hash combined data to curve-appropriate size (same as Sign)
	digest := hashCombinedData(combined, key)

	// 6. Verify signature
	_, signature, err := multibase.Decode(proofValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode proofValue: %w", err)
	}

	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keyBytes {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", 2*keyBytes, len(signature))
	}

	rInt := new(big.Int).SetBytes(signature[:keyBytes])
	sInt := new(big.Int).SetBytes(signature[keyBytes:])

	if !ecdsa.Verify(key, digest, rInt, sInt) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return proofNode, nil
}
