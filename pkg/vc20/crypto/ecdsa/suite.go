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
	docHashBytes, err := credential.UnsecuredDocumentHash(cred)
	if err != nil {
		return nil, err
	}

	// 2. Create proof configuration using helper
	proofConfig := buildProofConfig(opts)

	// 3. Canonicalize and hash proof configuration
	ldOpts := credential.NewJSONLDOptions("")
	ldOpts.Algorithm = ld.AlgorithmURDNA2015

	proofHashBytes, err := credential.ProofConfigHash(proofConfig, ldOpts)
	if err != nil {
		return nil, err
	}

	// 4. Combine hashes
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
	credMap, err := credential.DocumentAsMap(cred)
	if err != nil {
		return nil, err
	}

	proofConfig["proofValue"] = proofValue
	credential.AppendProof(credMap, proofConfig)

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
	// The proofs the document attaches to itself and the hash of what they
	// secure, with the same root-stability check Sign applies. See
	// credential.SecuredDocument.
	proofs, docHashBytes, err := credential.SecuredDocument(cred)
	if err != nil {
		return nil, err
	}

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
