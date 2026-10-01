package eddsa

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

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

	// 1. Get canonical document hash - the document this proof SECURES,
	// which is the document with the root's own proofs removed and every
	// embedded proof DELIBERATELY left where it is. An embedded
	// credential's issuer proof is content this signature covers; the code
	// that used to remove it is what let it be swapped or stripped. See
	// credential.UnsecuredDocumentHash.
	docHash, err := credential.UnsecuredDocumentHash(cred)
	if err != nil {
		return nil, err
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
	ldOpts := credential.NewJSONLDOptions("")
	ldOpts.Algorithm = ld.AlgorithmURDNA2015

	proofHash, err := credential.ProofConfigHash(proofConfig, ldOpts)
	if err != nil {
		return nil, err
	}

	// 4. Concatenate: proofHash + docHash (per spec)
	combined := append(proofHash[:], docHash[:]...)

	// 5. Sign with Ed25519
	signature := ed25519.Sign(key, combined)

	// 6. Encode signature (multibase base58-btc)
	proofValue, err := multibase.Encode(multibase.Base58BTC, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	// 7. Add proof to credential
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

// Verify verifies a credential using eddsa-rdfc-2022.
func (s *Suite) Verify(cred *credential.RDFCredential, key ed25519.PublicKey) error {
	_, err := s.VerifyProof(cred, key)
	return err
}

// VerifyProof verifies a credential using eddsa-rdfc-2022 and returns the
// proof that actually verified.
//
// WHICH proof is not a detail the caller can infer. A document may carry
// several root proofs and this tries each, so a caller that reads metadata
// off "the proof" - the first one in the array, say - can report a
// proofPurpose, a created or a verificationMethod from a proof that FAILED.
// An attacker only has to prepend one: the suite verifies the genuine proof
// later in the array while the caller describes the forged one in front.
//
// The proofs checked are the ones the document attaches to ITSELF, read off
// the document by credential.RootProofs rather than inferred from the
// reference graph. Sign attaches its proof to the top-level node, so the
// document has already answered which node it is about - and a graph-shaped
// guess could not, since a presentation linking a credential through a
// custom property and a credential whose subject is itself a credential are
// isomorphic in RDF.
//
// A proof moved onto an embedded credential is therefore not a candidate at
// all. It would not verify even if it were: hashing removes only the ROOT's
// proofs, so a moved proof stays in the secured document and the hash
// changes with it - see TestRelocatingAProofChangesTheSecuredDocument. That
// was not true while every proof was removed, which is what made relocation
// work in the first place.
func (s *Suite) VerifyProof(cred *credential.RDFCredential, key ed25519.PublicKey) (map[string]any, error) {
	return s.verifyRootProofs(cred, key, nil)
}

// VerifyRootProof verifies exactly the proof it is given and returns the
// candidate that verified.
//
// A caller holding several candidates must not ask the suite to pick one of
// its own: with a forged proof beside a genuine one, the suite can verify the
// genuine proof while the caller reports the forged one's purpose, created or
// verification method. It also stops the caller's loop from being quadratic -
// N candidates each rescanning N proofs - since this checks one.
//
// The match is on the WHOLE proof, not its proofValue. A forged proof that
// copies a genuine signature but changes its metadata is a different proof,
// and answering for the genuine one would hand back exactly the guarantee
// this is supposed to give.
func (s *Suite) VerifyRootProof(cred *credential.RDFCredential, key ed25519.PublicKey, proof map[string]any) (map[string]any, error) {
	if proof == nil {
		return nil, fmt.Errorf("proof is nil")
	}
	return s.verifyRootProofs(cred, key, proof)
}

func (s *Suite) verifyRootProofs(cred *credential.RDFCredential, key ed25519.PublicKey, want map[string]any) (map[string]any, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	// The proofs the document attaches to itself and the hash of what they
	// secure, with the same root-stability check Sign applies. See
	// credential.SecuredDocument.
	proofs, docHash, err := credential.SecuredDocument(cred)
	if err != nil {
		return nil, err
	}

	// EVERY proof the root carries, not just the first. Sign appends rather
	// than replaces, so a document signed by two keys carries two root
	// proofs - and checking only the first fails the second signature
	// against its own public key.
	//
	// Each is tried in turn and the first that verifies wins; the last
	// failure is what gets reported, since a document whose proofs all fail
	// is a document that did not verify.
	var lastErr error
	for _, expanded := range proofs {
		proofNode, err := credential.CompactRootProof(expanded)
		if err != nil {
			lastErr = err
			continue
		}
		// A DataIntegrityProof of THIS suite, checked in that order.
		//
		// The TYPE says the node is a proof at all. The previous selection
		// got that from FindProofNode's type filter; reading the root's
		// links directly would otherwise accept any node it points at that
		// happens to declare the cryptosuite.
		//
		// The CRYPTOSUITE says which procedure produced the signature. The
		// handler dispatches on the first proof while this loop may verify
		// a later one, so a proof made with the Ed25519 procedure but
		// labelled with some other suite could be verified here and
		// reported through the EdDSA handler as that other suite.
		// Relabelling an existing signature does not survive this anyway,
		// since the label is hashed into the proof configuration; the check
		// is here so that what verified and what is REPORTED cannot differ.
		if want != nil && !credential.SameProof(proofNode, want) {
			continue
		}
		if !credential.HasProofType(proofNode, ProofType) {
			lastErr = fmt.Errorf("the document's own proof link names a %v, not a %s", proofNode["type"], ProofType)
			continue
		}
		if suite, _ := proofNode["cryptosuite"].(string); suite != Cryptosuite2022 {
			lastErr = fmt.Errorf("the document's own proof declares cryptosuite %q, not %s", suite, Cryptosuite2022)
			continue
		}
		if err := s.verifyProofNode(cred, proofNode, key, docHash); err != nil {
			lastErr = err
			continue
		}
		return proofNode, nil
	}
	if lastErr == nil {
		if want != nil {
			lastErr = fmt.Errorf("the proof offered is not one this document attaches to itself")
		} else {
			lastErr = fmt.Errorf("the document's own proof link names no complete proof")
		}
	}

	return nil, lastErr
}

// verifyProofNode checks one proof node against the key, over the document
// that proof SECURES - the document with the root's own proofs removed and
// every embedded proof left where it is. An embedded credential's issuer
// proof is content the presentation's signature covers; removing it here
// would reinstate the hole credential.RootProofs closed.
//
// docHash is that document's hash, computed once by VerifyProof: every proof
// the root carries secures the same document, which is what a proof set
// means, so recomputing it per proof repeats the canonicalization for
// nothing.
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

	// Create the proof configuration, on a COPY.
	//
	// This used to delete proofValue from the caller's map and add an
	// @context to it. VerifyProof returns that map now, so mutating it
	// handed the caller a proof with no signature in it and a context it
	// never carried - an incomplete answer to "which proof verified".
	proofConfig := maps.Clone(proofNode)
	delete(proofConfig, "proofValue")

	// Ensure context
	if _, ok := proofConfig["@context"]; !ok {
		// Try to use context from credential if available
		if ctx, err := cred.Context(); err == nil && ctx != nil {
			proofConfig["@context"] = ctx
		} else {
			proofConfig["@context"] = credential.ContextV2
		}
	}

	proofConfigBytes, err := json.Marshal(proofConfig)
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
