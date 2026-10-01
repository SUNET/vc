package credential

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/piprate/json-gold/ld"
)

// The steps every rdfc cryptosuite takes around its signature, which is the
// only part that differs between them. They lived once per suite, which is how
// eddsa and ecdsa came to disagree about which proofs a document secures
// without anybody noticing - the whole subject of this change. One copy means
// a scope fix cannot land in one suite and miss the other.

// ProofConfigHash canonicalizes a proof configuration and hashes it. The
// configuration is the proof WITHOUT its proofValue: the signature covers the
// metadata that describes it - the verification method, the purpose, the
// created time - so none of those can be edited after the fact.
func ProofConfigHash(proofConfig map[string]any, options *ld.JsonLdOptions) ([32]byte, error) {
	var zero [32]byte

	proofConfigBytes, err := json.Marshal(proofConfig)
	if err != nil {
		return zero, fmt.Errorf("failed to marshal proof config: %w", err)
	}

	proofCred, err := NewRDFCredentialFromJSON(proofConfigBytes, options)
	if err != nil {
		return zero, fmt.Errorf("failed to create RDF credential for proof config: %w", err)
	}

	proofCanonical, err := proofCred.CanonicalForm()
	if err != nil {
		return zero, fmt.Errorf("failed to get canonical form of proof config: %w", err)
	}

	return sha256.Sum256([]byte(proofCanonical)), nil
}

// UnsecuredDocumentHash returns the hash of the document a new proof will
// secure: this document with the ROOT's own proofs removed and every embedded
// proof deliberately left where it is. An embedded credential's issuer proof
// is content the new signature covers.
//
// The root-stability check comes first. Signing a document that names one root
// as written and another once serialized through RDF produces a signature
// whose meaning depends on which serialization the verifier sees.
func UnsecuredDocumentHash(cred *RDFCredential) ([32]byte, error) {
	var zero [32]byte

	if err := cred.CheckRootSurvivesFlattening(); err != nil {
		return zero, err
	}

	_, withoutRootProof, err := cred.RootProofs()
	if err != nil {
		return zero, fmt.Errorf("failed to get the document the proof secures: %w", err)
	}

	return documentHash(withoutRootProof)
}

// SecuredDocument returns the proofs the document attaches to ITSELF and the
// hash of the document they secure.
//
// Verification needs the root-stability check MORE than signing does: a signed
// document can be re-rooted by the holder - the embedded credential lifted to
// the top level, the presentation pushed under @included, and the
// presentation's proof moved onto the credential - and removing the new root's
// proof then reproduces the original unsecured RDF, so the signature verifies
// as the credential's own.
//
// The hash is computed once, not once per proof. Every proof the root carries
// secures the SAME document - that is what a proof set means - so the
// expensive step, JSON-LD canonicalization, runs once; the proof
// CONFIGURATION hash stays per proof, since that is the part that differs.
func SecuredDocument(cred *RDFCredential) ([]any, [32]byte, error) {
	var zero [32]byte

	if err := cred.CheckRootSurvivesFlattening(); err != nil {
		return nil, zero, err
	}

	proofs, withoutRootProof, err := cred.RootProofs()
	if err != nil {
		return nil, zero, err
	}
	if len(proofs) == 0 {
		return nil, zero, fmt.Errorf("the document carries no proof of its own to verify")
	}

	docHash, err := documentHash(withoutRootProof)
	if err != nil {
		return nil, zero, err
	}

	return proofs, docHash, nil
}

func documentHash(cred *RDFCredential) ([32]byte, error) {
	canonical, err := cred.CanonicalForm()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to get canonical form of document: %w", err)
	}
	return sha256.Sum256([]byte(canonical)), nil
}

// DocumentAsMap returns the credential as a JSON object, preferring the
// document as it was written. Marshalling the parsed credential instead would
// hand back whatever round-tripping through RDF produced, which is a different
// document to attach a proof to.
func DocumentAsMap(cred *RDFCredential) (map[string]any, error) {
	var credMap map[string]any

	if originalJSON := cred.OriginalJSON(); originalJSON != "" {
		if err := json.Unmarshal([]byte(originalJSON), &credMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal original credential: %w", err)
		}
		return credMap, nil
	}

	jsonBytes, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to convert credential to JSON: %w", err)
	}
	if err := json.Unmarshal(jsonBytes, &credMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal converted credential: %w", err)
	}
	return credMap, nil
}

// AppendProof attaches a proof to the document root, keeping any proof already
// there. Signing twice makes a proof SET, so the second signature must not
// replace the first - a document can be secured by several parties, and
// RootProofs verifies each of them.
func AppendProof(credMap map[string]any, proofConfig map[string]any) {
	existing, present := credMap["proof"]
	if !present {
		credMap["proof"] = proofConfig
		return
	}
	if proofs, isList := existing.([]any); isList {
		credMap["proof"] = append(proofs, proofConfig)
		return
	}
	credMap["proof"] = []any{existing, proofConfig}
}
