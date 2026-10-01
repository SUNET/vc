package credential

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"

	"github.com/piprate/json-gold/ld"
)

// The steps every rdfc cryptosuite takes around its signature, which is the
// only part that differs between them. They lived once per suite, which is how
// eddsa and ecdsa came to disagree about which proofs a document secures
// without anybody noticing - the whole subject of this change. One copy means
// a scope fix cannot land in one suite and miss the other.

// MaxRootProofs bounds how many proofs a document may attach to itself before
// verification refuses it.
//
// The list is read off the document, so its length is chosen by whoever sent
// it, and trying one costs a JSON-LD canonicalization plus a signature check -
// work done before anything about the document has been authenticated. A real
// proof set is a handful of signers.
//
// Signing is capped too. The limit exists to bound work on untrusted input,
// and a signer is not that - but an uncapped Sign appends a 33rd proof,
// returns success, and hands back a document this same library then refuses
// before checking any signature. An API that produces output it cannot read
// is worse than one that says no.
const MaxRootProofs = 32

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

	existing, withoutRootProof, err := cred.RootProofs()
	if err != nil {
		return zero, fmt.Errorf("failed to get the document the proof secures: %w", err)
	}
	// The proof about to be added makes len(existing)+1.
	if len(existing) >= MaxRootProofs {
		return zero, fmt.Errorf("the document already attaches %d proofs to itself, and %d is the most this will verify", len(existing), MaxRootProofs)
	}

	return documentHash(withoutRootProof)
}

// SecuredDocumentHash returns the hash of the document the root's proofs
// secure. The proofs themselves come from CompactedRootProofs, which shares
// this answer.
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
func SecuredDocumentHash(cred *RDFCredential) ([32]byte, error) {
	answer, err := securedDocument(cred)
	if err != nil {
		return [32]byte{}, err
	}
	return answer.hash, nil
}

// securedDocument computes the answer once and keeps it.
//
// The expanded proofs stay INSIDE this package. They are mutable maps shared
// by every caller, and handing them out - even behind a fresh slice - meant a
// caller could poison the next verification or race a concurrent one, with
// nothing but a comment asking it not to. The compacted form is what callers
// want anyway, and CompactedRootProofs copies it.
func securedDocument(cred *RDFCredential) (*securedDocumentAnswer, error) {
	cred.memoMu.Lock()
	defer cred.memoMu.Unlock()

	return securedDocumentMemoized(cred)
}

// securedDocumentMemoized is securedDocument with the memo lock already held,
// so the compacted-proof answer can read it without taking a second mutex -
// which is what made the two orders of acquisition possible.
func securedDocumentMemoized(cred *RDFCredential) (*securedDocumentAnswer, error) {
	if cred.secured == nil {
		proofs, hash, err := securedDocumentOf(cred)
		cred.secured = &securedDocumentAnswer{proofs: proofs, hash: hash, err: err}
	}
	if cred.secured.err != nil {
		return nil, cred.secured.err
	}
	return cred.secured, nil
}

// CompactedRootProofs returns the document's own proofs in the short-keyed
// form callers read, computed once.
//
// A proof that will not compact is SKIPPED rather than fatal: every root proof
// is removed from the document a signature covers, so appending a malformed
// one does not disturb a genuine proof already there, and failing on it would
// let that append deny verification. The error is kept and returned only when
// nothing usable survives.
func CompactedRootProofs(cred *RDFCredential) ([]map[string]any, error) {
	cred.memoMu.Lock()
	defer cred.memoMu.Unlock()

	if cred.compactedProofs == nil {
		proofs, err := compactedRootProofsOf(cred)
		cred.compactedProofs = &compactedRootProofs{proofs: proofs, err: err}
	}
	if cred.compactedProofs.err != nil {
		return nil, cred.compactedProofs.err
	}

	// A COPY of each proof, not just of the slice. These are the cached
	// maps, this is an exported function, and "callers must not write to
	// what they are given" is not a guarantee - it is a hope. A compacted
	// proof is a small flat map, so copying one per call costs nothing
	// beside the JSON-LD compaction it saves.
	// DEEP copies. maps.Clone copies the top-level map and leaves every
	// slice and nested map shared - and a multi-typed proof already carries
	// a []any, so a caller writing through that slice reached the cache
	// anyway, which is the guarantee this is supposed to give.
	proofs := make([]map[string]any, 0, len(cred.compactedProofs.proofs))
	for _, proof := range cred.compactedProofs.proofs {
		copied, _ := deepCopy(proof).(map[string]any)
		proofs = append(proofs, copied)
	}
	return proofs, nil
}

func compactedRootProofsOf(cred *RDFCredential) ([]map[string]any, error) {
	answer, err := securedDocumentMemoized(cred)
	if err != nil {
		return nil, err
	}
	expanded := answer.proofs

	var compacted []map[string]any
	var unusable error
	for _, entry := range expanded {
		proof, err := CompactRootProof(entry)
		if err != nil {
			unusable = err
			continue
		}
		compacted = append(compacted, proof)
	}
	if len(compacted) == 0 {
		if unusable != nil {
			return nil, unusable
		}
		return nil, fmt.Errorf("the document carries no proof of its own to verify")
	}
	return compacted, nil
}

func securedDocumentOf(cred *RDFCredential) ([]any, [32]byte, error) {
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
	if len(proofs) > MaxRootProofs {
		return nil, zero, fmt.Errorf("the document attaches %d proofs to itself, more than the %d this will verify", len(proofs), MaxRootProofs)
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

// RootScopedDocument returns the document a proof secures - this document with
// the ROOT's own proofs removed and every nested proof left where it is -
// together with its canonical N-Quads. Computed ONCE per credential.
//
// Everything in it is a pure function of the document, and it is the SAME
// answer for every proof in a set, because that is what a proof set means.
// ecdsa-sd-2023 checked each candidate by recomputing the root-stability
// check, the proof removal and a full URDNA2015 run, so a 32-proof set paid
// for all of it 32 times - on a document nobody has authenticated yet, which
// is precisely where the proof cap exists to bound the work.
//
// The root-stability check comes first, for the reason the rdfc suites give:
// a document that names one root as written and another once serialized
// through RDF can be re-rooted by its holder, and removing the NEW root's
// proof then reproduces a different unsecured document than the signer meant
// to secure.
func RootScopedDocument(cred *RDFCredential) (*RDFCredential, string, error) {
	cred.memoMu.Lock()
	defer cred.memoMu.Unlock()

	if cred.rootScoped == nil {
		document, canonical, err := rootScopedDocumentOf(cred)
		cred.rootScoped = &rootScopedDocument{document: document, canonical: canonical, err: err}
	}
	if cred.rootScoped.err != nil {
		return nil, "", cred.rootScoped.err
	}
	return cred.rootScoped.document, cred.rootScoped.canonical, nil
}

func rootScopedDocumentOf(cred *RDFCredential) (*RDFCredential, string, error) {
	if err := cred.CheckRootSurvivesFlattening(); err != nil {
		return nil, "", err
	}

	_, withoutRootProof, err := cred.RootProofs()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get the document the proof secures: %w", err)
	}

	canonical, err := withoutRootProof.CanonicalForm()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get canonical form: %w", err)
	}

	return withoutRootProof, canonical, nil
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
	AppendProofUnder(credMap, proofConfig, "proof")
}

// AppendProofUnder attaches a proof under the member name the document uses
// for the proof predicate - see ProofKeyFor, which works it out.
func AppendProofUnder(credMap map[string]any, proofConfig map[string]any, key string) {
	// An explicit null is a term REMOVAL in JSON-LD, not a proof - and
	// neither is a list entry that is null. Keeping them produced
	// "proof": [null, {...}] in a signed document: it happened to verify,
	// because expansion drops the null, but it is not a document a stricter
	// verifier has to accept.
	existing, present := credMap[key]
	if !present || existing == nil {
		credMap[key] = proofConfig
		return
	}
	if proofs, isList := existing.([]any); isList {
		kept := make([]any, 0, len(proofs)+1)
		for _, entry := range proofs {
			if entry == nil {
				continue
			}
			kept = append(kept, entry)
		}
		credMap[key] = append(kept, proofConfig)
		return
	}
	credMap[key] = []any{existing, proofConfig}
}

// SameProof reports whether two proof objects are the SAME proof.
//
// Every member is compared but @context, which is a serialization detail: a
// proof as written carries the context Sign gave it, and the same proof read
// back through CompactRootProof has had it removed. Everything else - the
// verification method, the purpose, the created time, the cryptosuite, the
// signature - must match.
//
// Comparing proofValue alone is not enough and is the reason this exists. A
// forged proof that copies a genuine signature but changes its purpose or
// verification method is a DIFFERENT proof; answering for the genuine one
// would let a caller report the forged metadata as verified.
func SameProof(a map[string]any, b map[string]any) bool {
	if a == nil || b == nil {
		return false
	}
	return reflect.DeepEqual(withoutContext(a), withoutContext(b))
}

func withoutContext(proof map[string]any) map[string]any {
	if _, present := proof["@context"]; !present {
		return proof
	}
	stripped := maps.Clone(proof)
	delete(stripped, "@context")
	return stripped
}

// deepCopy copies the JSON-shaped value tree a decoded document is made of:
// maps, slices, and the scalars at the leaves, which are immutable.
func deepCopy(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		copied := make(map[string]any, len(typed))
		for key, member := range typed {
			copied[key] = deepCopy(member)
		}
		return copied
	case []any:
		copied := make([]any, len(typed))
		for i, member := range typed {
			copied[i] = deepCopy(member)
		}
		return copied
	default:
		return value
	}
}
