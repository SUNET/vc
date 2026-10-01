package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/piprate/json-gold/ld"
)

// RDFCredential represents a verifiable credential as an RDF dataset
// This avoids JSON marshaling issues and works directly with canonical RDF
type RDFCredential struct {
	// The RDF dataset representing this credential
	dataset *ld.RDFDataset
	// Original JSON for debugging
	originalJSON string
	// The processor used for RDF operations
	processor *ld.JsonLdProcessor
	options   *ld.JsonLdOptions

	// The secured-document answer, computed once. Reading the root's
	// proofs and canonicalizing the document they secure is the expensive
	// part of verification - JSON-LD expansion, flattening, RDF
	// serialization, URDNA2015 - and it is the SAME answer for every proof
	// in a set, because that is what a proof set means. A caller checking
	// several candidates would otherwise pay for it once per candidate, on
	// a document nobody has authenticated yet.
	// ONE mutex for all three. They are not independent: computing the
	// compacted proofs reads the secured-document answer, so separate
	// mutexes meant a reader could hold one while taking another, and an
	// invalidation clearing them one at a time could interleave with that -
	// leaving a cache repopulated from state the mutation had just voided.
	memoMu  sync.Mutex
	secured *securedDocumentAnswer

	// The same answer in the form every caller actually wants. Compacting
	// a root proof is a JSON-LD operation, and a verifier checking N
	// candidates compacted each of them N times - once per candidate, to
	// find the one it was asked about - so 32 proofs cost about a thousand
	// compactions before anything was authenticated.
	compactedProofs *compactedRootProofs

	// The root-scoped document and its canonical N-Quads, computed once.
	// ecdsa-sd-2023 needs the QUADS rather than a hash - it selects among
	// them by mandatory pointer - and recomputed the whole root-stability
	// check, proof removal and URDNA2015 run for every candidate proof in
	// a set. The secured-document memo above does not cover it, because
	// that one keeps a hash.
	rootScoped *rootScopedDocument
}

// rootScopedDocument holds only the canonical form, never the document it
// came from: see RootScopedCanonicalForm for why handing that out made the
// cache externally mutable.
type rootScopedDocument struct {
	canonical string
	err       error
}

type compactedRootProofs struct {
	proofs []map[string]any
	err    error
}

// securedDocumentAnswer is the memoized result, success or failure alike: a
// document that cannot be read is not worth re-reading.
type securedDocumentAnswer struct {
	proofs []any
	hash   [sha256.Size]byte
	err    error
}

// NewRDFCredentialFromJSON parses a JSON-LD credential into an RDF dataset
func NewRDFCredentialFromJSON(jsonData []byte, options *ld.JsonLdOptions) (*RDFCredential, error) {
	processor := ld.NewJsonLdProcessor()

	// A COPY, never the caller's struct: this function has no business
	// rewriting options its caller may still be using elsewhere.
	//
	// Format and InputFormat describe a call whose input or output is
	// N-Quads. This one's input is JSON, always. A caller reusing one option
	// set across both kinds of work left them set, and ToRDF then handed back
	// a serialized string instead of a dataset, or read the JSON as N-Quads -
	// so a credential that parses everywhere else failed to parse here.
	if options == nil {
		options = ld.NewJsonLdOptions("")
	} else {
		copied := *options
		options = &copied
	}
	options.Format = ""
	options.InputFormat = ""
	if _, isDefault := options.DocumentLoader.(*ld.DefaultDocumentLoader); options.DocumentLoader == nil || isDefault {
		options.DocumentLoader = GetGlobalLoader()
	}

	// Parse JSON to any
	var jsonLdDoc any
	if err := json.Unmarshal(jsonData, &jsonLdDoc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Convert JSON-LD to RDF dataset
	rdfData, err := processor.ToRDF(jsonLdDoc, options)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JSON-LD to RDF: %w", err)
	}

	// Type assert to RDFDataset
	dataset, ok := rdfData.(*ld.RDFDataset)
	if !ok {
		return nil, fmt.Errorf("unexpected RDF data type: %T", rdfData)
	}

	return &RDFCredential{
		dataset:      dataset,
		originalJSON: string(jsonData),
		processor:    processor,
		options:      options,
	}, nil
}

// refuseGeneralizedPredicates rejects a dataset carrying a blank node in
// PREDICATE position.
//
// URDNA2015 as json-gold implements it does not canonicalize one: it indexes
// and relabels only subjects, objects and graph names, and writes the
// predicate through unchanged. A parser-local label therefore survives into
// the "canonical" form, so two serializations of the same RDF can hash and
// sign differently - and a canonical form that is not canonical is worse than
// no answer, because every signature over it looks fine until someone
// re-serializes.
//
// Generalized RDF still round-trips through MarshalJSON and ToCompactJSON;
// what it cannot do is be signed or verified.
func refuseGeneralizedPredicates(dataset *ld.RDFDataset) error {
	for _, quads := range dataset.Graphs {
		for _, quad := range quads {
			if quad == nil || quad.Predicate == nil {
				continue
			}
			if ld.IsBlankNode(quad.Predicate) {
				return fmt.Errorf("this document uses a blank node as a predicate, and the canonicalization this library has does not canonicalize those - its label would be carried into the canonical form, so the same document could hash differently once re-serialized")
			}
		}
	}
	return nil
}

// canonicalizationOptions are the options this credential was PARSED with,
// set up to produce canonical N-Quads.
//
// Building fresh defaults here was a divergence of the same kind this package
// keeps finding: root selection, proof-key selection and proof-scope removal
// all re-expand under the credential's own options, while the canonical form
// the signature is actually computed over ignored them. A credential parsed
// with a custom document loader, an expandContext, a base or a processing mode
// was therefore READ one way and SIGNED another - and a verifier doing the
// same thing got a different document hash from the same bytes.
func (rc *RDFCredential) canonicalizationOptions() *ld.JsonLdOptions {
	opts := rc.expansionOptions()
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.Format = "application/n-quads"
	return opts
}

// CanonicalForm returns the canonical N-Quads representation
// This implements URDNA2015 normalization per W3C spec
func (rc *RDFCredential) CanonicalForm() (string, error) {
	if rc.originalJSON == "" {
		// If we don't have original JSON (e.g. created from dataset), we must use the dataset
		// But JsonLdProcessor.Normalize expects JSON-LD input unless InputFormat is set.
		// Since we have a dataset, we can use the lower-level API directly if possible,
		// or we have to convert dataset back to JSON-LD first (inefficient).
		// However, for now, let's assume we always have originalJSON or we can reconstruct it.
		if rc.dataset != nil {
			// The SAME route as below: straight to the normalization
			// algorithm. Serializing to N-Quads and parsing them back
			// dropped any quad with a blank node in predicate position,
			// which is not valid N-Quads however the dataset was built.
			//
			// On a CLONE, because normalization is not read-only: it writes
			// each quad's Graph field in place. Run against the credential's
			// own dataset it would rewrite the document while describing it,
			// two concurrent canonicalizations would race on those writes,
			// and a credential built by ProofObject - which shares its quads
			// with the one it came from - would rewrite that one's too.
			if err := refuseGeneralizedPredicates(rc.dataset); err != nil {
				return "", err
			}
			normalized, err := ld.NewJsonLdApi().Normalize(cloneDataset(rc.dataset), rc.canonicalizationOptions())
			if err != nil {
				return "", fmt.Errorf("failed to normalize dataset: %w", err)
			}
			normalizedStr, ok := normalized.(string)
			if !ok {
				return "", fmt.Errorf("unexpected normalized format: %T", normalized)
			}
			return normalizedStr, nil
		}
		return "", fmt.Errorf("original JSON is empty and dataset is nil")
	}

	// Parse the original JSON for normalization
	var jsonLdDoc any
	if err := json.Unmarshal([]byte(rc.originalJSON), &jsonLdDoc); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Use json-gold's Normalize function on the JSON-LD document
	// This performs URDNA2015 normalization and returns canonical N-Quads
	// TO RDF FIRST, under the credential's own options, and canonicalize that
	// DATASET - never a document or a string.
	//
	// Handing the JSON to JsonLdProcessor.Normalize instead loses most of
	// those options: json-gold builds FRESH options for its RDF step and
	// carries only the base, the processing mode and the document loader
	// across. The expandContext went, so a document that gets its terms from
	// one canonicalized to NOTHING - no error, no quads, and a signature over
	// the empty string, the same signature for every document of that shape.
	// So did ProduceGeneralizedRdf, so a credential parsed with it kept its
	// blank-node-predicate quads in the dataset and left them OUT of the
	// canonical form, where they could then be changed without invalidating
	// any signature.
	//
	// Serializing to N-Quads in between does not work either: a blank node in
	// predicate position is not valid N-Quads, and json-gold's parser refuses
	// it - so the round trip drops exactly the quads generalized RDF exists
	// for. The dataset goes straight to the normalization algorithm.
	rdf, err := ld.NewJsonLdProcessor().ToRDF(jsonLdDoc, rc.expansionOptions())
	if err != nil {
		return "", fmt.Errorf("failed to convert JSON-LD to RDF: %w", err)
	}
	dataset, isDataset := rdf.(*ld.RDFDataset)
	if !isDataset {
		return "", fmt.Errorf("unexpected RDF conversion result: %T", rdf)
	}

	if err := refuseGeneralizedPredicates(dataset); err != nil {
		return "", err
	}

	// No clone here: this dataset was just built by ToRDF above, is held by
	// nothing else, and is discarded after. The branch above has to clone
	// because the dataset there belongs to the credential.
	normalized, err := ld.NewJsonLdApi().Normalize(dataset, rc.canonicalizationOptions())
	if err != nil {
		return "", fmt.Errorf("failed to normalize JSON-LD: %w", err)
	}

	// Type assert the normalized result to string (N-Quads format)
	normalizedStr, ok := normalized.(string)
	if !ok {
		return "", fmt.Errorf("unexpected normalized format: %T", normalized)
	}

	return normalizedStr, nil
}

// CanonicalHash returns the SHA-256 hash of the canonical form
func (rc *RDFCredential) CanonicalHash() (string, error) {
	canonical, err := rc.CanonicalForm()
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(hash[:]), nil
}

// CredentialWithoutProof returns the credential as RDF without the proof object
// This is needed for signature verification
func (rc *RDFCredential) CredentialWithoutProof() (*RDFCredential, error) {
	return rc.CredentialWithoutProofForTypes()
}

// CredentialWithoutProofForTypes returns the credential as RDF without the proof object
// attached to nodes of the specified types. If no types are provided, all proofs are removed.
func (rc *RDFCredential) CredentialWithoutProofForTypes(targetTypes ...string) (*RDFCredential, error) {
	if rc.dataset == nil {
		return nil, fmt.Errorf("RDF dataset is nil")
	}

	// Map subject -> types
	subjectTypes := make(map[string][]string)
	for _, quads := range rc.dataset.Graphs {
		for _, quad := range quads {
			if quad.Predicate != nil && quad.Predicate.GetValue() == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" {
				if quad.Subject != nil && quad.Object != nil {
					sub := quad.Subject.GetValue()
					obj := quad.Object.GetValue()
					subjectTypes[sub] = append(subjectTypes[sub], obj)
				}
			}
		}
	}

	// Identify Proof Nodes to remove
	proofNodes := make(map[string]bool)
	// Identify Proof Links to remove (Subject -> Predicate -> Object)
	// We can't easily map quads, so we'll filter in the second pass based on logic.

	// Helper to check if a subject has one of the target types
	hasTargetType := func(subject string) bool {
		if len(targetTypes) == 0 {
			return true
		}
		types, ok := subjectTypes[subject]
		if !ok {
			return false
		}
		for _, t := range types {
			for _, target := range targetTypes {
				if t == target || strings.HasSuffix(t, target) {
					return true
				}
			}
		}
		return false
	}

	// Pass 1: Find proof nodes that should be removed
	for _, quads := range rc.dataset.Graphs {
		for _, quad := range quads {
			if quad.Predicate == nil {
				continue
			}
			pred := quad.Predicate.GetValue()

			// Check for link to proof
			if strings.Contains(pred, "https://w3id.org/security#proof") ||
				strings.Contains(pred, "http://www.w3.org/ns/credentials#proof") {

				if quad.Subject != nil {
					if hasTargetType(quad.Subject.GetValue()) {
						if quad.Object != nil {
							proofNodes[quad.Object.GetValue()] = true
						}
					}
				}
			}
		}
	}

	// Filter out proof quads from all graphs
	filteredGraphs := make(map[string][]*ld.Quad)

	for graphName, quads := range rc.dataset.Graphs {
		filteredQuads := make([]*ld.Quad, 0)

		for _, quad := range quads {
			// Skip quads that are part of the proof object

			// 1. Predicate is proof (link to proof)
			if quad.Predicate != nil && (strings.Contains(quad.Predicate.GetValue(), "https://w3id.org/security#proof") ||
				strings.Contains(quad.Predicate.GetValue(), "http://www.w3.org/ns/credentials#proof")) {

				if quad.Subject != nil && hasTargetType(quad.Subject.GetValue()) {
					continue
				}
			}

			// 2. Subject is a proof node (properties of proof)
			if quad.Subject != nil && proofNodes[quad.Subject.GetValue()] {
				continue
			}

			// 3. Graph is a proof node (proof in named graph)
			if quad.Graph != nil && proofNodes[quad.Graph.GetValue()] {
				continue
			}

			filteredQuads = append(filteredQuads, quad)
		}

		if len(filteredQuads) > 0 {
			filteredGraphs[graphName] = filteredQuads
		}
	}

	// Create filtered dataset
	filteredDataset := &ld.RDFDataset{
		Graphs: filteredGraphs,
	}

	// Convert filtered dataset back to JSON-LD for canonicalization
	// This is needed because directly serializing relative IRIs to N-Quads
	// produces invalid N-Quads (e.g., <UniversityDegreeCredential> without scheme)
	// The credential's OWN options, not fresh defaults: a private document
	// loader, an expandContext, a base or a processing mode all change what
	// this document says, and the result is what a signature is computed
	// over.
	jsonLdDoc, err := ld.NewJsonLdApi().FromRDF(filteredDataset, rc.expansionOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to convert filtered dataset to JSON-LD: %w", err)
	}

	// Serialize JSON-LD to string
	jsonBytes, err := json.Marshal(jsonLdDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize JSON-LD: %w", err)
	}

	// Create new credential without proof
	credWithoutProof := &RDFCredential{
		dataset: filteredDataset,
		// Store the JSON-LD representation for proper canonicalization
		originalJSON: string(jsonBytes),
		processor:    rc.processor,
		options:      rc.options,
	}

	return credWithoutProof, nil
}

// ProofObject extracts the proof object as separate RDF
func (rc *RDFCredential) ProofObject() (*RDFCredential, error) {
	if rc.dataset == nil {
		return nil, fmt.Errorf("RDF dataset is nil")
	}

	// Extract only proof quads from all graphs
	proofGraphs := make(map[string][]*ld.Quad)

	for graphName, quads := range rc.dataset.Graphs {
		proofQuads := make([]*ld.Quad, 0)

		for _, quad := range quads {
			if isProofQuad(quad) {
				proofQuads = append(proofQuads, quad)
			}
		}

		if len(proofQuads) > 0 {
			proofGraphs[graphName] = proofQuads
		}
	}

	if len(proofGraphs) == 0 {
		return nil, fmt.Errorf("no proof quads found")
	}

	proofRDF := &RDFCredential{
		dataset: &ld.RDFDataset{
			Graphs: proofGraphs,
		},
		// We don't have original JSON for the proof object
		originalJSON: "",
		processor:    rc.processor,
		options:      rc.options,
	}

	return proofRDF, nil
}

// isProofQuad checks if a quad is part of a proof object
// This is a heuristic based on common proof predicates
func isProofQuad(quad *ld.Quad) bool {
	if quad == nil {
		return false
	}

	// Check if the predicate indicates a proof property
	proofPredicates := []string{
		"http://www.w3.org/ns/credentials#proof",
		"https://w3id.org/security#proof",
		"https://www.w3.org/ns/credentials#proofValue",
		"https://w3id.org/security#proofValue",
		"https://www.w3.org/ns/credentials#cryptosuite",
		"https://w3id.org/security#cryptosuite",
		"https://www.w3.org/ns/credentials#verificationMethod",
		"https://w3id.org/security#verificationMethod",
		"https://www.w3.org/ns/credentials#proofPurpose",
		"https://w3id.org/security#proofPurpose",
		"https://www.w3.org/ns/credentials#created",
		"https://w3id.org/security#created",
		"http://purl.org/dc/terms/created",
		"https://w3id.org/security#challenge",
		"https://w3id.org/security#domain",
	}

	predicateValue := ""
	if quad.Predicate != nil {
		predicateValue = quad.Predicate.GetValue()
	}

	for _, pred := range proofPredicates {
		if strings.Contains(predicateValue, pred) {
			return true
		}
	}

	// Check if type is DataIntegrityProof
	objectValue := ""
	if quad.Object != nil {
		objectValue = quad.Object.GetValue()
	}

	if strings.Contains(predicateValue, "type") &&
		(strings.Contains(objectValue, "DataIntegrityProof") ||
			strings.Contains(objectValue, "Proof")) {
		return true
	}

	return false
}

// MarshalJSON implements json.Marshaler to convert the RDF credential back to JSON-LD
func (rc *RDFCredential) MarshalJSON() ([]byte, error) {
	if rc.dataset == nil {
		return nil, fmt.Errorf("RDF dataset is nil")
	}

	// STRAIGHT FROM THE DATASET, never through N-Quads.
	//
	// Serializing and re-parsing drops any quad with a blank node in
	// predicate position - that is not valid N-Quads however the dataset was
	// built, and json-gold's own parser refuses it. A credential parsed with
	// ProduceGeneralizedRdf could therefore be canonicalized but not
	// serialized, so CheckRootSurvivesFlattening - which reads the root off
	// this - refused it outright and the credential was neither signable nor
	// verifiable.
	//
	// It also drops the stale-options problem the old copy-and-set-Format
	// dance existed for: nothing here needs a Format at all.
	jsonLd, err := ld.NewJsonLdApi().FromRDF(rc.dataset, rc.expansionOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to convert RDF to JSON-LD: %w", err)
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(jsonLd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return jsonBytes, nil
}

// ToJSON is a helper that calls MarshalJSON
// Deprecated: Use json.Marshal instead
func (rc *RDFCredential) ToJSON() ([]byte, error) {
	return rc.MarshalJSON()
}

// ToCompactJSON returns the credential as compact JSON-LD using the original context.
// This is useful when you need to work with JSON pointers or preserve the original structure.
// If original JSON is available, it returns that directly (preserving the exact structure).
// Otherwise, it falls back to expanding and then compacting.
func (rc *RDFCredential) ToCompactJSON() ([]byte, error) {
	// If we have original JSON, return it directly - this preserves the exact structure
	// which is important for selective disclosure and JSON pointer operations
	if rc.originalJSON != "" {
		return []byte(rc.originalJSON), nil
	}

	if rc.dataset == nil {
		return nil, fmt.Errorf("RDF dataset is nil")
	}

	// Straight from the dataset, like MarshalJSON and CanonicalForm. Going
	// through N-Quads drops any quad with a blank node in predicate
	// position, which is not valid N-Quads however the dataset was built.
	//
	// And on the credential's OWN options rather than a copy, this used to
	// set Format on rc.options in place - so a credential that had once been
	// compacted parsed JSON as N-Quads ever after. expansionOptions returns
	// a copy with both format fields cleared, which is what this needs.
	expanded, err := ld.NewJsonLdApi().FromRDF(rc.dataset, rc.expansionOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to convert RDF to JSON-LD: %w", err)
	}

	// Fallback to W3C VC v2 context
	context := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/credentials/v2",
		},
	}

	// Compact the expanded JSON-LD
	compactOpts := ld.NewJsonLdOptions("")
	compactOpts.DocumentLoader = GetGlobalLoader()

	compacted, err := rc.processor.Compact(expanded, context, compactOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to compact JSON-LD: %w", err)
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(compacted)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal compact JSON: %w", err)
	}

	return jsonBytes, nil
}

// OriginalJSON returns the original JSON input
func (rc *RDFCredential) OriginalJSON() string {
	return rc.originalJSON
}

// Dataset returns a COPY of the credential's RDF dataset.
//
// Not the underlying one: mutating what this returns does not change the
// credential, which is a breaking change from the version that handed out the
// live dataset. The reason is below.
func (rc *RDFCredential) Dataset() *ld.RDFDataset {
	// Under memoMu, which guards the dataset against the in-place rewrite as
	// well as guarding the memos: cloning while NormalizeVerifiableCredentialGraph
	// rewrote the graphs would read a half-rewritten document.
	rc.memoMu.Lock()
	defer rc.memoMu.Unlock()

	// A COPY. The credential's own dataset never leaves this type.
	//
	// Invalidating the memos on the way out of here was not enough, and the
	// reason is worth keeping: a caller can hold the pointer, let a
	// verification repopulate the caches, and mutate afterwards - so the
	// cached proof set and document hash would then describe a document that
	// no longer exists, and the next verification would authenticate it
	// while skipping the root-stability check. Invalidating at hand-out time
	// cannot see that second mutation at all.
	//
	// The memos are only sound if nothing outside can change the document,
	// so nothing outside gets the chance.
	return cloneDataset(rc.dataset)
}

// cloneDataset deep-copies a dataset: new graph map, new quad slices, new
// quads, and the namespaces carried across.
//
// Through ld.NewRDFDataset rather than a struct literal. json-gold keeps its
// namespace map unexported and initializes it there, so a literal leaves it
// nil and the public SetNamespace panics on the copy - a method that works on
// every other dataset in the library.
func cloneDataset(dataset *ld.RDFDataset) *ld.RDFDataset {
	if dataset == nil {
		return nil
	}

	clone := ld.NewRDFDataset()
	for namespace, prefix := range dataset.GetNamespaces() {
		clone.SetNamespace(namespace, prefix)
	}

	graphs := make(map[string][]*ld.Quad, len(dataset.Graphs))
	for name, quads := range dataset.Graphs {
		copied := make([]*ld.Quad, 0, len(quads))
		for _, quad := range quads {
			if quad == nil {
				copied = append(copied, nil)
				continue
			}
			copied = append(copied, &ld.Quad{
				Subject:   cloneNode(quad.Subject),
				Predicate: cloneNode(quad.Predicate),
				Object:    cloneNode(quad.Object),
				Graph:     cloneNode(quad.Graph),
			})
		}
		graphs[name] = copied
	}

	clone.Graphs = graphs

	return clone
}

// cloneNode copies a node that is addressable through its interface. A node
// stored BY VALUE - which is what json-gold's constructors return - is already
// copied by the assignment, so only the pointer forms need this.
func cloneNode(node ld.Node) ld.Node {
	switch typed := node.(type) {
	case *ld.IRI:
		copied := *typed
		return &copied
	case *ld.BlankNode:
		copied := *typed
		return &copied
	case *ld.Literal:
		copied := *typed
		return &copied
	}
	return node
}

// invalidate clears every memoized answer. Each is a pure function of the
// document, so the only thing that can make one wrong is the document
// changing underneath it - and the memos exist precisely so that the
// expensive parts of verification run once, which is also what makes a stale
// one dangerous rather than merely slow.
func (rc *RDFCredential) invalidate() {
	// All three at once. Clearing them one at a time let a concurrent reader
	// repopulate one from another that had already been voided, so the
	// caches could end up describing two different documents.
	rc.memoMu.Lock()
	defer rc.memoMu.Unlock()

	rc.invalidateLocked()
}

// invalidateLocked clears the memos with memoMu already held, for a caller
// that must hold it across more than the clearing - the in-place dataset
// rewrite, which has to exclude readers for the whole mutation and not just
// at the end of it.
func (rc *RDFCredential) invalidateLocked() {
	rc.secured = nil
	rc.compactedProofs = nil
	rc.rootScoped = nil
}

// Context returns the @context from the original JSON
func (rc *RDFCredential) Context() (any, error) {
	if rc.originalJSON == "" {
		return nil, fmt.Errorf("original JSON not available")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(rc.originalJSON), &doc); err != nil {
		return nil, err
	}
	return doc["@context"], nil
}

// NQuads returns the N-Quads representation without normalization
// This preserves the blank node identifiers from the input
func (rc *RDFCredential) NQuads() (string, error) {
	if rc.dataset == nil {
		return "", fmt.Errorf("RDF dataset is nil")
	}

	serializer := &ld.NQuadRDFSerializer{}
	nquads, err := serializer.Serialize(rc.dataset)
	if err != nil {
		return "", fmt.Errorf("failed to serialize dataset to N-Quads: %w", err)
	}
	nquadsStr, ok := nquads.(string)
	if !ok {
		return "", fmt.Errorf("unexpected serialization result: %T", nquads)
	}
	return nquadsStr, nil
}

// NormalizeVerifiableCredentialGraph fixes an issue where json-gold puts VerifiableCredential
// in the default graph instead of a named graph when @context: null is used in the definition.
// This function moves the VC quads to a new named graph to match the expected structure.
func (rc *RDFCredential) NormalizeVerifiableCredentialGraph() error {
	// The lock is held for the WHOLE rewrite, not just the invalidation.
	//
	// Clearing the memos afterwards does not synchronize anything: a verifier
	// holding memoMu could be canonicalizing while this rewrote rc.dataset
	// underneath it - a data race, and one whose result is a hash taken over
	// a half-rewritten document. Excluding readers for the duration is the
	// only version of this that is safe, and the memos are cleared before the
	// lock is released so nobody sees the old answers against the new
	// dataset.
	//
	// Nothing in here calls a memoized accessor, so taking memoMu cannot
	// re-enter; invalidateLocked exists for exactly that reason.
	rc.memoMu.Lock()
	defer rc.memoMu.Unlock()
	defer rc.invalidateLocked()

	if rc.dataset == nil {
		return fmt.Errorf("RDF dataset is nil")
	}

	// Find verifiableCredential links in default graph
	defaultGraph, ok := rc.dataset.Graphs["@default"]
	if !ok {
		return nil
	}

	vcPredicate := "https://www.w3.org/2018/credentials#verifiableCredential"

	// Map of VC node -> new graph name
	vcMoves := make(map[string]string)

	// Identify VCs that need moving
	for _, quad := range defaultGraph {
		if quad.Predicate != nil && quad.Predicate.GetValue() == vcPredicate {
			if quad.Object != nil {
				obj := quad.Object.GetValue()
				// Check if object is a blank node (if it's an IRI, it might still be a graph name, but usually blank node)
				// If the object is a subject in the default graph, it means it's treated as a node, not a graph.
				if isSubjectInGraph(obj, defaultGraph) {
					// Generate new graph name
					// Strip _: prefix if present to avoid double prefix
					suffix := obj
					if strings.HasPrefix(obj, "_:") {
						suffix = obj[2:]
					}
					newGraphName := fmt.Sprintf("_:vc_graph_%s", suffix)
					vcMoves[obj] = newGraphName
				}
			}
		}
	}

	if len(vcMoves) == 0 {
		return nil
	}

	// Perform moves
	newDefaultGraph := make([]*ld.Quad, 0)
	newGraphs := make(map[string][]*ld.Quad)

	// Helper to check if a node should be moved to a specific graph
	// We need to move the VC node and its subgraph (excluding other named graphs)
	nodesToMove := make(map[string]string) // node -> targetGraph

	// Initialize with VC roots
	maps.Copy(nodesToMove, vcMoves)

	// Iteratively find all reachable nodes to move
	// This is a simplification: we assume VCs are trees rooted at the VC node
	// and don't share nodes with the VP or other VCs (except IRIs).
	// We only move blank nodes.
	changed := true
	for changed {
		changed = false
		for _, quad := range defaultGraph {
			if quad.Subject == nil {
				continue
			}
			sub := quad.Subject.GetValue()

			// If subject is marked for move
			if targetGraph, ok := nodesToMove[sub]; ok {
				// Check object
				if quad.Object != nil && strings.HasPrefix(quad.Object.GetValue(), "_:") {
					obj := quad.Object.GetValue()
					// If object is not already marked, mark it
					if _, exists := nodesToMove[obj]; !exists {
						nodesToMove[obj] = targetGraph
						changed = true
					}
				}
			}
		}
	}

	// Rebuild graphs
	for _, quad := range defaultGraph {
		// 1. Update VC link
		if quad.Predicate != nil && quad.Predicate.GetValue() == vcPredicate {
			if quad.Object != nil {
				obj := quad.Object.GetValue()
				if newGraph, ok := vcMoves[obj]; ok {
					// Update object to new graph name
					newQuad := &ld.Quad{
						Subject:   quad.Subject,
						Predicate: quad.Predicate,
						Object:    ld.NewBlankNode(newGraph),
						Graph:     quad.Graph,
					}
					newDefaultGraph = append(newDefaultGraph, newQuad)
					continue
				}
			}
		}

		// 2. Move quads
		if quad.Subject != nil {
			sub := quad.Subject.GetValue()
			if targetGraph, ok := nodesToMove[sub]; ok {
				// Move to new graph
				newQuad := &ld.Quad{
					Subject:   quad.Subject,
					Predicate: quad.Predicate,
					Object:    quad.Object,
					Graph:     ld.NewBlankNode(targetGraph),
				}
				// Add to new graph list
				newGraphs[targetGraph] = append(newGraphs[targetGraph], newQuad)
				continue
			}
		}

		// Keep in default graph
		newDefaultGraph = append(newDefaultGraph, quad)
	}

	// Update dataset
	rc.dataset.Graphs["@default"] = newDefaultGraph
	maps.Copy(rc.dataset.Graphs, newGraphs)

	return nil
}

func isSubjectInGraph(subject string, quads []*ld.Quad) bool {
	for _, q := range quads {
		if q.Subject != nil && q.Subject.GetValue() == subject {
			return true
		}
	}
	return false
}
