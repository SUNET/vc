package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

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
}

// NewRDFCredentialFromJSON parses a JSON-LD credential into an RDF dataset
func NewRDFCredentialFromJSON(jsonData []byte, options *ld.JsonLdOptions) (*RDFCredential, error) {
	processor := ld.NewJsonLdProcessor()

	if options == nil {
		options = ld.NewJsonLdOptions("")
		options.DocumentLoader = GetGlobalLoader()
	} else {
		if options.DocumentLoader == nil {
			options.DocumentLoader = GetGlobalLoader()
		} else if _, ok := options.DocumentLoader.(*ld.DefaultDocumentLoader); ok {
			options.DocumentLoader = GetGlobalLoader()
		}
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
			// Fallback: serialize dataset to N-Quads then normalize
			// We cannot pass *RDFDataset directly to Normalize or FromRDF as they expect serialized input

			serializer := &ld.NQuadRDFSerializer{}
			nquads, err := serializer.Serialize(rc.dataset)
			if err != nil {
				return "", fmt.Errorf("failed to serialize dataset to N-Quads: %w", err)
			}
			nquadsStr, ok := nquads.(string)
			if !ok {
				return "", fmt.Errorf("unexpected serialization result: %T", nquads)
			}

			processor := ld.NewJsonLdProcessor()
			opts := ld.NewJsonLdOptions("")
			opts.DocumentLoader = GetGlobalLoader()
			opts.Algorithm = ld.AlgorithmURDNA2015
			opts.Format = "application/n-quads"
			opts.InputFormat = "application/n-quads"

			normalized, err := processor.Normalize(nquadsStr, opts)
			if err != nil {
				return "", fmt.Errorf("failed to normalize N-Quads: %w", err)
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
	processor := ld.NewJsonLdProcessor()
	opts := ld.NewJsonLdOptions("")
	opts.DocumentLoader = GetGlobalLoader()
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.Format = "application/n-quads"

	normalized, err := processor.Normalize(jsonLdDoc, opts)
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

	// The document the holder signs has each embedded credential in its own graph (the
	// verifiableCredential term is an @graph container). json-gold leaves it in the default
	// graph, so every signer and verifier of a presentation has to put it there first, or the
	// canonical form - and with it the signature - differs from every other implementation's.
	// A no-op for a document without verifiableCredential links, and when already done.
	if err := rc.NormalizeVerifiableCredentialGraph(); err != nil {
		return nil, fmt.Errorf("placing embedded credentials in their graphs: %w", err)
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
	api := ld.NewJsonLdApi()
	opts := ld.NewJsonLdOptions("")
	opts.DocumentLoader = GetGlobalLoader()

	// Convert RDF dataset to JSON-LD using the API directly
	jsonLdDoc, err := api.FromRDF(filteredDataset, opts)
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

	// Convert RDF dataset back to JSON-LD
	// We must serialize to N-Quads first because FromRDF expects serialized input
	serializer := &ld.NQuadRDFSerializer{}
	nquads, err := serializer.Serialize(rc.dataset)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize dataset to N-Quads: %w", err)
	}
	nquadsStr, ok := nquads.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected serialization result: %T", nquads)
	}

	// Ensure options are set correctly
	opts := rc.options
	if opts == nil {
		opts = ld.NewJsonLdOptions("")
		opts.DocumentLoader = GetGlobalLoader()
	}
	// Set format to n-quads so FromRDF knows how to parse the input
	if opts.Format == "" {
		opts.Format = "application/n-quads"
	}

	jsonLd, err := rc.processor.FromRDF(nquadsStr, opts)
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

	// First get the expanded JSON-LD
	serializer := &ld.NQuadRDFSerializer{}
	nquads, err := serializer.Serialize(rc.dataset)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize dataset to N-Quads: %w", err)
	}
	nquadsStr, ok := nquads.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected serialization result: %T", nquads)
	}

	opts := rc.options
	if opts == nil {
		opts = ld.NewJsonLdOptions("")
		opts.DocumentLoader = GetGlobalLoader()
	}
	if opts.Format == "" {
		opts.Format = "application/n-quads"
	}

	expanded, err := rc.processor.FromRDF(nquadsStr, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to convert RDF to JSON-LD: %w", err)
	}

	// Fallback to W3C VC v2 context
	context := map[string]any{
		jsonLDContextKey: []any{
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

// Dataset returns the underlying RDF dataset
func (rc *RDFCredential) Dataset() *ld.RDFDataset {
	return rc.dataset
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
	return doc[jsonLDContextKey], nil
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

// NormalizeVerifiableCredentialGraph puts each embedded credential in its own named
// graph, where the verifiableCredential term's "@container": "@graph" says it belongs.
// json-gold does not apply that container, so without this the whole presentation lands
// in the default graph and the canonical form - and with it every signature over it -
// differs from what any other implementation computes.
//
// The placement is made in the JSON document, by wrapping each embedded credential in an
// explicit "@graph", and the dataset is rebuilt from that, so the processor draws the
// graph boundaries itself. Walking the flattened dataset instead cannot be made right:
// flattening has already merged descriptions, so two credentials that name the same
// issuer, or a credential whose subject the presentation also describes, share one set of
// quads with nothing left to say which graph each belongs to. Following them moved one
// credential's issuer into the other's graph, and could pull the presentation's own
// description of the holder in with it. Written as "@graph", a node described in two
// credentials is described in both graphs, which is what the document says.
//
// A no-op for a document with no verifiableCredential links - a bare credential comes
// out of it unchanged.
func (rc *RDFCredential) NormalizeVerifiableCredentialGraph() error {
	if rc.dataset == nil {
		return fmt.Errorf("RDF dataset is nil")
	}
	if rc.originalJSON == "" {
		// Nothing to rewrite: the graphs can only be read off the document, and this
		// credential was built from a dataset that has none.
		return nil
	}

	var doc any
	if err := json.Unmarshal([]byte(rc.originalJSON), &doc); err != nil {
		return fmt.Errorf("failed to unmarshal credential JSON: %w", err)
	}
	processor := rc.processor
	if processor == nil {
		processor = ld.NewJsonLdProcessor()
	}
	// Fresh options, not rc.options: a caller that set Format (N-Quads, say) would make
	// ToRDF hand back a serialized string instead of the dataset this needs.
	options := ld.NewJsonLdOptions("")
	options.DocumentLoader = GetGlobalLoader()
	if rc.options != nil {
		options.Base = rc.options.Base
		if rc.options.DocumentLoader != nil {
			if _, isDefault := rc.options.DocumentLoader.(*ld.DefaultDocumentLoader); !isDefault {
				options.DocumentLoader = rc.options.DocumentLoader
			}
		}
	}
	// Wrapping is done on the expanded document: there the term is its full IRI whatever
	// alias the document used, its container is already settled, and a JSON literal is a
	// plain @value this never looks inside.
	expanded, err := processor.Expand(doc, options)
	if err != nil {
		return fmt.Errorf("failed to expand the document: %w", err)
	}
	if !wrapEmbeddedCredentialsInGraphs(expanded) {
		return nil
	}
	rdfData, err := processor.ToRDF(expanded, options)
	if err != nil {
		return fmt.Errorf("failed to convert the rewritten document to RDF: %w", err)
	}
	dataset, ok := rdfData.(*ld.RDFDataset)
	if !ok {
		return fmt.Errorf("unexpected RDF data type: %T", rdfData)
	}
	rc.dataset = dataset
	return nil
}

// verifiableCredentialIRI is the verifiableCredential property in an expanded document.
const verifiableCredentialIRI = "https://www.w3.org/2018/credentials#verifiableCredential"

// wrapEmbeddedCredentialsInGraphs works on an expanded document and rewrites each node
// held under verifiableCredential into an explicit {"@graph": [<node>]}, reporting
// whether it changed anything. Left alone: a value already in a graph (a context whose
// container json-gold does apply, such as VC v1), a literal, and a bare node reference,
// which names a graph the document defines elsewhere - what CredentialWithoutProofForTypes
// produces through FromRDF. A literal's content, a JSON value included, is never entered.
func wrapEmbeddedCredentialsInGraphs(node any) bool {
	switch n := node.(type) {
	case map[string]any:
		return wrapInNode(n)
	case []any:
		return wrapInItems(n)
	}
	return false
}

// wrapInNode wraps the credentials held by one node object, and by everything below it.
func wrapInNode(n map[string]any) bool {
	if _, literal := n["@value"]; literal {
		return false
	}
	changed := false
	for key, child := range n {
		if key == verifiableCredentialIRI {
			if list, ok := child.([]any); ok {
				changed = wrapCredentialList(list) || changed
			}
		}
		changed = wrapEmbeddedCredentialsInGraphs(child) || changed
	}
	return changed
}

// wrapInItems wraps the credentials below each item of a list.
func wrapInItems(items []any) bool {
	changed := false
	for _, item := range items {
		changed = wrapEmbeddedCredentialsInGraphs(item) || changed
	}
	return changed
}

// wrapCredentialList wraps, in place, each node in a list of embedded credentials.
func wrapCredentialList(list []any) bool {
	changed := false
	for i, item := range list {
		cred, ok := item.(map[string]any)
		if !ok || !needsGraph(cred) {
			continue
		}
		list[i] = map[string]any{"@graph": []any{cred}}
		changed = true
	}
	return changed
}

// needsGraph reports whether a value under verifiableCredential is a credential not yet
// in a graph of its own.
func needsGraph(value map[string]any) bool {
	if _, inGraph := value["@graph"]; inGraph {
		return false
	}
	if _, literal := value["@value"]; literal {
		return false
	}
	return !isNodeReference(value)
}

// isNodeReference reports whether a node object says nothing but which node it is.
func isNodeReference(node map[string]any) bool {
	if _, hasID := node["@id"]; !hasID {
		return false
	}
	for key := range node {
		if key != "@id" && key != "@index" {
			return false
		}
	}
	return true
}
