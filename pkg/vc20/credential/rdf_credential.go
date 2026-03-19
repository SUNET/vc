package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
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
