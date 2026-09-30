package credential

import (
	"encoding/json"
	"fmt"

	"github.com/piprate/json-gold/ld"
)

// ProofPredicate is the expanded IRI of the link a document uses to attach a
// proof to itself. ProofPredicateLegacy is the VC 1.1-era spelling some
// documents still carry.
const (
	ProofPredicate       = "https://w3id.org/security#proof"
	ProofPredicateLegacy = "https://www.w3.org/2018/credentials#proof"
)

// RootProofs returns the proofs the document attaches to ITSELF, together
// with the document those proofs secure - which is the document with exactly
// those proofs removed, and every other proof left where it is.
//
// WHY THE ROOT IS READ FROM THE DOCUMENT AND NOT INFERRED FROM THE GRAPH.
// Sign attaches its proof to the top-level node, so that node IS the
// document being secured; anything else is inference about a question the
// document has already answered. Inferring it from the RDF reference graph
// cannot separate two shapes whose RDF is isomorphic - a presentation that
// links a credential through a custom property, and a credential whose
// subject is itself a credential linking back - and picking the wrong one
// lets a proof moved onto an embedded credential verify as the document's
// own.
//
// Read from the EXPANDED form rather than the JSON as written, because a
// compact document may alias the proof term ("sig" mapped to the proof IRI)
// and a document may arrive already expanded. Expansion resolves both, and
// leaves one node per top-level entry.
//
// WHY ONLY THE ROOT'S PROOFS ARE REMOVED. A proof secures the document it is
// attached to, so an embedded credential's issuer proof is CONTENT the
// presentation's signature covers and is deliberately left in place.
// Removing every proof in the graph - which is what this package used to do
// - meant that signature did not cover it at all, and the issuer proof
// could be swapped or stripped with the presentation still verifying.
//
// Proofs of the same node are all removed, which is what a proof SET
// requires: each of them secures the same unsecured document.
//
// A document with no single top-level node does not say what it is about,
// and is refused rather than guessed at.
func (rc *RDFCredential) RootProofs() (proofs []any, withoutRootProof *RDFCredential, err error) {
	root, nodes, graphs, err := rc.rootAndGraphs(rc.documentSource())
	if err != nil {
		return nil, nil, err
	}

	// The root's proofs, and the graphs they name. A proof written inline
	// carries its own @graph; one that survived a round trip through RDF is
	// a reference to a graph sitting beside the document, and removing the
	// link without removing the graph would leave the proof in the document
	// it is supposed to be absent from.
	claimed := map[string]bool{}
	for _, predicate := range []string{ProofPredicate, ProofPredicateLegacy} {
		attached, present := root[predicate]
		if !present {
			continue
		}
		for _, entry := range asList(attached) {
			node, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if _, inline := node["@graph"]; inline {
				proofs = append(proofs, node)
				continue
			}
			id, _ := node["@id"].(string)
			if graph, known := graphs[id]; known {
				proofs = append(proofs, graph)
				claimed[id] = true
				continue
			}
			// A link naming no graph in this document carries no proof.
			proofs = append(proofs, node)
		}
		delete(root, predicate)
	}

	kept := make([]any, 0, len(nodes)+len(graphs))
	for _, node := range nodes {
		kept = append(kept, node)
	}
	for id, graph := range graphs {
		if claimed[id] {
			continue
		}
		kept = append(kept, graph)
	}

	remaining, err := json.Marshal(kept)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize the document the proof secures: %w", err)
	}
	withoutRootProof, err = NewRDFCredentialFromJSON(remaining, rc.options)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to re-read the document the proof secures: %w", err)
	}

	return proofs, withoutRootProof, nil
}

// documentSource is the document as it was given to this credential, or as
// it serializes when there is no original.
func (rc *RDFCredential) documentSource() string {
	if rc.originalJSON != "" {
		return rc.originalJSON
	}
	marshalled, err := rc.MarshalJSON()
	if err != nil {
		return ""
	}
	return string(marshalled)
}

// rootAndGraphs expands a document and separates its root node, its other
// nodes, and the named graphs its proofs live in.
func (rc *RDFCredential) rootAndGraphs(source string) (map[string]any, []map[string]any, map[string]map[string]any, error) {
	if source == "" {
		return nil, nil, nil, fmt.Errorf("no document to read a root from")
	}

	var document any
	if err := json.Unmarshal([]byte(source), &document); err != nil {
		return nil, nil, nil, fmt.Errorf("document is not JSON: %w", err)
	}

	expanded, err := ld.NewJsonLdProcessor().Expand(document, NewJSONLDOptions(""))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("document could not be expanded: %w", err)
	}

	// A NAMED GRAPH is not a document node. Expanding the output of
	// MarshalJSON - which round-trips through N-Quads - lifts each proof
	// graph out to the top level beside the document, so "exactly one
	// top-level entry" is true of a compact document and false of the same
	// document re-read. The graphs are set aside, and one node has to
	// remain.
	graphs := map[string]map[string]any{}
	var nodes []map[string]any
	for _, entry := range expanded {
		node, ok := entry.(map[string]any)
		if !ok {
			return nil, nil, nil, fmt.Errorf("document holds a top-level entry that is not a node")
		}
		if _, isGraph := node["@graph"]; isGraph && len(node) <= 2 {
			id, _ := node["@id"].(string)
			graphs[id] = node
			continue
		}
		nodes = append(nodes, node)
	}

	root, err := rootOf(nodes)
	if err != nil {
		return nil, nil, nil, err
	}

	return root, nodes, graphs, nil
}

// CheckRootSurvivesFlattening refuses a document whose root can be read now
// and not after it has been through RDF.
//
// MarshalJSON round-trips through N-Quads, which FLATTENS: every node with
// properties of its own is lifted to the top level. A document whose root
// takes part in a reference cycle - a presentation carrying a credential
// whose subject links back at it - then has no top-level node that nothing
// else refers to, and RootProofs cannot say which node the document is
// about.
//
// Signing such a document would produce something this package verifies in
// one serialization and refuses in another. It is refused at signing
// instead, where the operator can still change it.
func (rc *RDFCredential) CheckRootSurvivesFlattening() error {
	marshalled, err := rc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("cannot tell whether this document keeps its root: %w", err)
	}
	if _, _, _, err := rc.rootAndGraphs(string(marshalled)); err != nil {
		return fmt.Errorf("this document does not say which node it is about once serialized through RDF, so it would verify in one form and not another: %w", err)
	}

	return nil
}

// rootOf picks the document node the others hang off.
//
// A compact document expands to exactly one top-level node, because its
// nesting IS the answer. A document that has been through RDF - MarshalJSON
// round-trips through N-Quads - comes back FLATTENED, with every node that
// has properties of its own lifted to the top level beside the document. The
// root is then the one nothing else refers to.
//
// More than one unreferenced node means the document does not say which of
// them it is about, and is refused rather than guessed at. That is also the
// shape a reference cycle between two candidates produces, which is the case
// no rule over predicates can decide.
func rootOf(nodes []map[string]any) (map[string]any, error) {
	if len(nodes) == 1 {
		return nodes[0], nil
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("document holds no node to read a proof from")
	}

	referenced := map[string]bool{}
	for _, node := range nodes {
		id, _ := node["@id"].(string)
		for _, value := range node {
			collectReferences(value, id, referenced)
		}
	}

	var roots []map[string]any
	for _, node := range nodes {
		id, _ := node["@id"].(string)
		if id == "" || !referenced[id] {
			roots = append(roots, node)
		}
	}
	if len(roots) != 1 {
		return nil, fmt.Errorf("document has %d top-level nodes nothing else refers to, so it does not say which one it is about", len(roots))
	}

	return roots[0], nil
}

// collectReferences records every @id one node mentions, other than its own.
func collectReferences(value any, self string, into map[string]bool) {
	switch typed := value.(type) {
	case map[string]any:
		if id, ok := typed["@id"].(string); ok && id != self {
			into[id] = true
		}
		for key, member := range typed {
			if key == "@id" {
				continue
			}
			collectReferences(member, self, into)
		}
	case []any:
		for _, member := range typed {
			collectReferences(member, self, into)
		}
	}
}

func asList(value any) []any {
	if list, ok := value.([]any); ok {
		return list
	}
	return []any{value}
}

// CompactRootProof turns one expanded root proof back into the short-keyed
// form the cryptosuites read.
//
// RootProofs returns proofs as they appear in the EXPANDED document, because
// that is the form in which aliases are already resolved. A proof attached
// through a graph container arrives wrapped in one, which is unwrapped here.
func CompactRootProof(expanded any) (map[string]any, error) {
	node, ok := expanded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("a root proof is not a node")
	}
	if graph, wrapped := node["@graph"]; wrapped {
		entries, isList := graph.([]any)
		if !isList || len(entries) != 1 {
			return nil, fmt.Errorf("a root proof names %T rather than one proof", graph)
		}
		node, ok = entries[0].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("a root proof's graph does not hold a node")
		}
	}

	context := map[string]any{"@context": ContextV2}
	compacted, err := ld.NewJsonLdProcessor().Compact(node, context, NewJSONLDOptions(""))
	if err != nil {
		return nil, fmt.Errorf("failed to compact a root proof: %w", err)
	}
	delete(compacted, "@context")

	return compacted, nil
}
