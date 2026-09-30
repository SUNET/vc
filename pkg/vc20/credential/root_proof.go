package credential

import (
	"encoding/json"
	"fmt"
	"strings"

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
	claimed := map[int]bool{}
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
			matches := graphsNamed(graphs, id)
			switch len(matches) {
			case 0:
				// A link naming no graph in this document carries no
				// proof; the caller will find it incomplete.
				proofs = append(proofs, node)
			case 1:
				proofs = append(proofs, graphs[matches[0]])
				claimed[matches[0]] = true
			default:
				// One graph name written across several entries. RDF
				// merges them, so which of them the proof is cannot be
				// answered here - and removing only one would leave part
				// of the proof in the document it secures.
				return nil, nil, fmt.Errorf("the document names %d separate graphs %q, so its proof cannot be told from what was added beside it", len(matches), id)
			}
		}
		delete(root, predicate)
	}

	kept := make([]any, 0, len(nodes)+len(graphs))
	for _, node := range nodes {
		kept = append(kept, node)
	}
	for i, graph := range graphs {
		if claimed[i] {
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
func (rc *RDFCredential) rootAndGraphs(source string) (map[string]any, []map[string]any, []map[string]any, error) {
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
	// A SLICE, not a map keyed by @id. Two top-level entries may carry the
	// same graph name - JSON-LD expansion keeps both and RDF conversion
	// merges their triples - and every entry without an @id would share the
	// empty key. Keeping one per id silently dropped the rest from the
	// document the signature covers, while the verifier's parsed RDF still
	// held them: an attacker could add triples under an embedded proof
	// graph's name and have them survive parsing but not hashing.
	var graphs, nodes []map[string]any
	for _, entry := range expanded {
		node, ok := entry.(map[string]any)
		if !ok {
			return nil, nil, nil, fmt.Errorf("document holds a top-level entry that is not a node")
		}
		if _, isGraph := node["@graph"]; isGraph && len(node) <= 2 {
			graphs = append(graphs, node)
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

// CheckRootSurvivesFlattening refuses a document whose root changes, or
// stops being readable, once it has been through RDF.
//
// MarshalJSON round-trips through N-Quads, which FLATTENS: every node with
// properties of its own is lifted to the top level. Two things can go wrong
// there, and both produce a document this package would treat differently
// in two serializations of the same RDF.
//
// The root can VANISH. A root taking part in a reference cycle - a
// presentation carrying a credential whose subject links back at it - then
// has no top-level node that nothing else refers to.
//
// The root can MOVE, which is worse. A disconnected node reachable only
// through @included, pointing at the real root, is referenced by nothing
// once flattened while the real root is referenced by it - so the flattened
// form names the attacker's node as the document. Moving the root's proof
// onto that node would then verify as its own, since the same proof is
// removed from the same RDF either way. Identity is therefore compared, not
// merely existence.
//
// A root named by a BLANK NODE, or by nothing at all, cannot be compared
// lexically: blank-node labels are serialization-local, and ToRDF relabels
// "_:root" to whatever its identifier issuer produces. Such a root is
// required instead to be referenced by nothing in the document as written -
// and then it is unreferenced in the flattened form too, where rootOf
// refuses as soon as a second unreferenced node appears, so it cannot have
// moved.
//
// Signing such a document would produce something this package verifies in
// one serialization and refuses - or worse, verifies differently - in
// another. It is refused at signing instead, where the operator can still
// change it.
func (rc *RDFCredential) CheckRootSurvivesFlattening() error {
	compactRoot, compactNodes, compactGraphs, err := rc.rootAndGraphs(rc.documentSource())
	if err != nil {
		return err
	}

	marshalled, err := rc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("cannot tell whether this document keeps its root: %w", err)
	}
	flatRoot, _, _, err := rc.rootAndGraphs(string(marshalled))
	if err != nil {
		return fmt.Errorf("this document does not say which node it is about once serialized through RDF, so it would verify in one form and not another: %w", err)
	}

	compactID, _ := compactRoot["@id"].(string)
	flatID, _ := flatRoot["@id"].(string)

	if isBlankOrAbsent(compactID) || isBlankOrAbsent(flatID) {
		// Nothing to compare. Require instead that nothing in the document
		// refers to the root, which is what makes it the unreferenced node
		// in the flattened form as well.
		if referencedAnywhere([][]map[string]any{compactNodes, compactGraphs}, compactID) {
			return fmt.Errorf("this document is about a node nothing can name across serializations, and something in it refers to that node, so which node it is about would be decided differently once serialized through RDF")
		}
		return nil
	}

	if compactID != flatID {
		return fmt.Errorf("this document is about %q as written and %q once serialized through RDF, so a proof on one would be read as the other's", compactID, flatID)
	}

	return nil
}

// isBlankOrAbsent reports whether an @id cannot be compared between two
// serializations of the same RDF.
func isBlankOrAbsent(id string) bool {
	return id == "" || strings.HasPrefix(id, "_:")
}

// referencedAnywhere reports whether anything in the document points at this
// node.
//
// The whole document, not only its top-level entries: a node reachable
// through @included sits inside the root's own subtree while compact and
// beside it once flattened, and a reference from there is exactly what makes
// the root stop being the unreferenced node.
//
// In expanded JSON-LD a reference is a map holding nothing but "@id", which
// is what separates it from the node's own definition.
func referencedAnywhere(entries [][]map[string]any, id string) bool {
	if id == "" {
		return false
	}
	found := false
	var walk func(any)
	walk = func(value any) {
		if found {
			return
		}
		switch typed := value.(type) {
		case map[string]any:
			if len(typed) == 1 {
				if at, ok := typed["@id"].(string); ok && at == id {
					found = true
					return
				}
			}
			for _, member := range typed {
				walk(member)
			}
		case []any:
			for _, member := range typed {
				walk(member)
			}
		}
	}
	for _, group := range entries {
		for _, entry := range group {
			walk(entry)
		}
	}
	return found
}

// graphsNamed returns the indices of every top-level graph entry carrying
// this name. More than one is a collision the caller has to refuse: RDF
// merges them into one graph, so there is no "the" entry to remove.
func graphsNamed(graphs []map[string]any, id string) []int {
	if id == "" {
		return nil
	}
	var matches []int
	for i, graph := range graphs {
		if name, _ := graph["@id"].(string); name == id {
			matches = append(matches, i)
		}
	}
	return matches
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
