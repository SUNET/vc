package credential

import (
	"fmt"

	"github.com/piprate/json-gold/ld"
)

// RootCompactedDocument turns a compacted JSON-LD document that came back as a
// bare @graph container into one rooted at its own top-level node.
//
// Compacting a flattened dataset with several nodes yields
// {"@context": ..., "@graph": [node, node, node]} - a document that is ABOUT
// nothing. Hanging a proof on that container, which is what deriving a
// selectively-disclosed credential used to do, produces a document whose proof
// belongs to no node: root selection finds nothing to read a proof from, and
// the only way to locate the proof again is to walk the graph for one, which
// is the unqualified search this change exists to remove.
//
// The remaining nodes move to @included, which puts them in the SAME graph
// they were already in, so the RDF - and therefore any signature over it - is
// unchanged. Only the JSON nesting differs.
//
// A document with no single unreferenced node is REFUSED. It does not say
// which node it is about, and guessing is how a presentation and the
// credential it carries became indistinguishable in the first place.
func RootCompactedDocument(compacted map[string]any, knownRootID string, options *ld.JsonLdOptions) (map[string]any, error) {
	graph, isContainer := compacted["@graph"]
	if !isContainer {
		// A single node still has to BE the node the caller said the
		// document is about. Selective disclosure that drops every triple
		// of the credential leaves a document about something else
		// entirely - here, the credential's subject - and attaching the
		// credential's proof to that is how a proof comes to secure a
		// document nobody meant to sign.
		if knownRootID != "" && !isKnownRoot(compacted, compacted["@context"], knownRootID, options) {
			return nil, fmt.Errorf("the document no longer holds the node %q it is about", knownRootID)
		}
		return compacted, nil
	}

	entries, isList := graph.([]any)
	if !isList {
		return nil, fmt.Errorf("a document's @graph holds %T rather than a list of nodes", graph)
	}

	nodes := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		node, isNode := entry.(map[string]any)
		if !isNode {
			return nil, fmt.Errorf("a document's @graph holds %T rather than a node", entry)
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("a document's @graph holds no node to root it at")
	}

	rootIndex := -1

	// The caller usually KNOWS which node this is, because the document it
	// derived from said so. Selective disclosure can drop the very links the
	// rule below reads - reveal nothing about the credential's subject and
	// the subject node stops being referred to - so inferring the root from
	// what survived would let the disclosure choose what the document is
	// about.
	if knownRootID != "" {
		for i, node := range nodes {
			if isKnownRoot(node, compacted["@context"], knownRootID, options) {
				rootIndex = i
				break
			}
		}
		if rootIndex < 0 {
			return nil, fmt.Errorf("the document no longer holds the node %q it is about", knownRootID)
		}
	}

	if rootIndex < 0 {
		index, err := rootIndexOfCompactedNodes(nodes)
		if err != nil {
			return nil, err
		}
		rootIndex = index
	}

	root := nodes[rootIndex]
	included := make([]any, 0, len(nodes)-1)
	for i, node := range nodes {
		if i == rootIndex {
			continue
		}
		included = append(included, node)
	}

	rooted := map[string]any{}
	for key, value := range compacted {
		if key == "@graph" {
			continue
		}
		rooted[key] = value
	}
	_, containerHasContext := rooted["@context"]
	for key, value := range root {
		// The container's context wins - compaction puts it there, and two
		// contexts applied in the wrong order mean different terms. A
		// context on the root node is only kept when the container carries
		// none, so promoting the node cannot silently drop it.
		if key == "@context" && containerHasContext {
			continue
		}
		rooted[key] = value
	}
	if len(included) > 0 {
		rooted["@included"] = included
	}

	return rooted, nil
}

// compactNodeID reads a node's identifier under either spelling. A compacted
// document written against the v2 context aliases @id to id.
func compactNodeID(node map[string]any) string {
	if id, ok := node["@id"].(string); ok {
		return id
	}
	if id, ok := node["id"].(string); ok {
		return id
	}
	return ""
}

// referencedByAnyOther reports whether any node but the one at skip mentions
// id. A reference may be a nested object carrying that identifier OR a bare
// string, since a term declared "@type": "@id" - credentialSubject among them
// - compacts to the identifier itself.
func referencedByAnyOther(nodes []map[string]any, skip int, id string) bool {
	for i, node := range nodes {
		if i == skip {
			continue
		}
		if mentionsID(node, id, true) {
			return true
		}
	}
	return false
}

func mentionsID(value any, id string, atNodeRoot bool) bool {
	switch typed := value.(type) {
	case string:
		return typed == id
	case []any:
		for _, entry := range typed {
			if mentionsID(entry, id, false) {
				return true
			}
		}
	case map[string]any:
		// A LITERAL is not a reference, however much it looks like one. In
		// expanded JSON-LD a value object carries @value, and its contents
		// are a string the document says something with - not a node it
		// points at. Reading one as a reference marks the node it names as
		// referenced, and a document where some literal happens to equal the
		// root's identifier then has no unreferenced node left and is
		// refused outright.
		if _, isLiteral := typed["@value"]; isLiteral {
			return false
		}
		for key, member := range typed {
			// A node's OWN identifier is not a reference to itself.
			if atNodeRoot && (key == "@id" || key == "id") {
				continue
			}
			if mentionsID(member, id, false) {
				return true
			}
		}
	}
	return false
}

// RootOfCompactedNodes returns the node a flattened COMPACT document is about:
// the one nothing else in the list refers to.
//
// It is the compact-JSON counterpart of the rule RootProofs applies to an
// expanded document, and it has to be a separate implementation because a
// compacted document spells @id as id and a term declared "@type": "@id"
// compacts a reference down to a bare string.
//
// No single such node is a REFUSAL. A document that does not say which node it
// is about is one whose proof could be read as securing either.
func RootOfCompactedNodes(nodes []map[string]any) (map[string]any, error) {
	index, err := rootIndexOfCompactedNodes(nodes)
	if err != nil {
		return nil, err
	}
	return nodes[index], nil
}

func rootIndexOfCompactedNodes(nodes []map[string]any) (int, error) {
	if len(nodes) == 0 {
		return -1, fmt.Errorf("a document holds no node to be about")
	}

	rootIndex := -1
	for i, node := range nodes {
		id := compactNodeID(node)
		// A node with no identifier cannot be referred to, so it is a
		// candidate like any other unreferenced node.
		if id != "" && referencedByAnyOther(nodes, i, id) {
			continue
		}
		if rootIndex >= 0 {
			return -1, fmt.Errorf("a document holds more than one node nothing refers to, so it does not say which it is about")
		}
		rootIndex = i
	}
	if rootIndex < 0 {
		return -1, fmt.Errorf("every node in a document is referred to by another, so it says it is about none of them")
	}
	return rootIndex, nil
}

// isKnownRoot reports whether a node in a COMPACTED document is the node named
// by an ABSOLUTE identifier.
//
// The two spellings need not match literally. knownRootID is read off the
// expanded document, so it is always an absolute IRI; compaction rewrites a
// node's identifier under the document's context, which may turn it into a
// term or a compact IRI. Comparing the strings alone rejected a perfectly
// valid derivation purely because compaction changed the spelling of its root.
func isKnownRoot(node map[string]any, context any, knownRootID string, options *ld.JsonLdOptions) bool {
	id := compactNodeID(node)
	if id == "" {
		return false
	}
	if id == knownRootID {
		return true
	}
	return expandNodeID(context, id, options) == knownRootID
}

// expandNodeID resolves an identifier as written in a compacted document to
// the absolute IRI it stands for, or "" when it does not resolve to one.
//
// options are the ones the credential was parsed with; see ExpansionOptions.
//
// The identifier is expanded as the OBJECT of a property, because a node
// carrying nothing but an @id is free-floating and expansion drops it.
func expandNodeID(context any, id string, options *ld.JsonLdOptions) string {
	const probeIRI = "https://w3id.org/security#proof"

	probe := map[string]any{probeIRI: map[string]any{"@id": id}}
	if context != nil {
		probe["@context"] = context
	}

	// The options the document was PARSED with, so a context only its own
	// loader knows still resolves here. Expanding under fresh defaults
	// instead would fail to resolve it, the identifier would not normalize,
	// and a valid derivation would be refused as if its root had vanished.
	if options == nil {
		options = NewJSONLDOptions("")
	}
	expanded, err := ld.NewJsonLdProcessor().Expand(probe, options)
	if err != nil {
		return ""
	}

	if len(expanded) == 0 {
		return ""
	}
	node, isNode := expanded[0].(map[string]any)
	if !isNode {
		return ""
	}
	values, present := node[probeIRI].([]any)
	if !present || len(values) == 0 {
		return ""
	}
	value, isNode := values[0].(map[string]any)
	if !isNode {
		return ""
	}
	resolved, _ := value["@id"].(string)
	return resolved
}
