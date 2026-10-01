package credential

import (
	"fmt"
	"strings"

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
		index, err := rootIndexOfCompactedNodes(nodes, compacted["@context"], options)
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
func RootOfCompactedNodes(nodes []map[string]any, context any, options *ld.JsonLdOptions) (map[string]any, error) {
	index, err := rootIndexOfCompactedNodes(nodes, context, options)
	if err != nil {
		return nil, err
	}
	return nodes[index], nil
}

func rootIndexOfCompactedNodes(nodes []map[string]any, context any, options *ld.JsonLdOptions) (int, error) {
	if len(nodes) == 0 {
		return -1, fmt.Errorf("a document holds no node to be about")
	}

	// Which identifiers are REFERRED TO, decided on the expanded form where
	// a reference is an @id object and a literal is an @value one. In
	// compact JSON-LD the two are the same Go string: a term declared
	// "@type": "@id" writes a reference as a bare string, and so does any
	// ordinary string-valued property. Reading every string as a reference
	// marked a node referenced because some unrelated literal happened to
	// equal its identifier, and the document was then refused - or a
	// different node picked - for saying nothing of the kind.
	referenced, resolved := referencedIDs(nodes, context, options)

	rootIndex := -1
	for i, node := range nodes {
		id := compactNodeID(node)
		// A node with no identifier cannot be referred to, so it is a
		// candidate like any other unreferenced node.
		if id != "" && isReferenced(nodes, i, id, referenced, resolved) {
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

// ProofKeys returns the members of a node that name a Data Integrity proof
// under the given context.
//
// Matching raw spellings is not enough, and got it wrong twice over: the
// legacy predicate was written as https://www.w3.org/ns/credentials#proof,
// which is not a proof predicate at all, so a document using the real one
// kept its root proof - while RootProofs, which uses the constants, removed
// it. The two then disagreed about which quads a signature covers.
//
// A proof term may also be ALIASED. "proof" is only the name the v2 context
// happens to give it; a document may define its own, and a node written that
// way has a root proof that no list of spellings will find. Each member is
// resolved through the active context instead.
func ProofKeys(node map[string]any, context any, options *ld.JsonLdOptions) []string {
	var keys []string
	var unresolved []string

	for key := range node {
		if strings.HasPrefix(key, "@") {
			continue
		}
		// Already expanded, or the term the v2 context defines. The literal
		// "proof" stays a match even with no context to resolve it against:
		// failing to remove the root's own proof is the worse failure.
		if key == ProofPredicate || key == ProofPredicateLegacy || key == "proof" {
			keys = append(keys, key)
			continue
		}
		unresolved = append(unresolved, key)
	}

	if context == nil || len(unresolved) == 0 {
		return keys
	}

	// ONE expansion, not one per member. This runs on an SD credential
	// before its signature has been checked, so a document carrying many
	// arbitrary properties would otherwise turn a single request into a
	// context-processing operation per property.
	for _, key := range proofTerms(unresolved, context, options) {
		keys = append(keys, key)
	}
	return keys
}

// proofTerms resolves several member names against a context in one pass and
// returns those naming a proof.
//
// Each name is probed under a DISTINCT sentinel identifier, so the expanded
// output says which original name produced which predicate - several aliases
// of the same predicate would otherwise collapse into one entry.
func proofTerms(terms []string, context any, options *ld.JsonLdOptions) []string {
	const sentinelPrefix = "https://example.invalid/a-proof-node#"

	// Each term gets its OWN node, and a plain STRING for a value.
	//
	// Sharing one node means a term aliasing a keyword rewrites that node
	// instead of adding a member. Using {"@id": ...} as the value is worse:
	// a term aliased to @id - which is what every compact VC context does
	// with "id" - then carries an object where @id requires a string, and
	// json-gold rejects the WHOLE probe, so every other term's answer is
	// lost with it. A string is valid wherever it lands, and the sentinel
	// comes back under @value or @id depending on how the term is declared.
	entries := make([]any, 0, len(terms))
	bySentinel := make(map[string]string, len(terms))
	for i, term := range terms {
		sentinel := fmt.Sprintf("%s%d", sentinelPrefix, i)
		bySentinel[sentinel] = term
		entries = append(entries, map[string]any{term: sentinel})
	}
	probe := map[string]any{"@context": context, "@graph": entries}
	if options == nil {
		options = NewJSONLDOptions("")
	}

	expanded, err := ld.NewJsonLdProcessor().Expand(probe, options)
	if err != nil {
		return nil
	}

	var found []string
	collectProofTerms(expanded, bySentinel, &found)
	return found
}

// IsBareGraphContainer reports whether a map is nothing but a graph: the
// shape compacting a flattened dataset returns, which is ABOUT no node.
//
// A node may also carry @graph alongside properties of its own - that is a
// named graph, and the node is still the thing the document talks about.
// Treating one as a container reaches into its graph and removes a proof
// from there too, which is the opposite of root-scoped.
func IsBareGraphContainer(node map[string]any) bool {
	if _, present := node["@graph"]; !present {
		return false
	}
	for key := range node {
		if key != "@graph" && key != "@context" {
			return false
		}
	}
	return true
}

// referencedIDs collects the identifiers the document POINTS AT, by expanding
// it and reading the @id of every value object. resolved reports whether that
// expansion succeeded; when it did not - no context to resolve against, or one
// that will not load - the caller falls back to scanning strings, which is
// imprecise but never misses a reference.
func referencedIDs(nodes []map[string]any, context any, options *ld.JsonLdOptions) (map[string]bool, bool) {
	if context == nil {
		return nil, false
	}
	if options == nil {
		options = NewJSONLDOptions("")
	}

	entries := make([]any, 0, len(nodes))
	for _, node := range nodes {
		entries = append(entries, node)
	}
	document := map[string]any{"@context": context, "@graph": entries}

	expanded, err := ld.NewJsonLdProcessor().Expand(document, options)
	if err != nil {
		return nil, false
	}

	referenced := map[string]bool{}
	collectReferencedIDs(expanded, referenced, true)
	return referenced, true
}

// collectReferencedIDs walks expanded JSON-LD adding every @id that appears as
// a VALUE. A node's own @id is not a reference to itself, so the identifier at
// the top of each node is skipped.
func collectReferencedIDs(value any, into map[string]bool, atNodeRoot bool) {
	switch typed := value.(type) {
	case []any:
		for _, entry := range typed {
			collectReferencedIDs(entry, into, atNodeRoot)
		}
	case map[string]any:
		if _, isLiteral := typed["@value"]; isLiteral {
			return
		}
		if id, ok := typed["@id"].(string); ok && !atNodeRoot {
			into[id] = true
		}
		for key, member := range typed {
			if key == "@id" {
				continue
			}
			// Only the entries of @graph are nodes in their own right;
			// everything else below here is a value.
			collectReferencedIDs(member, into, key == "@graph")
		}
	}
}

// isReferenced answers from the expanded reading when there was one, and from
// the string scan otherwise.
func isReferenced(nodes []map[string]any, skip int, id string, referenced map[string]bool, resolved bool) bool {
	if resolved {
		return referenced[id]
	}
	return referencedByAnyOther(nodes, skip, id)
}

// collectProofTerms walks an expanded probe, adding the original member name
// behind every sentinel reached through a proof predicate.
func collectProofTerms(value any, bySentinel map[string]string, found *[]string) {
	switch typed := value.(type) {
	case []any:
		for _, entry := range typed {
			collectProofTerms(entry, bySentinel, found)
		}
	case map[string]any:
		for _, predicate := range []string{ProofPredicate, ProofPredicateLegacy} {
			values, present := typed[predicate].([]any)
			if !present {
				continue
			}
			for _, entry := range values {
				object, isObject := entry.(map[string]any)
				if !isObject {
					continue
				}
				// Under @id when the term is declared "@type": "@id",
				// under @value otherwise.
				marker, _ := object["@id"].(string)
				if marker == "" {
					marker, _ = object["@value"].(string)
				}
				if term, known := bySentinel[marker]; known {
					*found = append(*found, term)
				}
			}
		}
		for key, member := range typed {
			if key == ProofPredicate || key == ProofPredicateLegacy {
				continue
			}
			collectProofTerms(member, bySentinel, found)
		}
	}
}

// RootOfExpandedNodes returns the node an EXPANDED, flattened document is
// about, by the same rules rootAndGraphs applies before reading a root's
// proofs.
//
// Two of those rules are easy to lose by writing a fresh selector. A NAMED
// GRAPH is not a document node: round-tripping through N-Quads lifts each
// proof graph out to the top level beside the document, and counting those as
// candidates makes every document ambiguous. And a node's properties may be
// split across several top-level entries, which RDF conversion merges back
// into one node - treating them as separate candidates reported an ambiguous
// root for a document that reads perfectly well.
func RootOfExpandedNodes(expanded []any) (map[string]any, error) {
	var nodes []map[string]any
	for _, entry := range expanded {
		node, isNode := entry.(map[string]any)
		if !isNode {
			return nil, fmt.Errorf("document holds a top-level entry that is not a node")
		}
		if _, isGraph := node["@graph"]; isGraph && len(node) <= 2 {
			continue
		}
		nodes = append(nodes, node)
	}

	return rootOf(coalesceByID(nodes))
}
