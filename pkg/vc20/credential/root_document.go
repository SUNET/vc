package credential

import (
	"encoding/json"
	"fmt"
	"maps"
	"sort"
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
	// A BARE container, by ld.IsGraph's rule and this package's own: a node
	// carrying @graph beside its own id and properties is a named-graph
	// NODE, and the document is about it. Treating one as a container sent
	// root selection inside its graph and refused a perfectly good
	// credential, or rooted it at the wrong node.
	graph, isContainer := compacted["@graph"]
	if isContainer && !IsBareGraphContainer(compacted) {
		isContainer = false
	}
	if !isContainer {
		// A single node still has to BE the node the caller said the
		// document is about. Selective disclosure that drops every triple
		// of the credential leaves a document about something else
		// entirely - here, the credential's subject - and attaching the
		// credential's proof to that is how a proof comes to secure a
		// document nobody meant to sign.
		// No container here: the document IS the node, so its @context is
		// the node's OWN. Passing it as a container context too composed it
		// with itself.
		if knownRootID != "" && !isKnownRoot(compacted, nil, knownRootID, options) {
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

	// Fragments of ONE node merged before anything is selected. Flattening
	// may split a node across several @graph entries, and reading each as a
	// node of its own left two entries carrying the same identifier, neither
	// referring to the other - so a perfectly unambiguous document was
	// refused for holding "more than one node nothing refers to". The merge
	// is on clones, and the promoted root is the merged node, so it carries
	// every property the document gave it rather than whichever fragment
	// came first. RootOfCompactedNodes has always done this; this path had
	// not.
	nodes = coalesceCompactedByID(nodes, compacted["@context"], options)

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
	included := make([]map[string]any, 0, len(nodes)-1)
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
	containerContext, containerHasContext := rooted["@context"]
	for key, value := range root {
		// BOTH contexts, in the order JSON-LD applies them: the container's
		// first, then the node's own. Keeping only the container's dropped
		// definitions the root actually uses, which changes or removes
		// triples - in a helper whose whole promise is that the graph, and
		// so the signature over it, is unchanged.
		if key == "@context" {
			switch {
			case !containerHasContext:
				rooted["@context"] = value
			case value == nil:
				// An explicit null is a RESET. Treating it as an absent
				// context left the promoted node inheriting the
				// container's definitions, which it did not have - more
				// triples than the document carried, from a helper whose
				// promise is that the graph is unchanged. The null stays
				// in the sequence, where it clears what came before it.
				rooted["@context"] = []any{containerContext, nil}
			default:
				rooted["@context"] = JoinContexts(containerContext, value)
			}
			continue
		}
		rooted[key] = value
	}
	// APPENDED to whatever the root already included. Replacing it dropped
	// those nodes from the document - and they are in the same graph, so
	// dropping them removes their triples from the dataset this is supposed
	// to carry through unchanged.
	attach := func(entries []map[string]any) map[string]any {
		if len(entries) == 0 {
			return rooted
		}
		document := maps.Clone(rooted)
		combined := make([]any, 0, len(entries)+1)
		// Only when the root HAS one: asList of an absent member yields a
		// list holding nil, and a nil entry in @included is not a node.
		if existing, present := rooted["@included"]; present {
			combined = append(combined, asList(existing)...)
		}
		for _, entry := range entries {
			combined = append(combined, entry)
		}
		document["@included"] = combined
		return document
	}

	// Moving a sibling UNDER the promoted root puts it inside that root's own
	// local context, which it never had: inside @graph every node saw the
	// container's context alone. If the root redefines a term a sibling uses,
	// that sibling's expanded IRIs change, and with them the RDF and any
	// signature over it - in a helper whose whole promise is that the dataset
	// is unchanged.
	//
	// So restore each moved sibling's scope, and PROVE the dataset came
	// through rather than assume it. The restoration is a context reset,
	// which JSON-LD refuses over protected terms, so the unscoped form is
	// tried second - and a document neither form carries through is REFUSED,
	// not rooted silently into a different graph.
	//
	// The proof runs WHENEVER nodes move, not only when the root has a
	// context of its own. Scoping is one way this rewrite can change the
	// dataset and there is no list of the others: merging fragments that
	// carry different local contexts is a second, the processing mode is a
	// third. Deciding by inspection which documents need checking is the
	// assumption-that-coincides this whole change exists to remove.
	if len(included) == 0 {
		return attach(included), nil
	}

	// @included is a JSON-LD 1.1 keyword, and 1.1 ONLY: a 1.0 processor
	// treats it as an unknown term and skips it, so the siblings - and every
	// triple they carry - vanish from the document. The hash would then be
	// taken over less than the document says, and a verifier reading the
	// same bytes under 1.1 defaults would see those triples reappear.
	if options != nil && options.ProcessingMode == ld.JsonLd_1_0 {
		return nil, fmt.Errorf("a document of %d nodes cannot be rooted under JSON-LD 1.0, which ignores @included and would drop the %d node(s) beside the root", len(nodes), len(included))
	}

	want, err := canonicalFormOf(compacted, options)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize the document being rooted: %w", err)
	}

	candidates := [][]map[string]any{included}
	if _, rootHasOwnContext := root["@context"]; rootHasOwnContext {
		scoped := make([]map[string]any, 0, len(included))
		for _, node := range included {
			scoped = append(scoped, scopedToContainer(node, containerContext, containerHasContext))
		}
		// Preferred: it is the scope the siblings actually had.
		candidates = [][]map[string]any{scoped, included}
	}

	for _, entries := range candidates {
		candidate := attach(entries)
		got, err := canonicalFormOf(candidate, options)
		if err == nil && got == want {
			return candidate, nil
		}
	}

	// Deliberately not naming a cause. The check is what decides, and it
	// covers more than the scoping it was written for - a cause in the
	// message would be a guess that reads as a finding.
	return nil, fmt.Errorf("rooting the document at %q would change its RDF: the %d node(s) beside it in @graph do not survive being moved under it unchanged", compactNodeID(root), len(included))
}

// RootedCredential returns cred with its document rooted at the node the
// document is about, re-read so every later step sees the same shape.
//
// A document that came back from flattening as a bare @graph container is
// ABOUT nothing, and every signing path read it two ways at once: root-scoped
// hashing selected the node INSIDE the container, while the proof was appended
// to the container itself. The proof then belonged to a wrapper rather than to
// the credential that was hashed - and under the v2 type-scoped context, where
// `proof` is defined on credential types, it expanded away entirely. Sign
// returned success and handed back a document this same library refuses.
//
// Rooting at the TOP of Sign rather than just before the append is what makes
// the two readings one. ecdsa-sd-2023 also selects its mandatory statements by
// JSON pointer, so a pointer like /issuer must address the same member the
// hash covers; rooting late left those pointers resolving against the
// container at signing time and against the credential at verification time.
func RootedCredential(cred *RDFCredential) (*RDFCredential, error) {
	document, err := DocumentAsMap(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to read the credential as a document: %w", err)
	}
	if !IsBareGraphContainer(document) {
		return cred, nil
	}

	rootID, err := cred.RootID()
	if err != nil {
		return nil, fmt.Errorf("failed to read the node the credential is about: %w", err)
	}

	rooted, err := RootCompactedDocument(document, rootID, cred.ExpansionOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to root the credential: %w", err)
	}

	encoded, err := json.Marshal(rooted)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the rooted credential: %w", err)
	}

	return NewRDFCredentialFromJSON(encoded, cred.ExpansionOptions())
}

// scopedToContainer gives a node the context scope it had as a @graph entry:
// the container's context and its own, and NOTHING of the node it is being
// moved inside. The leading null is what clears that node's definitions.
func scopedToContainer(node map[string]any, containerContext any, containerHasContext bool) map[string]any {
	scoped := maps.Clone(node)

	sequence := []any{nil}
	if containerHasContext {
		sequence = append(sequence, asList(containerContext)...)
	}
	// An explicit null of its own is a reset the node ASKED for; it stays in
	// the sequence, after the container's, where it clears what came before.
	if own, present := node["@context"]; present {
		sequence = append(sequence, asList(own)...)
	}
	scoped["@context"] = sequence

	return scoped
}

// canonicalFormOf runs a compacted document through the same pipeline a
// signature does - expansion, flattening, RDF, URDNA2015 - so two documents
// can be compared by the only thing a proof covers.
func canonicalFormOf(document map[string]any, options *ld.JsonLdOptions) (string, error) {
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("failed to marshal the document: %w", err)
	}

	cred, err := NewRDFCredentialFromJSON(encoded, options)
	if err != nil {
		return "", fmt.Errorf("failed to read the document as RDF: %w", err)
	}

	return cred.CanonicalForm()
}

// composedContext returns the context a @graph ENTRY is read under: the
// container's, then the entry's own. Nothing else - the node it may later be
// moved inside does not reach it.
//
// Reading an entry under the container's context alone was enough to lose it:
// a node declaring its own prefix and using it in its identifier resolved to
// the compact spelling, matched no known root, and all three signing paths
// rejected the document as though its root had disappeared.
func composedContext(node map[string]any, containerContext any, containerHasContext bool) any {
	own, present := node["@context"]
	switch {
	case !present:
		return containerContext
	case !containerHasContext:
		return own
	case own == nil:
		// An explicit null is a RESET the node asked for. It stays in the
		// sequence, after the container's, where it clears what came before.
		return []any{containerContext, nil}
	default:
		return JoinContexts(containerContext, own)
	}
}

// nodeIDUnder reads a node's identifier, resolving ANY alias of @id the active
// context defines.
//
// JSON-LD lets a context alias @id to any term, so hard-coding the spellings
// @id and id read no identifier at all from a document using one - RootID,
// which works on the EXPANDED form, found it, and root matching here did not,
// so signing failed on a document that parses perfectly well.
//
// Keys are taken in order, so a document defining two aliases gets one answer
// rather than whichever the map iteration happened to yield.
func nodeIDUnder(node map[string]any, context any, options *ld.JsonLdOptions) string {
	if id := compactNodeID(node); id != "" {
		return id
	}

	active := nodeContext(node, context, options)
	if active == nil {
		return ""
	}

	keys := make([]string, 0, len(node))
	for key := range node {
		if !strings.HasPrefix(key, "@") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	for _, key := range keys {
		text, isText := node[key].(string)
		if !isText {
			continue
		}
		if resolved, unresolvable := expandMemberName(active, key); !unresolvable && resolved == "@id" {
			return text
		}
	}
	return ""
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
	// COALESCED first. Expanded JSON-LD may split one node's properties
	// across several top-level entries, which RDF conversion merges back
	// into one - RootProofs has always coalesced before selecting, and not
	// doing it here rejected the same document as having several roots.
	merged := coalesceCompactedByID(nodes, context, options)

	index, err := rootIndexOfCompactedNodes(merged, context, options)
	if err != nil {
		return nil, err
	}
	return merged[index], nil
}

// CompactNodeID returns a node's identifier as the document writes it, so a
// caller holding the original entries can find every fragment of the node
// RootOfCompactedNodes selected.
//
// It takes the context because selection does: JSON-LD lets a context alias
// @id to any term, and reading only the spellings @id and id returned "" for
// every node of a document using one. A caller comparing those answers then
// found every node equal to the root - and in SD proof removal that deleted
// the embedded credentials' proofs along with the root's, which is the exact
// failure this change exists to remove.
func CompactNodeID(node map[string]any, context any, options *ld.JsonLdOptions) string {
	return nodeIDUnder(node, composedContext(node, context, context != nil), options)
}

// coalesceCompactedByID merges entries sharing an identifier, on COPIES - the
// caller's document is not ours to rewrite.
func coalesceCompactedByID(nodes []map[string]any, context any, options *ld.JsonLdOptions) []map[string]any {
	merged := make([]map[string]any, 0, len(nodes))
	at := map[string]int{}

	for _, node := range nodes {
		// Read under the node's own scope and through any alias of @id, or
		// fragments of one node spelled through a context go on looking like
		// separate nodes - which is the refusal this merge exists to avoid.
		id := nodeIDUnder(node, composedContext(node, context, context != nil), options)
		if id == "" {
			merged = append(merged, maps.Clone(node))
			continue
		}
		index, seen := at[id]
		if !seen {
			at[id] = len(merged)
			merged = append(merged, maps.Clone(node))
			continue
		}
		into := merged[index]
		for key, value := range node {
			if key == "@id" || key == "id" {
				continue
			}
			existing, present := into[key]
			if !present {
				into[key] = value
				continue
			}
			into[key] = append(asList(existing), asList(value)...)
		}
	}
	return merged
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
	referencedBy, resolved := referencedIDs(nodes, context, options)

	// The ids to LOOK UP with. After expansion the referenced set holds
	// absolute IRIs, while a node's own id is still spelled as the document
	// writes it - so a compact id never matched, every node looked
	// unreferenced, and a perfectly good document read as ambiguous.
	// Each node read under the context it ACTUALLY has - the container's and
	// its own - and through any alias of @id that context defines.
	scopes := make([]any, len(nodes))
	lookup := make([]string, len(nodes))
	shared := make([]string, len(nodes))
	ownContext := make([]bool, len(nodes))
	for i, node := range nodes {
		_, ownContext[i] = node["@context"]
		scopes[i] = composedContext(node, context, context != nil)
		lookup[i] = nodeIDUnder(node, scopes[i], options)
		if !ownContext[i] {
			shared[i] = lookup[i]
		}
	}
	if resolved {
		// Batched for the nodes that share the container's context, which is
		// almost all of them; one carrying a context of its own is expanded
		// on its own, because a batch can only apply ONE context.
		shared = expandNodeIDs(shared, context, options)
		for i := range nodes {
			if !ownContext[i] {
				lookup[i] = shared[i]
				continue
			}
			if expanded := expandNodeID(scopes[i], lookup[i], options); expanded != "" {
				lookup[i] = expanded
			}
		}
	}

	rootIndex := -1
	for i := range nodes {
		// A node with no identifier cannot be referred to, so it is a
		// candidate like any other unreferenced node.
		if lookup[i] != "" && isReferenced(nodes, i, lookup[i], referencedBy, resolved) {
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
	// The context the node is actually READ under - the container's and its
	// own. A @graph entry may declare its own prefix and use it in its
	// identifier; resolving that against the container's context alone left
	// the compact spelling, which matches no absolute IRI, and the document
	// was rejected as though its root had disappeared.
	scoped := composedContext(node, context, context != nil)

	id := nodeIDUnder(node, scoped, options)
	if id == "" {
		return false
	}
	if id == knownRootID {
		return true
	}
	return expandNodeID(scoped, id, options) == knownRootID
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
	// The context parsed ONCE, and every member EXPANDED through it the way
	// JSON-LD would - which is not the same as looking the term up. A
	// context declaring @vocab and no explicit "proof" expands the name
	// through that vocabulary, to something which is emphatically not the
	// security predicate; a lookup finds no definition and an earlier
	// version then fell back to the bare name and removed an ordinary
	// property, which in SD mandatory-pointer selection would let a
	// mandatory /proof value be dropped from a derivation.
	active := nodeContext(node, context, options)

	var keys []string
	for key := range node {
		if strings.HasPrefix(key, "@") {
			continue
		}
		// Already expanded: this IS the predicate, whatever a context might
		// say about other names.
		if key == ProofPredicate {
			keys = append(keys, key)
			continue
		}

		resolved, unresolvable := expandMemberName(active, key)
		if !unresolvable {
			// The context has an opinion, so it decides - an alias of the
			// predicate is a proof, anything else is not.
			if resolved == ProofPredicate {
				keys = append(keys, key)
			}
			continue
		}

		// Nothing resolves it: no context, or one that defines neither the
		// term nor a vocabulary to read it through. "proof" is then the
		// name it is everywhere else, and failing to remove the root's own
		// proof is the worse failure.
		if key == "proof" {
			keys = append(keys, key)
		}
	}
	return keys
}

// expandMemberName resolves a member name the way JSON-LD expands a property:
// through an explicit term definition, or through @vocab when there is one.
// unresolvable reports that the active context gives the name no meaning, so
// the name itself is all a caller has to go on.
func expandMemberName(active *ld.Context, key string) (resolved string, unresolvable bool) {
	if active == nil {
		return "", true
	}
	iri, err := active.ExpandIri(key, false, true, nil, nil)
	if err != nil || iri == "" || iri == key {
		return "", true
	}
	return iri, false
}

// nodeContext is the context ACTIVE on a node: the document's, with any
// type-scoped context its own types name applied on top.
//
// JSON-LD applies a type-scoped context before expanding a node's members, so
// a proof alias defined in that scope is one RootProofs sees - it expands the
// whole document - and one a top-level lookup misses. The VC 2.0 context
// itself declares proof this way, which is why a document-level lookup finds
// nothing for the plain name.
func nodeContext(node map[string]any, context any, options *ld.JsonLdOptions) *ld.Context {
	// An explicit "@context": null on the node is a RESET, and it clears the
	// options' expandContext along with everything else. It arrives here as
	// a nil context, indistinguishable from an ABSENT one, so the node is
	// asked directly. Measured: the same document expands to its triples
	// with no @context member and to NOTHING with an explicit null - while
	// term resolution went on applying the expandContext either way, so
	// ProofKeyFor handed back an alias the document had just disabled and
	// Sign returned a document whose proof expansion drops.
	//
	// The null is the INNERMOST context, so it wins over anything the
	// caller composed ahead of it.
	if own, present := node["@context"]; present && own == nil {
		if options == nil {
			options = NewJSONLDOptions("")
		}
		return ld.NewContext(nil, options)
	}

	active := activeContext(context, options)
	if active == nil {
		return nil
	}

	// LEXICOGRAPHIC order, and deduplicated. JSON-LD applies type-scoped
	// contexts in sorted order of the type names, so two types defining the
	// same term have a defined winner - taking them in document order would
	// let the order they happen to be written in decide which definition
	// applies, which is the thing this whole change is about.
	var types []string
	seen := map[string]bool{}
	for _, key := range []string{"@type", "type"} {
		for _, entry := range asList(node[key]) {
			name, isString := entry.(string)
			if !isString || name == "" || seen[name] {
				continue
			}
			seen[name] = true
			types = append(types, name)
		}
	}
	sort.Strings(types)

	for _, name := range types {
		definition := active.GetTermDefinition(name)
		if definition == nil || !definition.HasContext {
			continue
		}
		scoped, err := active.Parse(definition.Context)
		if err != nil {
			continue
		}
		active = scoped
	}
	return active
}

// activeContext parses a document's context, or returns nil when there is
// none to parse or it will not load.
func activeContext(context any, options *ld.JsonLdOptions) *ld.Context {
	if options == nil {
		options = NewJSONLDOptions("")
	}
	// Either one is enough to resolve a name against. Returning early on an
	// absent document context skipped ExpandContext entirely, which is the
	// case this exists for.
	if context == nil && options.ExpandContext == nil {
		return nil
	}
	// From ExpandContext first, which is what json-gold applies before a
	// document's own. RootProofs expands under these options, so ignoring
	// it here made term resolution disagree with the expansion it is
	// supposed to match - and an external context aliasing "proof" would
	// then have signing and SD proof removal act on a different member.
	active := ld.NewContext(nil, options)
	if options.ExpandContext != nil {
		expandContext := options.ExpandContext
		if outer, isMap := expandContext.(map[string]any); isMap {
			if inner, present := outer["@context"]; present {
				expandContext = inner
			}
		}
		parsed, err := active.Parse(expandContext)
		if err != nil {
			return nil
		}
		active = parsed
	}

	// Only when there IS one: Parse(nil) is a context reset, which would
	// throw away the expand context just applied.
	if context != nil {
		parsed, err := active.Parse(context)
		if err != nil {
			return nil
		}
		active = parsed
	}
	return active
}

func termDefinition(active *ld.Context, term string) *ld.TermDefinition {
	if active == nil {
		return nil
	}
	return active.GetTermDefinition(term)
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

// IsGraphWrapper reports whether a node in a COMPACTED document is a graph
// WRAPPER - a named graph standing for nothing but the graph it carries -
// rather than a node that happens to have a @graph member of its own.
//
// ld.IsGraph answers this for EXPANDED documents, where the only spellings are
// @id and @index. In a compacted document a context may alias either to any
// term, and ld.IsGraph then reports the wrapper as an ordinary node: SD proof
// removal left such a graph in the supposedly proof-free document, and root
// selection offered it as a candidate for what the document is about.
func IsGraphWrapper(node map[string]any, context any, options *ld.JsonLdOptions) bool {
	if _, present := node["@graph"]; !present {
		return false
	}

	var active *ld.Context
	for key := range node {
		if key == "@graph" || key == "@context" || key == "@id" || key == "@index" {
			continue
		}
		if active == nil {
			active = nodeContext(node, composedContext(node, context, context != nil), options)
			if active == nil {
				return false
			}
		}
		resolved, unresolvable := expandMemberName(active, key)
		if unresolvable || (resolved != "@id" && resolved != "@index") {
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
func referencedIDs(nodes []map[string]any, context any, options *ld.JsonLdOptions) ([]map[string]bool, bool) {
	// Expanded when ANYTHING has a context to resolve against - the shared
	// one, or a node's own. A top-level compact array has no shared context,
	// but its nodes may each carry one, and returning early on the shared
	// one alone forced the string scan, which cannot tell an id-coerced
	// value from an ordinary literal: a literal equal to another node's id
	// made that node look referenced and a valid document read as rootless.
	//
	// With NO context anywhere there is nothing to expand against - every
	// term would simply drop, leaving no references at all and every node
	// looking like a root - so the string scan is the better reading there.
	// It errs toward seeing a reference rather than missing one.
	hasContext := context != nil
	entries := make([]any, 0, len(nodes))
	for _, node := range nodes {
		if _, own := node["@context"]; own {
			hasContext = true
		}
		entries = append(entries, node)
	}
	if !hasContext {
		return nil, false
	}

	if options == nil {
		options = NewJSONLDOptions("")
	}

	document := map[string]any{"@graph": entries}
	if context != nil {
		document["@context"] = context
	}

	expanded, err := ld.NewJsonLdProcessor().Expand(document, options)
	if err != nil {
		return nil, false
	}
	// PER SOURCE NODE, so a node naming itself is not counted as referring
	// to itself. One combined set lost that, and the string-scan fallback
	// did not - so adding a context to a document changed which node it was
	// about, which is the one thing root selection must never do.
	//
	// The alignment has to hold for that: expanding a @graph of N nodes
	// should give N entries back. When it does not - a node dropped as
	// free-floating, say - there is no way to say which node supplied a
	// reference, and the scan is the honest answer.
	if len(expanded) != len(nodes) {
		return nil, false
	}

	referencedBy := make([]map[string]bool, len(nodes))
	for i, entry := range expanded {
		referencedBy[i] = map[string]bool{}
		collectReferencedIDs(entry, referencedBy[i], true)
	}
	return referencedBy, true
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
// the string scan otherwise. Either way a node's OWN references do not count:
// a node that names itself is still the node nothing ELSE refers to.
func isReferenced(nodes []map[string]any, skip int, id string, referencedBy []map[string]bool, resolved bool) bool {
	if resolved {
		for source, references := range referencedBy {
			if source != skip && references[id] {
				return true
			}
		}
		return false
	}
	return referencedByAnyOther(nodes, skip, id)
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
		// ld.IsGraph, not a key count: a graph object may carry @index
		// beside @graph and @id, and counting keys called an indexed
		// proof graph a document node.
		if ld.IsGraph(node) {
			continue
		}
		// Cloned for the same reason CompactRootProof clones: coalescing
		// merges into the first map for an id, and the caller's document is
		// not ours to rewrite.
		nodes = append(nodes, maps.Clone(node))
	}

	return rootOf(coalesceByID(nodes))
}

// expandNodeIDs resolves several identifiers to the absolute IRIs they stand
// for, in ONE expansion, keeping the position of each. An identifier that does
// not resolve keeps its original spelling, which is the right answer for a
// blank node label and a safe one for anything else.
func expandNodeIDs(ids []string, context any, options *ld.JsonLdOptions) []string {
	resolved := make([]string, len(ids))
	copy(resolved, ids)

	entries := make([]any, 0, len(ids))
	positions := make([]int, 0, len(ids))
	for i, id := range ids {
		if id == "" || strings.HasPrefix(id, "_:") {
			continue
		}
		// A node carrying nothing but an identifier is free-floating and
		// expansion drops it, so each probe gets a property to keep it.
		entries = append(entries, map[string]any{
			"@id":                        id,
			"https://example.invalid/at": "probe",
		})
		positions = append(positions, i)
	}
	if len(entries) == 0 {
		return resolved
	}

	if options == nil {
		options = NewJSONLDOptions("")
	}
	document := map[string]any{"@graph": entries}
	if context != nil {
		document["@context"] = context
	}

	expanded, err := ld.NewJsonLdProcessor().Expand(document, options)
	if err != nil || len(expanded) != len(entries) {
		return resolved
	}
	for at, entry := range expanded {
		node, isNode := entry.(map[string]any)
		if !isNode {
			continue
		}
		if id, ok := node["@id"].(string); ok && id != "" {
			resolved[positions[at]] = id
		}
	}
	return resolved
}

// JoinContexts applies one context after another, as JSON-LD does for an outer
// scope and a node inside it.
//
// FLATTENED into a single array: json-gold refuses a context array nested
// inside another. Repeated entries are kept rather than deduplicated, because
// re-applying a context is how a document puts back a term an earlier one
// redefined - dropping the repeat would silently change what the terms mean.
//
// A nil INNER means "there is no inner context", and this returns the outer
// one unchanged. It does NOT mean an explicit "@context": null, which is a
// RESET and must clear the outer context instead - a caller that cannot tell
// the two apart has to check for the key's presence itself before calling
// here. Both callers in this package do; getting it wrong re-enables terms a
// document deliberately switched off, and changes the RDF being signed.
func JoinContexts(outer any, inner any) any {
	if outer == nil {
		return inner
	}
	if inner == nil {
		return outer
	}

	joined := make([]any, 0, 2)
	for _, context := range []any{outer, inner} {
		if entries, isList := context.([]any); isList {
			joined = append(joined, entries...)
			continue
		}
		joined = append(joined, context)
	}
	return joined
}

// ProofKeyFor returns the member name a new proof should be written under on
// this node.
//
// Not always "proof". That is the name the v2 context gives the predicate, but
// a document may ALIAS it - in which case the new proof belongs beside the
// existing one under the same name, as one proof set - or remap it to an
// ordinary property, in which case writing "proof" would attach the signature
// to something that is not a proof at all, and the library could not verify
// what it had just signed.
//
// The absolute predicate is the answer whenever the bare term is not KNOWN to
// mean the predicate - whether the active context gives "proof" another
// meaning, or there is no context to give it any. An IRI expands to itself
// under any context; a bare term no context defines is a RELATIVE IRI, which
// expansion drops.
func ProofKeyFor(node map[string]any, context any, options *ld.JsonLdOptions) string {
	active := nodeContext(node, context, options)

	// An existing proof member keeps its name, so signing twice makes one
	// proof set rather than two members meaning the same thing - but only a
	// name that SURVIVES expansion. ProofKeys deliberately also returns a
	// bare, unmapped "proof" so that removing the root's own proof fails
	// safe; writing a signature there would not.
	for _, key := range ProofKeys(node, context, options) {
		if key == ProofPredicate {
			return key
		}
		if resolved, unresolvable := expandMemberName(active, key); !unresolvable && resolved == ProofPredicate {
			return key
		}
	}

	if resolved, unresolvable := expandMemberName(active, "proof"); !unresolvable && resolved == ProofPredicate {
		return "proof"
	}

	// Nothing maps the bare term to the predicate: no context at all - a
	// document already in expanded form - or one defining neither "proof"
	// nor a vocabulary to read it through. Expansion drops a member named
	// that, so Sign would return a document with no root proof and this
	// library would refuse to verify what it had just produced.
	return ProofPredicate
}
