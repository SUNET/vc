package credential

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// ProofPredicate is the expanded IRI of the link a document uses to attach a
// proof to itself.
//
// There is only one. VC 1.1 and VC 2.0 both map the term "proof" to
// https://w3id.org/security#proof - checked against their published contexts,
// not assumed. A second "VC 1.1-era" predicate used to be listed here,
// https://www.w3.org/2018/credentials#proof, which neither version defines:
// treating it as a proof meant any document using that IRI as an ORDINARY
// property had it removed from the secured document, so its value could be
// changed or stripped without invalidating any signature.
const ProofPredicate = "https://w3id.org/security#proof"

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
	claimedNodes := map[int]bool{}
	rootID, _ := root["@id"].(string)
	for _, predicate := range []string{ProofPredicate} {
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
			// One entry per name by now, holding every triple written
			// under it - so removing the proof removes the whole named
			// graph, which is what RDF says it is, rather than whichever
			// part of it happened to be indexed.
			if match := graphNamed(graphs, id); match >= 0 {
				// ONCE. The same named graph may be referenced more than
				// once, and duplicate references produce the same RDF
				// triple - so counting them as separate proofs could put a
				// document over MaxRootProofs on the strength of a
				// serialization detail the signed RDF does not have.
				if !claimed[match] {
					proofs = append(proofs, graphs[match])
					claimed[match] = true
				}
				continue
			}
			// A proof alias WITHOUT "@container": "@graph" is written
			// INLINE while the document is compact, and an RDF round trip
			// flattens it into an ordinary top-level node rather than a
			// named graph. The reference is then just an @id, and resolving
			// it only against named graphs returned the incomplete LINK as
			// the proof while the real proof node stayed in the document
			// the signature covers - so a document verified straight from
			// Sign and failed once serialized and read back.
			if match := nodeNamed(nodes, id, rootID); match >= 0 {
				if !claimedNodes[match] {
					proofs = append(proofs, nodes[match])
					claimedNodes[match] = true
				}
				continue
			}

			// A link naming nothing in this document carries no proof; the
			// caller will find it incomplete.
			proofs = append(proofs, node)
		}
		delete(root, predicate)
	}

	kept := make([]any, 0, len(nodes)+len(graphs))
	for i, node := range nodes {
		if claimedNodes[i] {
			continue
		}
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

	expanded, err := ld.NewJsonLdProcessor().Expand(document, rc.expansionOptions())
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
		// ld.IsGraph, not a key count: a graph object may carry @index
		// beside @graph and @id, and counting keys called an indexed
		// proof graph a document node.
		if ld.IsGraph(node) {
			graphs = append(graphs, node)
			continue
		}
		nodes = append(nodes, node)
	}

	// COALESCED by @id. Expanded JSON-LD may carry a node's properties
	// across several top-level entries, and RDF conversion merges them into
	// one node - so treating them as separate candidates reported an
	// ambiguous root for a document whose merged serialization reads fine.
	// The same is true of a named graph written more than once.
	nodes = coalesceByID(nodes)
	graphs = coalesceByID(graphs)

	root, err := rootOf(nodes)
	if err != nil {
		return nil, nil, nil, err
	}

	return root, nodes, graphs, nil
}

// coalesceByID merges top-level entries that name the same node or graph.
//
// Entries without an @id are each their own anonymous node and are left
// alone. Order is preserved, and the merged entry sits where the first of
// its parts did, so nothing about the document's shape depends on map
// iteration.
func coalesceByID(entries []map[string]any) []map[string]any {
	merged := make([]map[string]any, 0, len(entries))
	at := map[string]int{}

	for _, entry := range entries {
		id, named := entry["@id"].(string)
		if !named || id == "" {
			merged = append(merged, entry)
			continue
		}
		index, seen := at[id]
		if !seen {
			at[id] = len(merged)
			merged = append(merged, entry)
			continue
		}
		into := merged[index]
		for key, value := range entry {
			if key == "@id" {
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

// ExpansionOptions returns the JSON-LD options this credential was parsed
// with, ready for re-expanding it. A caller that re-expands any part of a
// document under fresh defaults instead sees a different document than the one
// that parsed - or, for a context only this credential's loader knows, no
// document at all.
func (rc *RDFCredential) ExpansionOptions() *ld.JsonLdOptions {
	return rc.expansionOptions()
}

// expansionOptions are the options this credential was PARSED with, which
// is what root selection has to re-expand under.
//
// Expanding with a fresh default instead meant a credential created with a
// custom document loader, an expandContext, a processing mode or a base
// parsed successfully and then expanded differently - or not at all - on
// every Sign and Verify, with ids resolving against a different base.
//
// A copy, and with Format and InputFormat cleared: both describe a call whose
// input is N-Quads, which this one's is not. A caller reusing one option set
// across both kinds of work left InputFormat set, and the credential - parsed
// from JSON, and still JSON here - was then handed to Normalize to be read as
// N-Quads. The dataset branch of CanonicalForm, whose input really is N-Quads,
// sets it back explicitly.
func (rc *RDFCredential) expansionOptions() *ld.JsonLdOptions {
	if rc.options == nil {
		return NewJSONLDOptions("")
	}
	copied := *rc.options
	copied.Format = ""
	copied.InputFormat = ""
	if copied.DocumentLoader == nil {
		copied.DocumentLoader = GetGlobalLoader()
	}
	return &copied
}

// RootID returns the identifier of the node this document is ABOUT, or an
// empty string when that node carries none. Deriving a selectively-disclosed
// credential needs it: the derived dataset is flattened, and which of its
// nodes the derived document should be rooted at is not something to infer
// from what survived disclosure - it is the node the BASE document was about.
func (rc *RDFCredential) RootID() (string, error) {
	root, _, _, err := rc.rootAndGraphs(rc.documentSource())
	if err != nil {
		return "", err
	}
	id, _ := root["@id"].(string)
	if isBlankOrAbsent(id) {
		return "", nil
	}
	return id, nil
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
// "_:root" to whatever its identifier issuer produces. Three things are
// required of such a root instead. The flattened root must be nameless too,
// or it is plainly a different node. Nothing may point back at the root
// through @reverse, which is the one way to be pointed at without the
// pointing showing up as a reference to an @id. And nothing may refer to it
// by name. Together those make it the unreferenced node in the flattened
// form as well, where rootOf refuses as soon as a second unreferenced node
// appears - so it cannot have moved.
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

	if isBlankOrAbsent(compactID) {
		// Nothing to compare the root by, so the flattened root has to be
		// nameless too. A flattened root with a real name is a DIFFERENT
		// node: @reverse lets a nested node point at an anonymous parent
		// without giving it one, and after flattening the parent is the
		// referenced node while the child is the root.
		if !isBlankOrAbsent(flatID) {
			return fmt.Errorf("this document is about an unnamed node as written and about %q once serialized through RDF, so a proof on one would be read as the other's", flatID)
		}
		// Both unnamed. Then nothing may point BACK at the root, because
		// that is what would make some other node the unreferenced one -
		// and with no name to compare, that swap would be invisible.
		if reverseLinkAnywhere([][]map[string]any{compactNodes, compactGraphs}) {
			return fmt.Errorf("this document is about an unnamed node and uses @reverse, so which node it is about would be decided differently once serialized through RDF")
		}
		if referencedAnywhere([][]map[string]any{compactNodes, compactGraphs}, compactID) {
			return fmt.Errorf("this document is about a node nothing can name across serializations, and something in it refers to that node, so which node it is about would be decided differently once serialized through RDF")
		}
		return nil
	}
	if isBlankOrAbsent(flatID) {
		return fmt.Errorf("this document is about %q as written and about an unnamed node once serialized through RDF, so a proof on one would be read as the other's", compactID)
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

// reverseLinkAnywhere reports whether the document uses @reverse.
//
// A reverse link is the one way a node can be pointed AT without the
// pointing being visible as a reference to its @id - which is exactly the
// signal the unnamed-root rule relies on. Rare enough that refusing it
// outright for an unnamed root costs nothing; a NAMED root is compared by
// identity and needs no such rule.
func reverseLinkAnywhere(entries [][]map[string]any) bool {
	found := false
	var walk func(any)
	walk = func(value any) {
		if found {
			return
		}
		switch typed := value.(type) {
		case map[string]any:
			if _, reverse := typed["@reverse"]; reverse {
				found = true
				return
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

	// SELF-links do not count, the same way rootOf does not count them: a
	// node that names itself - a credential whose credentialSubject is the
	// credential - is still the node nothing ELSE refers to, before and
	// after flattening alike. Counting them refused a document that
	// flattens perfectly well.
	//
	// What identifies a self-link is the nearest ENCLOSING node, which is
	// why this tracks it while walking rather than taking the top-level
	// entry's id. A node reached through @included carries its own @id and
	// becomes the enclosing node for everything under it, so a reference
	// from there back to the root still counts - and it must, because that
	// node sits beside the root once flattened and is exactly what makes
	// the root stop being the unreferenced one.
	var walk func(value any, self string, topLevel bool) bool
	walk = func(value any, self string, topLevel bool) bool {
		switch typed := value.(type) {
		case map[string]any:
			// A VALUE object holds a literal, not a node, and nothing
			// inside it refers to anything.
			if _, isValue := typed["@value"]; isValue {
				return false
			}
			at, named := typed["@id"].(string)
			if len(typed) == 1 && named {
				// A bare {"@id": ...} is a reference, not a definition.
				return at == id && self != id
			}
			// A nested node object is a definition AND the object of an
			// edge from whatever contains it. Only a bare reference was
			// counted, so {"@id": "_:root", "@type": [...]} sitting under
			// another node pointed at the root without being seen - and
			// flattening then made the containing node the root, a switch
			// this check exists to refuse and, both names being blank,
			// could not otherwise notice.
			if !topLevel && named && at == id && self != id {
				return true
			}
			// A LIST is not a node object; its members belong to whatever
			// node encloses the list.
			if list, isList := typed["@list"]; isList {
				return walk(list, self, topLevel)
			}
			// Everything else here is a NODE object, and it becomes the
			// enclosing node for what is under it - whether or not it has a
			// name. An anonymous one that inherited the parent's identity
			// made its reference back to a blank-named root look like a
			// self-link: flattening then turns that node into a separate
			// blank node, the original root stops being the unreferenced
			// one, and because both names are blank the root could switch
			// without this check noticing. A proof relocated onto the new
			// root secures the same unsecured RDF, which is the whole
			// attack.
			enclosing := ""
			if named && at != "" {
				enclosing = at
			}
			for key, member := range typed {
				if key == "@id" {
					continue
				}
				if walk(member, enclosing, false) {
					return true
				}
			}
		case []any:
			for _, member := range typed {
				if walk(member, self, topLevel) {
					return true
				}
			}
		}
		return false
	}

	for _, group := range entries {
		for _, entry := range group {
			if walk(entry, "", true) {
				return true
			}
		}
	}
	return false
}

// graphNamed returns the index of the graph entry carrying this name, or -1.
// Entries are coalesced by name before this runs, so there is at most one.
// nodeNamed finds the top-level node a proof reference points at. The ROOT is
// never it: a document referring to itself as its own proof is naming the
// document the signature covers, and removing it would leave nothing.
func nodeNamed(nodes []map[string]any, id string, rootID string) int {
	if id == "" || (rootID != "" && id == rootID) {
		return -1
	}
	for i, node := range nodes {
		if name, _ := node["@id"].(string); name == id {
			return i
		}
	}
	return -1
}

func graphNamed(graphs []map[string]any, id string) int {
	if id == "" {
		return -1
	}
	for i, graph := range graphs {
		if name, _ := graph["@id"].(string); name == id {
			return i
		}
	}
	return -1
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
	shared, ok := expanded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("a root proof is not a node")
	}
	// A COPY from the start. The node may be one SecuredDocument memoized
	// and hands to every caller, and what happens to it below is not all
	// ours: json-gold's Compact takes the node as input, and this must not
	// depend on whether that leaves it alone.
	node := maps.Clone(shared)

	if graph, wrapped := node["@graph"]; wrapped {
		entries, isList := graph.([]any)
		if !isList {
			return nil, fmt.Errorf("a root proof names %T rather than one proof", graph)
		}
		// COALESCED first. Expanded JSON-LD may carry one proof node's
		// properties across several entries of its graph - two wrappers
		// with the same name have their graphs concatenated here - and RDF
		// conversion merges them into one node. Counting the entries
		// without merging refused a proof that is single by every measure
		// that matters.
		// CLONED before coalescing. coalesceByID merges into the first map
		// it sees for an id, and these members can be the shared nodes
		// SecuredDocument hands out: compacting the same candidate twice -
		// which the ecdsa suite does, once to match the offered proof and
		// once to verify it - would then merge a split proof into the cache
		// twice and accumulate duplicate values, and two verifications at
		// once would race on the same maps.
		//
		// A shallow copy is enough: the merge appends to new slices and
		// writes only top-level keys.
		nodes := make([]map[string]any, 0, len(entries))
		for _, entry := range entries {
			member, isNode := entry.(map[string]any)
			if !isNode {
				return nil, fmt.Errorf("a root proof's graph does not hold a node")
			}
			nodes = append(nodes, maps.Clone(member))
		}
		merged := coalesceByID(nodes)
		if len(merged) != 1 {
			return nil, fmt.Errorf("a root proof names %d proofs rather than one", len(merged))
		}
		node = merged[0]
	}

	context := map[string]any{"@context": ContextV2}
	compacted, err := ld.NewJsonLdProcessor().Compact(node, context, NewJSONLDOptions(""))
	if err != nil {
		return nil, fmt.Errorf("failed to compact a root proof: %w", err)
	}
	delete(compacted, "@context")

	return compacted, nil
}

// HasProofType reports whether a compacted proof node carries this type.
//
// A node may carry SEVERAL types - a document that puts a type-scoped
// context on its own alias for DataIntegrityProof has to name both, or the
// VC 2.0 context's own scoped definitions of cryptosuite, proofValue and the
// rest never activate. Reading only a single string called such a proof
// untyped.
func HasProofType(proofNode map[string]any, want string) bool {
	switch typed := proofNode["type"].(type) {
	case string:
		return typed == want
	case []any:
		for _, entry := range typed {
			if name, ok := entry.(string); ok && name == want {
				return true
			}
		}
	case []string:
		for _, name := range typed {
			if name == want {
				return true
			}
		}
	}
	return false
}
