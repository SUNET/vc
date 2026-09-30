package eddsa

import (
	"slices"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/piprate/json-gold/ld"
)

// Proof predicates, deliberately the SAME two that
// credential.CredentialWithoutProofForTypes removes.
//
// They have to match exactly. A link this accepts but removal does not
// leaves that proof in the hashed document, so verification cannot
// reproduce a signature computed with proofs removed - a valid document
// would be rejected. Widening the set here without widening removal is
// therefore not a tolerance, it is a break.
var proofPredicates = []string{
	"https://w3id.org/security#proof",
	"http://www.w3.org/ns/credentials#proof",
}

// rootProofGraphs names the RDF graphs holding the proofs the document
// attaches to ITSELF.
//
// Read from the RDF DATASET, not from the JSON. The JSON is the wrong layer
// for this question three ways over: a compact document may alias "proof"
// and "proofValue" through its context, an expanded one need not label its
// root, and either may carry nodes that are neither the root nor anything
// the root names. RDF has no aliases, gives every node a label, and is the
// form the signature is actually over.
//
// Why it has to be asked at all: Verify removes EVERY proof when hashing, so
// a proof MOVED elsewhere in the document - onto an embedded credential, or
// onto a node detached from the root - leaves the canonical form unchanged.
// Someone holding a legitimately signed document could relocate its proof
// and have the misplaced one verify with the original key. So the proof
// checked has to be the one the root itself carries.
//
// Graph NAMES rather than proofValues, because a value does not establish
// attachment: a proofValue can be copied into a stub proof at the root
// while the real, typed proof sits on an embedded credential, and matching
// on the value alone would then select the moved one. The graph the root
// links to is what the root actually carries.
//
// THE ROOT IS THE SUBJECT NOTHING ELSE POINTS AT. A presentation names its
// embedded credential, so the credential is referenced and the presentation
// is not; a detached node is unreferenced too, which makes the document
// AMBIGUOUS rather than merely odd - so more than one candidate is refused
// rather than resolved by preference. An empty result means the caller must
// refuse.
func rootProofGraphs(cred *credential.RDFCredential) []string {
	dataset := cred.Dataset()
	if dataset == nil {
		return nil
	}

	defaultGraph := dataset.Graphs["@default"]
	if len(defaultGraph) == 0 {
		return nil
	}

	// The reference graph among the document's own subjects. A subject that
	// nothing else points at is a root candidate - but "nothing else" has
	// to mean nothing OUTSIDE its own cycle, because a perfectly ordinary
	// credential can contain one: the credential names its
	// credentialSubject, and an @id-valued subject property can name the
	// credential back. Requiring zero incoming edges rejected those.
	//
	// So the candidates are the SOURCE components of the reference graph -
	// the strongly connected components nothing outside them points at.
	// A presentation names its embedded credential, so the credential's
	// component has an incoming edge and only the presentation's is a
	// source. A DETACHED node is a source of its own, which makes the
	// document ambiguous - and more than one source is refused rather than
	// resolved by preference.
	subjects := make(map[string]bool)
	edges := make(map[string]map[string]bool)
	for _, quad := range defaultGraph {
		if quad == nil || quad.Subject == nil {
			continue
		}
		subject := quad.Subject.GetValue()
		subjects[subject] = true
		if edges[subject] == nil {
			edges[subject] = make(map[string]bool)
		}
	}
	for _, quad := range defaultGraph {
		if quad == nil || quad.Subject == nil || !isNode(quad.Object) {
			continue
		}
		subject, object := quad.Subject.GetValue(), quad.Object.GetValue()
		// Only edges BETWEEN the document's subjects matter, and a
		// self-edge says nothing about parentage - a presentation may set
		// id to the holder DID, and holder is a node reference.
		if subject == object || !subjects[object] {
			continue
		}
		edges[subject][object] = true
	}

	candidates := sourceComponent(subjects, edges)
	if len(candidates) == 0 {
		return nil
	}

	// A source component is not a root: the credential ↔ credentialSubject
	// cycle puts BOTH nodes in it, and accepting either one's proof link
	// would let the proof be moved onto the subject node - which
	// CredentialWithoutProof removes just the same, so the hash is
	// unchanged and a credential with no proof of its own would verify.
	//
	// The root is the member that IS a credential or a presentation, said
	// by its rdf:type. Exactly one, or ownership is not established and the
	// document is refused.
	roots := typedRoots(defaultGraph, candidates)
	if len(roots) != 1 {
		return nil
	}

	var graphNames []string
	for _, quad := range defaultGraph {
		if quad == nil || quad.Subject == nil || quad.Predicate == nil {
			continue
		}
		if quad.Subject.GetValue() != roots[0] {
			continue
		}
		if !contains(proofPredicates, quad.Predicate.GetValue()) {
			continue
		}
		if isNode(quad.Object) {
			graphNames = append(graphNames, quad.Object.GetValue())
		}
	}
	slices.Sort(graphNames)
	return graphNames
}

// credentialTypes are the rdf:type values that say a node is the thing the
// document is about, in the spellings the parser produces.
var credentialTypes = []string{
	"https://www.w3.org/2018/credentials#VerifiableCredential",
	"https://www.w3.org/2018/credentials#VerifiablePresentation",
	"https://www.w3.org/ns/credentials#VerifiableCredential",
	"https://www.w3.org/ns/credentials#VerifiablePresentation",
}

const rdfTypePredicate = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"

// typedRoots narrows root candidates to those that are actually a
// credential or a presentation.
func typedRoots(defaultGraph []*ld.Quad, candidates map[string]bool) []string {
	typed := make(map[string]bool)
	for _, quad := range defaultGraph {
		if quad == nil || quad.Subject == nil || quad.Predicate == nil || quad.Object == nil {
			continue
		}
		if quad.Predicate.GetValue() != rdfTypePredicate {
			continue
		}
		if !candidates[quad.Subject.GetValue()] {
			continue
		}
		if contains(credentialTypes, quad.Object.GetValue()) {
			typed[quad.Subject.GetValue()] = true
		}
	}

	roots := make([]string, 0, len(typed))
	for subject := range typed {
		roots = append(roots, subject)
	}
	slices.Sort(roots)
	return roots
}

// sourceComponent returns the members of the one strongly connected
// component nothing outside it points at, or nil when there is not exactly
// one.
//
// Not "the node with no incoming edges": an ordinary credential can contain
// a reference cycle, and then no node has zero incoming edges even though
// the document plainly has a root. Condensing the cycles first answers the
// question the document is really being asked - which node is it about -
// while still refusing a document with two unconnected candidates.
func sourceComponent(subjects map[string]bool, edges map[string]map[string]bool) map[string]bool {
	componentOf := stronglyConnectedComponents(subjects, edges)

	hasIncoming := make(map[int]bool)
	for subject, targets := range edges {
		for target := range targets {
			if componentOf[subject] != componentOf[target] {
				hasIncoming[componentOf[target]] = true
			}
		}
	}

	var sources []int
	seen := make(map[int]bool)
	for _, component := range componentOf {
		if seen[component] || hasIncoming[component] {
			continue
		}
		seen[component] = true
		sources = append(sources, component)
	}
	if len(sources) != 1 {
		return nil
	}

	members := make(map[string]bool)
	for subject, component := range componentOf {
		if component == sources[0] {
			members[subject] = true
		}
	}
	return members
}

// stronglyConnectedComponents assigns each subject a component id, by
// Tarjan's algorithm. Subjects are visited in sorted order so the ids are
// stable, which keeps a refusal a refusal rather than a coin flip.
func stronglyConnectedComponents(subjects map[string]bool, edges map[string]map[string]bool) map[string]int {
	index := make(map[string]int)
	low := make(map[string]int)
	onStack := make(map[string]bool)
	componentOf := make(map[string]int)
	var stack []string
	next, components := 0, 0

	var strongConnect func(string)
	strongConnect = func(v string) {
		index[v] = next
		low[v] = next
		next++
		stack = append(stack, v)
		onStack[v] = true

		targets := make([]string, 0, len(edges[v]))
		for target := range edges[v] {
			targets = append(targets, target)
		}
		slices.Sort(targets)
		for _, w := range targets {
			if _, visited := index[w]; !visited {
				strongConnect(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], index[w])
			}
		}

		if low[v] == index[v] {
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				componentOf[w] = components
				if w == v {
					break
				}
			}
			components++
		}
	}

	ordered := make([]string, 0, len(subjects))
	for subject := range subjects {
		ordered = append(ordered, subject)
	}
	slices.Sort(ordered)
	for _, subject := range ordered {
		if _, visited := index[subject]; !visited {
			strongConnect(subject)
		}
	}
	return componentOf
}

// isNode reports whether an RDF term names something else in the graph,
// rather than being a literal value.
//
// json-gold's helpers rather than a type switch: a term can arrive as a
// value or a pointer, and a switch on the pointer forms alone silently
// answers false for every term - which made every subject look unreferenced
// and every proof link invisible.
func isNode(term ld.Node) bool {
	return term != nil && (ld.IsIRI(term) || ld.IsBlankNode(term))
}

func contains(values []string, want string) bool {
	return slices.Contains(values, want)
}
