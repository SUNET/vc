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

	subjects := make(map[string]bool)
	referenced := make(map[string]bool)
	for _, quad := range defaultGraph {
		if quad == nil || quad.Subject == nil {
			continue
		}
		subject := quad.Subject.GetValue()
		subjects[subject] = true
		// A SELF-edge is not a reference from anything else. A presentation
		// may set id to the holder DID, and holder is a node reference in
		// the VC 2.0 context - counting that edge would leave the document
		// with no root at all and reject a perfectly good signature.
		if isNode(quad.Object) && quad.Object.GetValue() != subject {
			referenced[quad.Object.GetValue()] = true
		}
	}

	// Sorted, so a document with more than one candidate is refused the
	// same way every time rather than sometimes picking one - map order
	// would otherwise make the refusal a coin flip.
	var roots []string
	for subject := range subjects {
		if !referenced[subject] {
			roots = append(roots, subject)
		}
	}
	slices.Sort(roots)
	// Exactly one, or the document does not say which node is its root and
	// no proof in it can be attributed. Refusing is the only safe answer:
	// picking one would be picking whichever an attacker arranged.
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
