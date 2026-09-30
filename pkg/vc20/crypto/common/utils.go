package common

// HasType checks if a JSON-LD object has a specific type
func HasType(m map[string]any, expectedType string) bool {
	t, ok := m["type"]
	if !ok {
		t, ok = m["@type"]
	}
	if !ok {
		return false
	}

	if s, ok := t.(string); ok {
		return s == expectedType
	}
	if list, ok := t.([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok && s == expectedType {
				return true
			}
		}
	}
	return false
}

// FindProofNode recursively searches for a proof node in a JSON-LD object
func FindProofNode(data any, proofType string) map[string]any {
	if m, ok := data.(map[string]any); ok {
		if HasType(m, proofType) || HasType(m, "Proof") {
			return m
		}
		// Check all values
		for _, v := range m {
			if found := FindProofNode(v, proofType); found != nil {
				return found
			}
		}
	} else if list, ok := data.([]any); ok {
		for _, item := range list {
			if found := FindProofNode(item, proofType); found != nil {
				return found
			}
		}
	}
	return nil
}

// securityProofIRI is the expanded form of the "proof" predicate. Compacting
// a proof object against the VC 2.0 context leaves it expanded, because the
// nodes that carry it hold nothing else the context can key on.
const securityProofIRI = "https://w3id.org/security#proof"

// FindRootProofNode returns the proof node attached to the document's ROOT
// node, or nil when it cannot be identified.
//
// A verifiable presentation holds two proofs - the holder's, over the
// presentation, and the embedded credential's, from the issuer - and both
// land in the same proof object. "The first one found" is not a choice, it
// is an accident of graph ordering: it happens to reach the holder's proof
// for the documents VPBuilder produces today, and nothing makes that true.
// Verifying the issuer's proofValue with the holder's key fails a
// presentation that is perfectly good.
//
// The root is found by following the link, not by guessing: the graph node
// whose id is the document's own id names its proof, and that named graph
// holds it. rootID comes from the document itself, so a document with no id
// - which is also a document with nothing to be ambiguous about - returns
// nil and leaves the caller to fall back.
func FindRootProofNode(proofObject any, proofType, rootID string) map[string]any {
	if rootID == "" {
		return nil
	}
	root, ok := proofObject.(map[string]any)
	if !ok {
		return nil
	}
	graph, ok := root["@graph"]
	if !ok {
		return nil
	}

	byID := make(map[string]map[string]any)
	for _, entry := range graphNodes(graph) {
		if id, ok := entry["id"].(string); ok {
			byID[id] = entry
		}
	}

	rootNode, ok := byID[rootID]
	if !ok {
		return nil
	}
	proofID := nodeReference(rootNode["proof"])
	if proofID == "" {
		proofID = nodeReference(rootNode[securityProofIRI])
	}
	if proofID == "" {
		return nil
	}
	proofGraph, ok := byID[proofID]
	if !ok {
		return nil
	}
	return FindProofNode(proofGraph, proofType)
}

// graphNodes normalises a @graph member, which may be one node or a list.
func graphNodes(graph any) []map[string]any {
	var out []map[string]any
	switch v := graph.(type) {
	case []any:
		for _, item := range v {
			if node, ok := item.(map[string]any); ok {
				out = append(out, node)
			}
		}
	case map[string]any:
		out = append(out, v)
	}
	return out
}

// nodeReference reads an id out of a JSON-LD node reference, which is either
// {"id": "..."} or the bare string.
func nodeReference(v any) string {
	switch ref := v.(type) {
	case string:
		return ref
	case map[string]any:
		id, _ := ref["id"].(string)
		return id
	}
	return ""
}
