package common

import (
	"maps"
	"slices"
)

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
	return FindProofNodeFunc(data, proofType, nil)
}

// FindProofNodeInGraphs returns a typed proof node from one of the named
// graphs, and nothing from anywhere else.
//
// Selection has to be tied to the graph the document's root LINKS to, not
// to a value found anywhere in the proof object. A proofValue can be copied
// into a stub proof at the root while the real, typed proof is moved onto
// an embedded credential - and since verification removes every proof when
// hashing, the document hashes the same either way. Matching on the value
// would then pick the moved proof and verify it against the root's key.
//
// So the search is confined to the root's own graph, and a graph holding no
// TYPED proof - the stub in that attack holds only a proofValue - yields
// nothing.
func FindProofNodeInGraphs(proofObject any, proofType string, graphNames []string) map[string]any {
	if len(graphNames) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(graphNames))
	for _, name := range graphNames {
		wanted[name] = true
	}

	root, ok := proofObject.(map[string]any)
	if !ok {
		return nil
	}
	for _, entry := range asGraphNodes(root["@graph"]) {
		id, _ := entry["id"].(string)
		if !wanted[id] {
			continue
		}
		if found := FindProofNodeFunc(entry["@graph"], proofType, nil); found != nil {
			return found
		}
	}
	return nil
}

// asGraphNodes normalises a @graph member, which may be one node or a list.
func asGraphNodes(graph any) []map[string]any {
	switch v := graph.(type) {
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if node, ok := item.(map[string]any); ok {
				out = append(out, node)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{v}
	}
	return nil
}

// FindProofNodeWithValue returns the proof node carrying one of the given
// proofValues.
//
// The proofValue identifies a proof unambiguously among several in one
// document: it is the signature itself. A caller that knows WHICH proof it
// means - because it read it off the document's root - names it this way
// rather than relying on traversal order.
func FindProofNodeWithValue(proofObject any, proofType string, values []string) map[string]any {
	if len(values) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(values))
	for _, v := range values {
		wanted[v] = true
	}
	return FindProofNodeFunc(proofObject, proofType, func(node map[string]any) bool {
		value, _ := node["proofValue"].(string)
		return wanted[value]
	})
}

// FindProofNodeFunc returns the first proof node satisfying match, in a
// DETERMINISTIC traversal order - map keys are visited sorted, so a document
// holding two proof nodes does not return a different one between runs.
//
// Determinism alone is not enough when the answer matters: a caller that
// knows which proof it means must say so through match.
func FindProofNodeFunc(data any, proofType string, match func(map[string]any) bool) map[string]any {
	switch v := data.(type) {
	case map[string]any:
		if HasType(v, proofType) || HasType(v, "Proof") {
			if match == nil || match(v) {
				return v
			}
		}
		for _, key := range slices.Sorted(maps.Keys(v)) {
			if found := FindProofNodeFunc(v[key], proofType, match); found != nil {
				return found
			}
		}
	case []any:
		for _, item := range v {
			if found := FindProofNodeFunc(item, proofType, match); found != nil {
				return found
			}
		}
	}
	return nil
}
