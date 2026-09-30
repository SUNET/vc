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
