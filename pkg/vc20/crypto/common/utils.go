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

// FindProofNode recursively searches for a proof node in a JSON-LD object.
//
// A document can hold more than one - a verifiable presentation carries the
// holder's proof AND the embedded credential's issuer proof - and this
// returns the first one found. Use FindProofNodeFunc when it matters WHICH.
func FindProofNode(data any, proofType string) map[string]any {
	return FindProofNodeFunc(data, proofType, nil)
}

// FindProofNodeFunc returns the first proof node satisfying match, or the
// first proof node at all when match is nil.
//
// The traversal order is DETERMINISTIC: map keys are visited in sorted
// order. It used to be `for _, v := range m`, and Go randomises map
// iteration, so a document holding two proof nodes returned a different one
// between runs of the same input - which for a presentation meant the
// holder's key was sometimes checked against the ISSUER's proofValue, and
// a legitimate presentation failed intermittently.
//
// Determinism alone is not the fix, only the half of it that stops the
// flakiness. A caller that knows which proof it means must say so.
func FindProofNodeFunc(data any, proofType string, match func(map[string]any) bool) map[string]any {
	switch v := data.(type) {
	case map[string]any:
		if HasType(v, proofType) || HasType(v, "Proof") {
			if match == nil || match(v) {
				return v
			}
			// A proof node that is not the one asked for. Keep looking -
			// it may nest another (an embedded credential inside a
			// presentation's proof graph).
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

// MatchProofValue selects the proof node carrying exactly this proofValue.
//
// The proofValue is what identifies a proof unambiguously among several in
// one document: it is the signature itself, so a caller holding the proof
// it parsed out of the original JSON can name the same node in the
// RDF-derived, compacted form without relying on traversal order or on
// which graph it landed in.
func MatchProofValue(proofValue string) func(map[string]any) bool {
	return func(node map[string]any) bool {
		got, _ := node["proofValue"].(string)
		return got == proofValue
	}
}
