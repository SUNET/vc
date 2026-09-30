package eddsa

import (
	"encoding/json"

	"github.com/SUNET/vc/pkg/vc20/credential"
)

// Expanded JSON-LD predicate IRIs. A credential re-parsed from MarshalJSON
// output names its members this way rather than by compact term.
const (
	expandedProofIRI                = "https://w3id.org/security#proof"
	expandedProofValueIRI           = "https://w3id.org/security#proofValue"
	expandedVerifiableCredentialIRI = "https://www.w3.org/2018/credentials#verifiableCredential"
)

// rootProofValues returns the proofValues of the proofs the document
// attaches to ITSELF, read from the document as the caller passed it.
//
// This is what decides which proof gets verified, and it has to come from
// the document rather than from the proof object, because the proof object
// has lost the parentage: ProofObject() keeps proof quads and drops the
// links that say whose proof is whose.
//
// Without it, "the first proof found" is not merely arbitrary, it is
// forgeable. Verify removes EVERY proof when hashing, so a proof moved from
// the presentation onto the embedded credential leaves the hash unchanged -
// someone holding a legitimately signed presentation could move the holder
// proof onto the credential, delete the presentation's own proof, and have
// the misplaced proof verify with the holder's key against a document the
// holder never signed in that shape.
//
// An empty result means the document attaches no proof to itself, and the
// caller must refuse: not "fall back to whatever is in there".
func rootProofValues(cred *credential.RDFCredential) []string {
	originalJSON := cred.OriginalJSON()
	if originalJSON == "" {
		return nil
	}

	var raw any
	if err := json.Unmarshal([]byte(originalJSON), &raw); err != nil {
		return nil
	}

	switch doc := raw.(type) {
	case map[string]any:
		return compactRootProofValues(doc)
	case []any:
		return expandedRootProofValues(doc)
	default:
		return nil
	}
}

// compactRootProofValues reads proofValue from a compact document's own
// "proof" member, which may be one proof or several.
func compactRootProofValues(doc map[string]any) []string {
	var out []string
	for _, entry := range asSlice(doc["proof"]) {
		proof, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if value, ok := proof["proofValue"].(string); ok && value != "" {
			out = append(out, value)
		}
	}
	return out
}

// expandedRootProofValues reads them from an expanded document, where the
// root is a node nothing else embeds and its proof lives in a named graph.
//
// The root is identified by ELIMINATION rather than by having an id: an
// expanded presentation's nodes are a flat list, and an embedded credential
// is exactly the node another node names under verifiableCredential. A
// blank-node root is therefore still identifiable, which matters because a
// presentation is not required to have an id.
func expandedRootProofValues(nodes []any) []string {
	byID := make(map[string]map[string]any)
	embedded := make(map[string]bool)
	for _, entry := range nodes {
		node, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := node["@id"].(string); ok {
			byID[id] = node
		}
		for _, ref := range asSlice(node[expandedVerifiableCredentialIRI]) {
			if id := expandedID(ref); id != "" {
				embedded[id] = true
			}
		}
	}

	var out []string
	for id, node := range byID {
		if embedded[id] {
			continue
		}
		for _, ref := range asSlice(node[expandedProofIRI]) {
			graphID := expandedID(ref)
			if graphID == "" {
				continue
			}
			graph, ok := byID[graphID]
			if !ok {
				continue
			}
			out = append(out, expandedGraphProofValues(graph)...)
		}
	}
	return out
}

// expandedGraphProofValues reads every proofValue out of a named graph.
func expandedGraphProofValues(graph map[string]any) []string {
	var out []string
	for _, entry := range asSlice(graph["@graph"]) {
		node, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		for _, v := range asSlice(node[expandedProofValueIRI]) {
			value, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if s, ok := value["@value"].(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// expandedID reads an @id out of a JSON-LD node reference.
func expandedID(v any) string {
	switch ref := v.(type) {
	case string:
		return ref
	case map[string]any:
		id, _ := ref["@id"].(string)
		return id
	}
	return ""
}

// asSlice normalises a JSON-LD member that may be one value or a list.
func asSlice(v any) []any {
	if v == nil {
		return nil
	}
	if list, ok := v.([]any); ok {
		return list
	}
	return []any{v}
}
