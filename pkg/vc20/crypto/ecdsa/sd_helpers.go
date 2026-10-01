package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/piprate/json-gold/ld"
)

func parseNQuads(nquads string) []string {
	if nquads == "" {
		return []string{}
	}
	lines := strings.Split(nquads, "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result
}

func parseQuadComponents(quad string) (string, string, string, string) {
	// Very basic N-Quad parser
	// Assumes canonical format (spaces separate components)
	// Subject Predicate Object Graph .
	// Note: Object can be a string with spaces.
	// But in canonical form, strings are escaped.
	// We can use regex or simple splitting if we are careful.

	// Better: use a proper RDF parser if available, but we are working with strings here.
	// For grouping, we just need to identify blank nodes.

	parts := strings.SplitN(quad, " ", 3)
	if len(parts) < 3 {
		return "", "", "", ""
	}
	s := parts[0]
	p := parts[1]
	rest := parts[2]

	// Object is tricky. It ends with " ." or " <graph> ."
	// But since we only care about blank nodes which are _:..., they don't contain spaces.
	// If object is a literal, it starts with ".

	var o string
	// If rest starts with ", parse until end of string
	// If rest starts with < or _:, parse until space

	if strings.HasPrefix(rest, "\"") {
		// Literal. Find the end of the literal.
		// This is hard without full parsing.
		// But we only need to check if it is a blank node.
		// Literals are NOT blank nodes.
		o = "LITERAL" // Placeholder
	} else {
		oParts := strings.SplitN(rest, " ", 2)
		o = oParts[0]
	}

	return s, p, o, ""
}

func skolemizeQuad(quad string, key []byte) string {
	// Replace all _:... with _:HMAC(...)
	// We need to find all occurrences of _:([a-zA-Z0-9]+)
	// and replace them.

	re := regexp.MustCompile(`_:[a-zA-Z0-9\-_]+`)
	return re.ReplaceAllStringFunc(quad, func(match string) string {
		// match is _:label
		label := match[2:]
		h := hmacSha256(key, []byte(label))
		// Per spec and Digital Bazaar: "u" prefix + base64url-encoded HMAC (no padding)
		// The "u" prefix makes the ID syntax-legal for blank nodes
		encoded := base64.RawURLEncoding.EncodeToString(h)
		return "_:u" + encoded
	})
}

// applyHMACLabelReplacement applies HMAC-based blank node label replacement to a slice of N-Quads.
// This matches the Digital Bazaar di-sd-primitives createHmacIdLabelMapFunction behavior.
func applyHMACLabelReplacement(quads []string, hmacKey []byte) []string {
	result := make([]string, len(quads))
	for i, quad := range quads {
		result[i] = skolemizeQuad(quad, hmacKey)
	}
	return result
}

func hmacSha256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func serializeSignature(r, s *big.Int, bits int) []byte {
	keyBytes := (bits + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	signature := make([]byte, 2*keyBytes)
	copy(signature[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(signature[2*keyBytes-len(sBytes):], sBytes)
	return signature
}

func ellipticMarshal(pub ecdsa.PublicKey) []byte {
	// Use standard uncompressed point serialization
	// 0x04 || x || y
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

// ellipticMarshalCompressed serializes a public key in compressed format with multicodec prefix.
// For P-256: 0x80 0x24 || compressed point (33 bytes)
func ellipticMarshalCompressed(pub ecdsa.PublicKey) []byte {
	// Get the compressed representation
	compressed := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	// Add multicodec prefix for P-256 (0x8024 as varint)
	result := make([]byte, 2+len(compressed))
	result[0] = 0x80
	result[1] = 0x24
	copy(result[2:], compressed)
	return result
}

// parseEphemeralPublicKey parses an ephemeral public key from the proof.
// The key may be in one of two formats:
// 1. Uncompressed: 0x04 || x || y (65 bytes for P-256)
// 2. Multicodec + compressed: 0x80 0x24 || compressed point (35 bytes for P-256)
func parseEphemeralPublicKey(data []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty public key data")
	}

	var x, y *big.Int

	// Check if it's multicodec + compressed format (P-256)
	if len(data) >= 2 && data[0] == 0x80 && data[1] == 0x24 {
		// P-256 multicodec prefix, compressed format
		keyData := data[2:]
		if len(keyData) != 33 {
			return nil, fmt.Errorf("invalid compressed P-256 key length: expected 33, got %d", len(keyData))
		}
		x, y = elliptic.UnmarshalCompressed(elliptic.P256(), keyData)
		if x == nil {
			return nil, fmt.Errorf("failed to unmarshal compressed P-256 point")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}

	// Check if it's multicodec + compressed format (P-384)
	if len(data) >= 2 && data[0] == 0x81 && data[1] == 0x24 {
		// P-384 multicodec prefix, compressed format
		keyData := data[2:]
		if len(keyData) != 49 {
			return nil, fmt.Errorf("invalid compressed P-384 key length: expected 49, got %d", len(keyData))
		}
		x, y = elliptic.UnmarshalCompressed(elliptic.P384(), keyData)
		if x == nil {
			return nil, fmt.Errorf("failed to unmarshal compressed P-384 point")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, nil
	}

	// Try uncompressed format: 0x04 || x || y
	if data[0] == 0x04 {
		x, y = elliptic.Unmarshal(curve, data)
		if x == nil {
			return nil, fmt.Errorf("failed to unmarshal uncompressed point")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}

	return nil, fmt.Errorf("unrecognized public key format: first byte 0x%02x", data[0])
}

func verifySignature(key *ecdsa.PublicKey, hash, signature []byte) bool {
	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keyBytes {
		return false
	}
	r := new(big.Int).SetBytes(signature[:keyBytes])
	s := new(big.Int).SetBytes(signature[keyBytes:])
	return ecdsa.Verify(key, hash, r, s)
}

func replaceURNs(data any) {
	if m, ok := data.(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				if strings.HasPrefix(s, "urn:bn:") {
					m[k] = "_:" + s[7:]
				}
			} else {
				replaceURNs(v)
			}
		}
	} else if list, ok := data.([]any); ok {
		for i, item := range list {
			if s, ok := item.(string); ok {
				if strings.HasPrefix(s, "urn:bn:") {
					list[i] = "_:" + s[7:]
				}
			} else {
				replaceURNs(item)
			}
		}
	}
}

func replaceLabelsWithURNs(data any, labelMap map[string]string) {
	if m, ok := data.(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				if strings.HasPrefix(s, "_:") {
					label := s[2:]
					if hmac, ok := labelMap[label]; ok {
						m[k] = fmt.Sprintf("urn:bn:%s", hmac)
					}
				}
			} else {
				replaceLabelsWithURNs(v, labelMap)
			}
		}
	} else if list, ok := data.([]any); ok {
		for i, item := range list {
			if s, ok := item.(string); ok {
				if strings.HasPrefix(s, "_:") {
					label := s[2:]
					if hmac, ok := labelMap[label]; ok {
						list[i] = fmt.Sprintf("urn:bn:%s", hmac)
					}
				}
			} else {
				replaceLabelsWithURNs(item, labelMap)
			}
		}
	}
}

func replaceURNsInNQuads(nquads string) string {
	// Replace <urn:bn:HMAC> with _:HMAC
	re := regexp.MustCompile(`<urn:bn:([^>]+)>`)
	return re.ReplaceAllString(nquads, "_:$1")
}

// removeRootProof deletes the proof the DOCUMENT attaches to itself, and
// leaves every nested proof alone. A nested credential's own proof is content
// the enclosing signature covers; removing it would take those quads out of
// the signed set and so out of the signature's reach.
//
// A top-level ARRAY is not a set of independent roots. RDFCredential's own
// JSON marshalling goes through FromRDF, which FLATTENS - every embedded node
// is lifted to that same array beside the document. Deleting proof keys from
// each entry would therefore strip exactly the nested proofs this is meant to
// preserve, and only after a round trip through RDF, so the compact path and
// the expanded path would disagree about what is signed.
//
// The root is identified the way credential.RootProofs identifies it: the node
// nothing else refers to. A document that holds no such node, or more than
// one, does not say what it is about and is REFUSED rather than guessed at.
//
// Which members ARE the proof is resolved through the document's context, not
// matched against a list of spellings - see credential.ProofKeys.
func removeRootProof(data any, options *ld.JsonLdOptions) (any, error) {
	// NO inherited context at the top: there is no enclosing scope, so a
	// top-level node's own context becomes the active one exactly once.
	// Seeding this with the document's context made that node's context
	// both the outer and the local one, and composing a context with
	// itself is not what JSON-LD does with it.
	return removeRootProofUnder(data, nil, options)
}

// removeRootProofUnder carries the context DOWN rather than recomputing it.
//
// A compacted graph container keeps its @context on the container alone, so
// recomputing after descending into @graph found none - and a proof written
// through an aliased term stopped being recognized, staying in a document
// that is supposed to be without it.
func removeRootProofUnder(data any, context any, options *ld.JsonLdOptions) (any, error) {
	// The graph NAMES the removed links pointed at. In flattened JSON-LD a
	// proof is a link to a named graph sitting beside the document, so
	// deleting the link alone leaves the proof's quads in a document that
	// is supposed to be without them - and verification then canonicalizes
	// proof quads no disclosed signature covers. RootProofs removes both;
	// so does this.
	var orphaned []string
	deleteProofKeys := func(m map[string]any, active any) {
		for _, key := range credential.ProofKeys(m, active, options) {
			orphaned = append(orphaned, graphNamesIn(m[key])...)
			delete(m, key)
		}
	}

	switch typed := data.(type) {
	case map[string]any:
		// A BARE container holds the nodes and is about none of them, so
		// the root is inside. A node that merely carries @graph beside
		// properties of its own is a named graph, and the node itself is
		// still what the document is about - reaching into its graph would
		// remove a proof this must not touch.
		if credential.IsBareGraphContainer(typed) {
			graph, err := removeRootProofUnder(typed["@graph"], contextFor(typed, context), options)
			if err != nil {
				return nil, err
			}
			typed["@graph"] = graph
			return typed, nil
		}
		deleteProofKeys(typed, contextFor(typed, context))
		return typed, nil
	case []any:
		// Graph WRAPPERS are not root candidates. RootProofs excludes them
		// when it selects a root, and an unreferenced named graph is
		// perfectly good secured content there - offering it here made the
		// same document ambiguous and SD signing and derivation fail on it.
		// They stay in the document; they just do not stand for it.
		nodes := make([]map[string]any, 0, len(typed))
		for _, entry := range typed {
			node, isNode := entry.(map[string]any)
			if !isNode || ld.IsGraph(node) {
				continue
			}
			nodes = append(nodes, node)
		}

		if len(nodes) == 1 {
			deleteProofKeys(nodes[0], contextFor(nodes[0], context))
			return withoutNamedGraphs(typed, orphaned), nil
		}

		selected, err := credential.RootOfCompactedNodes(nodes, context, options)
		if err != nil {
			return nil, err
		}

		// EVERY fragment of the selected root. Expanded JSON-LD may split
		// one node across several top-level entries; selection merges them
		// to decide, and the proof may be written on any of them - so the
		// merged copy is what says WHICH node, and the originals are what
		// has to be edited.
		//
		// The ROOT's own context, not whichever node happened to be first:
		// a flattened array may give each node its own, and reordering
		// top-level nodes does not change the RDF.
		rootID := credential.CompactNodeID(selected, context, options)

		var targets []map[string]any
		for _, node := range nodes {
			id := credential.CompactNodeID(node, context, options)
			if rootID != "" {
				if id == rootID {
					targets = append(targets, node)
				}
				continue
			}
			// An UNIDENTIFIED root cannot have been split across
			// fragments - fragments are joined by identifier - so exactly
			// one entry is it, and selection returned a clone of that one.
			if id == "" && reflect.DeepEqual(node, selected) {
				targets = append(targets, node)
			}
		}

		// INVARIANT CHECKS, not reachable paths: selection refuses a
		// document with two unidentified top-level nodes, and the node it
		// returns is a clone of one of these. They are here so that a
		// future change to selection cannot silently widen this removal -
		// which, applied to the wrong node or to all of them, is exactly
		// the embedded-proof stripping this change exists to prevent.
		// Removing from none is no better: the signature would then cover a
		// document the verifier does not reproduce.
		if len(targets) == 0 {
			return nil, fmt.Errorf("a document holds no entry for the node %q it is about", rootID)
		}
		if rootID == "" && len(targets) != 1 {
			return nil, fmt.Errorf("a document holds %d unidentified nodes indistinguishable from the one it is about, so whose proof is the root's cannot be decided", len(targets))
		}

		for _, node := range targets {
			deleteProofKeys(node, contextFor(node, context))
		}
		return withoutNamedGraphs(typed, orphaned), nil
	}
	return nil, fmt.Errorf("a document is %T rather than a node or a list of nodes", data)
}

// graphNamesIn reads the identifiers a removed proof link pointed at. A proof
// written INLINE names no graph and contributes none - it goes with the link.
func graphNamesIn(value any) []string {
	var names []string
	switch typed := value.(type) {
	case []any:
		for _, entry := range typed {
			names = append(names, graphNamesIn(entry)...)
		}
	case map[string]any:
		if _, inline := typed["@graph"]; inline {
			return nil
		}
		for _, key := range []string{"@id", "id"} {
			if id, ok := typed[key].(string); ok && id != "" {
				names = append(names, id)
			}
		}
	case string:
		if typed != "" {
			names = append(names, typed)
		}
	}
	return names
}

// withoutNamedGraphs drops the top-level graph entries a removed root proof
// named. Only graph WRAPPERS are candidates: an entry that merely shares an
// identifier is a node the document still talks about.
func withoutNamedGraphs(entries []any, names []string) []any {
	if len(names) == 0 {
		return entries
	}
	named := make(map[string]bool, len(names))
	for _, name := range names {
		named[name] = true
	}

	kept := make([]any, 0, len(entries))
	for _, entry := range entries {
		if node, isNode := entry.(map[string]any); isNode {
			// ld.IsGraph, not a key count: a graph object may carry @index
			// beside @graph and @id, and counting keys called an indexed
			// proof graph a document node.
			if ld.IsGraph(node) {
				id, _ := node["@id"].(string)
				if named[id] {
					continue
				}
			}
		}
		kept = append(kept, entry)
	}
	return kept
}

// contextFor is the context to resolve a NODE's members against: the one
// inherited from the enclosing scope, with the node's own applied on top.
//
// APPLIED ON TOP, not instead of. A node-local context adds to and overrides
// what is already active; returning only the node's own dropped outer
// definitions - an outer alias for the proof predicate among them - so
// removeRootProof could leave a root proof that RootProofs removes, and SD
// signing and derivation would hash different documents.
//
// An explicit null is the exception, because in JSON-LD it is a RESET: it
// clears what is active rather than adding to it.
func contextFor(node map[string]any, inherited any) any {
	own, present := node["@context"]
	if !present {
		return inherited
	}
	if own == nil {
		return nil
	}
	return credential.JoinContexts(inherited, own)
}

// parseJSONPointer parses a JSON pointer (RFC 6901) into path segments.
// For example, "/issuer" -> ["issuer"], "/credentialSubject/name" -> ["credentialSubject", "name"]
func parseJSONPointer(pointer string) []string {
	if pointer == "" || pointer == "/" {
		return []string{}
	}
	// Remove leading slash
	if strings.HasPrefix(pointer, "/") {
		pointer = pointer[1:]
	}
	// Split by /
	parts := strings.Split(pointer, "/")
	// Unescape ~1 -> / and ~0 -> ~
	for i, part := range parts {
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")
		parts[i] = part
	}
	return parts
}

// getValueAtPointer returns the value at the given JSON pointer path in a JSON-LD document.
// Returns nil if the path doesn't exist.
func getValueAtPointer(doc any, pointer string) any {
	parts := parseJSONPointer(pointer)
	if len(parts) == 0 {
		return doc
	}

	current := doc
	for _, part := range parts {
		switch v := current.(type) {
		case map[string]any:
			val, ok := v[part]
			if !ok {
				return nil
			}
			current = val
		case []any:
			// Try to parse part as array index
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(v) {
				return nil
			}
			current = v[idx]
		default:
			return nil
		}
	}
	return current
}

// selectMandatoryNQuads selects N-Quads from the canonicalized document that correspond
// to the mandatory JSON pointers. This implements the W3C spec's canonicalizeAndGroup
// and selectJsonLd functions, following Section 3.4.11 createInitialSelection:
//
// "The selection MUST include all `type`s in the path of any JSON Pointer,
// including any root document `type`."
//
// The algorithm works as follows:
// 1. Get the values at each mandatory pointer in the original JSON-LD
// 2. Match those values against N-Quads based on the predicate (from JSON-LD context)
// 3. Include the type(s) of all containers in the path (per spec)
// 4. Return the sorted set of matching N-Quads
func selectMandatoryNQuads(docJSON any, nquads []string, pointers []string) []string {
	if len(pointers) == 0 {
		return []string{}
	}

	// Map of common JSON-LD properties to their expanded predicate URIs
	// These are the predicates used in VC 2.0 context
	predicateMap := map[string][]string{
		"issuer":            {"<https://www.w3.org/2018/credentials#issuer>"},
		"validFrom":         {"<https://www.w3.org/2018/credentials#validFrom>"},
		"validUntil":        {"<https://www.w3.org/2018/credentials#validUntil>"},
		"type":              {"<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>"},
		"id":                {"@id"}, // Special case - represents subject IRI
		"credentialSubject": {"<https://www.w3.org/2018/credentials#credentialSubject>"},
	}

	mandatoryQuads := make(map[string]bool)

	// Per W3C spec Section 3.4.11 createInitialSelection:
	// "If source.type is set, set selection.type to its value."
	// This means we must include the root document's type in the selection.
	// Get the document's id (subject IRI) to find its type quads.
	var docSubject string
	if docMap, ok := docJSON.(map[string]any); ok {
		if id, ok := docMap["id"].(string); ok {
			docSubject = id
		}
	}

	// Track which container paths we've processed to include their types
	includedContainerTypes := make(map[string]bool)

	for _, pointer := range pointers {
		parts := parseJSONPointer(pointer)
		if len(parts) == 0 {
			continue
		}

		// Per spec: include types of all containers in the path
		// For a pointer like "/issuer" at the root, we need to include the root's type
		// For a pointer like "/credentialSubject/name", we need root type AND credentialSubject type
		if len(parts) > 0 && !includedContainerTypes[""] {
			// This pointer touches the root document, so include root's type(s)
			includedContainerTypes[""] = true
		}

		// Get the property name (last part of pointer for simple properties)
		propName := parts[len(parts)-1]

		// Get the value at this pointer
		value := getValueAtPointer(docJSON, pointer)
		if value == nil {
			continue
		}

		// Convert value to string for matching
		var valueStr string
		switch v := value.(type) {
		case string:
			valueStr = v
		case float64:
			valueStr = fmt.Sprintf("%v", v)
		case bool:
			valueStr = fmt.Sprintf("%v", v)
		default:
			// For complex objects, we might need to match by subject
			continue
		}

		// Find predicates for this property
		predicates, ok := predicateMap[propName]
		if !ok {
			// Try generic matching
			predicates = []string{fmt.Sprintf("<%s>", propName)}
		}

		// Search N-Quads for matches
		for _, quad := range nquads {
			for _, pred := range predicates {
				if strings.Contains(quad, pred) {
					// Check if the value also matches (for literals)
					// Value can be an IRI like <did:web:...> or a literal like "2025-..."
					if strings.Contains(quad, "<"+valueStr+">") ||
						strings.Contains(quad, "\""+valueStr+"\"") ||
						strings.Contains(quad, valueStr) {
						mandatoryQuads[quad] = true
					}
				}
			}
		}
	}

	// Now add the type quads for all containers we've marked
	// Per spec: "The selection MUST include all types in the path of any JSON Pointer"
	if includedContainerTypes[""] && docSubject != "" {
		// Add the root document's type quad(s)
		typePredicate := "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>"
		for _, quad := range nquads {
			// Check if this quad has the document subject and type predicate
			if strings.Contains(quad, "<"+docSubject+">") && strings.Contains(quad, typePredicate) {
				mandatoryQuads[quad] = true
			}
		}
	}

	// Convert to sorted slice
	result := make([]string, 0, len(mandatoryQuads))
	for quad := range mandatoryQuads {
		result = append(result, quad)
	}
	sort.Strings(result)
	return result
}
