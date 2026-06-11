package sdjwtvc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/PaesslerAG/jsonpath"
)

// ParsedCredential represents a parsed SD-JWT credential with claims and disclosures
type ParsedCredential struct {
	// Claims contains the credential claims (base JWT claims plus disclosed selective disclosures)
	Claims map[string]any
	// Disclosures contains the raw selective disclosure strings
	Disclosures []string
	// Header contains the JWT header
	Header map[string]any
	// Signature is the JWT signature
	Signature string
	// KeyBinding contains the key binding JWT parts if present
	KeyBinding []string
}

// Token represents an SD-JWT token string that can be split into components
type Token string

// Parse parses an SD-JWT token into credential claims and selective disclosures
// Returns the parsed credential with claims, disclosures, header, signature, and optional key binding
func (t Token) Parse() (*ParsedCredential, error) {
	header, body, signature, disclosures, keyBinding, err := t.Split()
	if err != nil {
		return nil, fmt.Errorf("failed to split token: %w", err)
	}

	// Decode and parse header
	headerBytes, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var headerMap map[string]any
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// Decode and parse body (JWT claims)
	bodyBytes, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode body: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(bodyBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Resolve all selective disclosures recursively (handles nested _sd arrays)
	if err := resolveDisclosuresRecursive(claims, disclosures); err != nil {
		return nil, err
	}

	// Remove any unresolved array element markers {"...": hash} left behind
	// when the wallet omits element disclosures from the token.
	cleanUnresolvedMarkers(claims)

	return &ParsedCredential{
		Claims:      claims,
		Disclosures: disclosures,
		Header:      headerMap,
		Signature:   signature,
		KeyBinding:  keyBinding,
	}, nil
}

// sdParsedDisclosure holds a parsed selective disclosure for resolution.
type sdParsedDisclosure struct {
	claimName  string
	claimValue any
	isArray    bool // true for array element disclosures [salt, value]
}

// resolveDisclosuresRecursive resolves selective disclosures at all levels of the claims map.
// It matches disclosure hashes against _sd arrays in nested objects and inserts the disclosed values.
// After processing, all _sd and _sd_alg keys are removed from the claims tree.
func resolveDisclosuresRecursive(claims map[string]any, disclosures []string) error {
	// Determine hash algorithm from _sd_alg claim (default: sha-256 per spec)
	sdAlg, _ := claims["_sd_alg"].(string)
	if sdAlg == "" {
		sdAlg = "sha-256"
	}
	hashMethod, err := getHashFromAlgorithm(sdAlg)
	if err != nil {
		return fmt.Errorf("unsupported _sd_alg %q: %w", sdAlg, err)
	}

	// Build a map of disclosure hash -> parsed disclosure for efficient lookup
	disclosureMap := make(map[string]*sdParsedDisclosure, len(disclosures))
	for _, disclosure := range disclosures {
		hashMethod.Reset()
		hashMethod.Write([]byte(disclosure))
		hashB64 := base64.RawURLEncoding.EncodeToString(hashMethod.Sum(nil))

		disclosureBytes, err := base64.RawURLEncoding.DecodeString(disclosure)
		if err != nil {
			return fmt.Errorf("failed to base64url-decode disclosure: %w", err)
		}

		var disclosureArray []any
		if err := json.Unmarshal(disclosureBytes, &disclosureArray); err != nil {
			return fmt.Errorf("failed to unmarshal disclosure JSON: %w", err)
		}

		switch len(disclosureArray) {
		case 2:
			// Array element disclosure: [salt, value]
			disclosureMap[hashB64] = &sdParsedDisclosure{
				claimValue: disclosureArray[1],
				isArray:    true,
			}
		case 3:
			// Object property disclosure: [salt, claim_name, claim_value]
			claimName, ok := disclosureArray[1].(string)
			if !ok {
				return fmt.Errorf("invalid disclosure: claim name must be a string, got %T", disclosureArray[1])
			}
			disclosureMap[hashB64] = &sdParsedDisclosure{
				claimName:  claimName,
				claimValue: disclosureArray[2],
			}
		default:
			return fmt.Errorf("invalid disclosure format: expected 2 or 3 elements, got %d", len(disclosureArray))
		}
	}

	// Recursively resolve _sd arrays in the claims tree
	resolveNode(claims, disclosureMap)
	return nil
}

// resolveNode processes a single map node, resolving its _sd array and recursing into nested maps.
func resolveNode(node map[string]any, disclosureMap map[string]*sdParsedDisclosure) {
	// Resolve _sd array at this level
	if sdField, ok := node["_sd"]; ok {
		if sdArray, ok := sdField.([]any); ok {
			for _, h := range sdArray {
				hashStr, ok := h.(string)
				if !ok {
					continue
				}
				if pd, found := disclosureMap[hashStr]; found && !pd.isArray {
					node[pd.claimName] = pd.claimValue
				}
			}
		}
	}

	// Remove _sd and _sd_alg from this level
	delete(node, "_sd")
	delete(node, "_sd_alg")

	// Collect keys first to avoid issues with map iteration after modification.
	// New keys added during _sd resolution above must be included.
	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}

	// Recurse into nested maps and resolve array elements
	for _, key := range keys {
		value := node[key]
		switch v := value.(type) {
		case map[string]any:
			resolveNode(v, disclosureMap)
		case []any:
			node[key] = resolveArrayNode(v, disclosureMap)
		}
	}
}

// resolveArrayNode processes an array, resolving any SD-JWT array element disclosures
// (objects with a single "..." key containing a hash) and recursing into nested maps.
func resolveArrayNode(arr []any, disclosureMap map[string]*sdParsedDisclosure) []any {
	result := make([]any, 0, len(arr))
	for _, elem := range arr {
		switch v := elem.(type) {
		case map[string]any:
			// Check if this is an array element disclosure marker {"...": "<hash>"}
			if len(v) == 1 {
				if hashVal, ok := v["..."]; ok {
					if hashStr, ok := hashVal.(string); ok {
						if pd, found := disclosureMap[hashStr]; found && pd.isArray {
							// Recurse into the disclosed value in case it
							// contains nested _sd or array markers.
							switch dv := pd.claimValue.(type) {
							case map[string]any:
								resolveNode(dv, disclosureMap)
								result = append(result, dv)
							case []any:
								result = append(result, resolveArrayNode(dv, disclosureMap))
							default:
								result = append(result, pd.claimValue)
							}
							continue
						}
					}
				}
			}
			// Regular nested object — recurse
			resolveNode(v, disclosureMap)
			result = append(result, v)
		case []any:
			result = append(result, resolveArrayNode(v, disclosureMap))
		default:
			result = append(result, elem)
		}
	}
	return result
}

// cleanUnresolvedMarkers removes leftover {"...": hash} array element markers
// from the claims tree. These remain when the wallet discloses a claim whose
// value contains array element markers but doesn't include the corresponding
// element disclosures in the token.
func cleanUnresolvedMarkers(node map[string]any) {
	for key, value := range node {
		switch v := value.(type) {
		case map[string]any:
			cleanUnresolvedMarkers(v)
		case []any:
			node[key] = cleanArrayMarkers(v)
		}
	}
}

func cleanArrayMarkers(arr []any) []any {
	result := make([]any, 0, len(arr))
	for _, elem := range arr {
		switch v := elem.(type) {
		case map[string]any:
			if len(v) == 1 {
				if _, isMarker := v["..."]; isMarker {
					// Skip unresolved marker
					continue
				}
			}
			cleanUnresolvedMarkers(v)
			result = append(result, v)
		case []any:
			result = append(result, cleanArrayMarkers(v))
		default:
			result = append(result, elem)
		}
	}
	return result
}

// Split splits the token into header, body, signature, selective disclosure, keybinding, or error
func (t Token) Split() (string, string, string, []string, []string, error) {
	token := string(t)
	if token == "" {
		return "", "", "", nil, nil, errors.New("empty token")
	}

	parts := strings.Split(token, "~")
	if len(parts) == 0 {
		return "", "", "", nil, nil, errors.New("invalid token format")
	}

	sdToken := parts[0]
	jwtParts := strings.Split(sdToken, ".")
	if len(jwtParts) != 3 {
		return "", "", "", nil, nil, errors.New("invalid JWT format: must have 3 parts (header.payload.signature)")
	}

	header := jwtParts[0]
	body := jwtParts[1]
	signature := jwtParts[2]

	selectiveDisclosure := []string{}
	if len(parts) > 1 {
		selectiveDisclosure = parts[1 : len(parts)-1]
	}

	var keybindingList []string
	if len(parts) > 1 {
		keybinding := parts[len(parts)-1:]
		keybindingList = strings.Split(keybinding[0], ".")
		if slices.Contains(keybindingList, "") {
			keybindingList = nil
		}
	}

	return header, body, signature, selectiveDisclosure, keybindingList, nil
}

// Base64Decode decodes a base64url-encoded string to a string
func Base64Decode(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// ExtractClaimsByJSONPath extracts specific claim values from document data using JSONPath queries.
// Takes a map of label->JSONPath expressions and returns a map of label->extracted values.
// Example: {"given-name": "$.name.given"} extracts the value at path $.name.given and maps it to "given-name".
// Paths that do not match any value in the document data are silently skipped.
func ExtractClaimsByJSONPath(documentData map[string]any, jsonPathMap map[string]string) (map[string]any, error) {
	v := any(nil)

	b, err := json.Marshal(documentData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal document data: %w", err)
	}

	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document data: %w", err)
	}

	reply := map[string]any{}

	for key, path := range jsonPathMap {
		result, err := jsonpath.Get(path, v)
		if err != nil {
			// Path not found in document data — skip it.
			continue
		}

		reply[key] = result
	}

	return reply, nil
}

// ParseSelectiveDisclosure parses selective disclosure strings and returns a slice of Discloser objects.
// Each disclosure is a base64url-encoded JSON array containing either:
// - [salt, claim_name, claim_value] for object properties
// - [salt, claim_value] for array elements
// Returns a slice of Discloser objects representing the disclosed claims.
// Example: ["WyJzYWx0IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"] -> []Discloser{{Salt: "salt", ClaimName: "given_name", Value: "John"}}
func ParseSelectiveDisclosure(selectiveDisclosure []string) ([]Discloser, error) {
	if selectiveDisclosure == nil {
		return nil, errors.New("selective disclosure array is nil")
	}

	disclosers := make([]Discloser, 0, len(selectiveDisclosure))

	for i, disclosure := range selectiveDisclosure {
		if disclosure == "" {
			return nil, fmt.Errorf("disclosure at index %d is empty", i)
		}

		// Decode the base64url-encoded disclosure
		disclosureBytes, err := base64.RawURLEncoding.DecodeString(disclosure)
		if err != nil {
			return nil, fmt.Errorf("failed to decode disclosure at index %d: %w", i, err)
		}

		// Parse disclosure array
		var disclosureArray []any
		if err := json.Unmarshal(disclosureBytes, &disclosureArray); err != nil {
			return nil, fmt.Errorf("failed to unmarshal disclosure at index %d: %w", i, err)
		}

		// Validate disclosure array has at least 2 elements (for array elements)
		if len(disclosureArray) < 2 {
			return nil, fmt.Errorf("disclosure at index %d has invalid format: expected at least 2 elements, got %d", i, len(disclosureArray))
		}

		// Extract salt (first element)
		salt, ok := disclosureArray[0].(string)
		if !ok {
			return nil, fmt.Errorf("disclosure at index %d has invalid salt: expected string, got %T", i, disclosureArray[0])
		}

		var discloser Discloser

		// Check if this is an array element disclosure (2 elements) or object property disclosure (3+ elements)
		if len(disclosureArray) == 2 {
			// Array element disclosure: [salt, value]
			discloser = Discloser{
				Salt:      salt,
				ClaimName: "", // Empty for array elements
				Value:     disclosureArray[1],
				IsArray:   true,
			}
		} else {
			// Object property disclosure: [salt, claim_name, value]
			claimName, ok := disclosureArray[1].(string)
			if !ok {
				return nil, fmt.Errorf("disclosure at index %d has invalid claim name: expected string, got %T", i, disclosureArray[1])
			}

			discloser = Discloser{
				Salt:      salt,
				ClaimName: claimName,
				Value:     disclosureArray[2],
				IsArray:   false,
			}
		}

		disclosers = append(disclosers, discloser)
	}

	return disclosers, nil
}
