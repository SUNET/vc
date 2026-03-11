package sdjwtvc

import (
	"crypto/sha256"
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

	// Get the _sd array for hash comparison
	var sdHashes []string
	if sdField, ok := claims["_sd"]; ok {
		if sdArray, ok := sdField.([]any); ok {
			for _, h := range sdArray {
				if hash, ok := h.(string); ok {
					sdHashes = append(sdHashes, hash)
				}
			}
		}
	}

	// Process disclosures and add disclosed claims to the claims map
	for _, disclosure := range disclosures {
		// Calculate hash of disclosure
		hash := sha256.Sum256([]byte(disclosure))
		hashB64 := base64.RawURLEncoding.EncodeToString(hash[:])

		// Check if this disclosure hash is in the _sd array
		if slices.Contains(sdHashes, hashB64) {
			// Decode the disclosure
			disclosureBytes, err := base64.RawURLEncoding.DecodeString(disclosure)
			if err != nil {
				return nil, fmt.Errorf("failed to decode disclosure: %w", err)
			}

			// Parse disclosure array [salt, claim_name, claim_value]
			var disclosureArray []any
			if err := json.Unmarshal(disclosureBytes, &disclosureArray); err != nil {
				return nil, fmt.Errorf("failed to unmarshal disclosure: %w", err)
			}

			if len(disclosureArray) >= 3 {
				claimName, ok := disclosureArray[1].(string)
				if !ok {
					return nil, fmt.Errorf("invalid claim name in disclosure")
				}
				claimValue := disclosureArray[2]

				// Add disclosed claim to claims map
				claims[claimName] = claimValue
			}
		}
	}

	// Remove _sd and _sd_alg from final claims (they're internal to SD-JWT)
	delete(claims, "_sd")
	delete(claims, "_sd_alg")

	return &ParsedCredential{
		Claims:      claims,
		Disclosures: disclosures,
		Header:      headerMap,
		Signature:   signature,
		KeyBinding:  keyBinding,
	}, nil
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
