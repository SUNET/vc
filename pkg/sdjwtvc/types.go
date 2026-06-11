package sdjwtvc

import (
	"encoding/base64"
	"encoding/json"
	"hash"
)

// Discloser represents a selective disclosure element per SD-JWT draft-22
// Used to create Disclosures for selectively disclosable claims
// See: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/
type Discloser struct {
	Salt      string `json:"-"`
	ClaimName string `json:"claim_name"` // Empty for array elements
	Value     any    `json:"value"`
	IsArray   bool   `json:"-"` // True for array element disclosures
}

// Hash returns the hash of the discloser and its base64 representation
// Per draft-22 section 4.2.3: hash the base64url-encoded Disclosure
func (d *Discloser) Hash(hasher hash.Hash) (string, string, []any, error) {
	var disclosureArray []any

	// Per section 4.2.1 for object properties: [salt, claim_name, value]
	// Per section 4.2.2 for array elements: [salt, value]
	if d.IsArray {
		disclosureArray = []any{d.Salt, d.Value}
	} else {
		disclosureArray = []any{d.Salt, d.ClaimName, d.Value}
	}

	// Marshal to JSON
	disclosureBytes, err := json.Marshal(disclosureArray)
	if err != nil {
		return "", "", nil, err
	}

	// Base64url-encode the JSON
	selectiveDisclosure := base64.RawURLEncoding.EncodeToString(disclosureBytes)

	// Reset hasher to ensure clean state
	hasher.Reset()

	// Hash the base64url-encoded disclosure
	// Per section 4.2.3: "The input to the hash function MUST be the base64url-encoded Disclosure"
	_, err = hasher.Write([]byte(selectiveDisclosure))
	if err != nil {
		return "", "", nil, err
	}

	// Base64url-encode the hash digest
	hashed := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	return hashed, selectiveDisclosure, disclosureArray, nil
}

// CredentialCache holds credential claims and data
type CredentialCache struct {
	Scope      string         `json:"scope"`
	Claims     []Discloser    `json:"claims"`
	Credential map[string]any `json:"credential"`
}
