package sdjwtvc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
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
	Claims     []Discloser    `json:"claims"`
	Credential map[string]any `json:"credential"`
}

// VCTM is the Verifiable Credential Type Metadata per SD-JWT VC draft-13 section 6.
// Type Metadata provides information about credential types including:
// - Display properties for rendering credentials in wallets
// - Claim metadata for validation and selective disclosure rules
// - Extensibility through the extends mechanism
// This enables issuers, verifiers, and wallets to process credentials consistently.
type VCTM struct {
	// VCT is the verifiable credential type identifier (REQUIRED per section 6.2)
	// Must match the vct claim value in the SD-JWT VC
	VCT string `json:"vct"`

	// Name is a human-readable name for developers (OPTIONAL per section 6.2)
	Name string `json:"name,omitempty"`

	// Description is a human-readable description for developers (OPTIONAL per section 6.2)
	Description string `json:"description,omitempty"`

	// Comment allows for additional developer notes (extension)
	Comment string `json:"$comment,omitempty"`

	// Display contains rendering information per section 8
	// Array of display objects for different locales (OPTIONAL per section 6.2)
	Display []VCTMDisplay `json:"display,omitempty"`

	// Claims contains claim metadata per section 9
	// Array of claim information for validation and display (OPTIONAL per section 6.2)
	Claims []Claim `json:"claims,omitempty"`

	// Extends references another type that this type extends (OPTIONAL per section 6.4)
	// URI of the parent type metadata
	Extends string `json:"extends,omitempty"`

	// ExtendsIntegrity provides integrity protection per section 7
	// Uses Subresource Integrity format (OPTIONAL)
	ExtendsIntegrity string `json:"extends#integrity,omitempty"`
}

// SRIIntegrity computes the Subresource Integrity (SRI) hash of the VCTM document
// as defined in W3C SRI spec and SD-JWT VC draft-14 Section 6.
// The rawBytes parameter should be the original VCTM document bytes (not re-marshalled)
// to preserve exact byte-level integrity.
// If rawBytes is nil, the VCTM is marshalled to JSON.
// Returns a string like "sha256-<base64-hash>".
func (v *VCTM) SRIIntegrity(rawBytes []byte) (string, error) {
	if rawBytes == nil {
		var err error
		rawBytes, err = json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("failed to marshal VCTM for integrity hash: %w", err)
		}
	}
	h := sha256.Sum256(rawBytes)
	encoded := base64.StdEncoding.EncodeToString(h[:])
	return "sha256-" + encoded, nil
}

// Attributes parse vctm claims and return a map of labels and their paths for each locale
func (v *VCTM) Attributes() map[string]map[string][]string {
	reply := map[string]map[string][]string{}

	for _, c := range v.Claims {
		for _, d := range c.Display {
			if _, ok := reply[d.Locale]; !ok {
				reply[d.Locale] = map[string][]string{}
			}

			label := d.Label

			for _, p := range c.Path {
				if p != nil {
					reply[d.Locale][label] = append(reply[d.Locale][label], *p)
				}
			}
		}
	}

	return reply
}

// AttributesWithoutObjects parse vctm claims and return a map of labels and their paths for each locale,
// excluding claims that represent objects (claims with nested paths)
func (v *VCTM) AttributesWithoutObjects() map[string]map[string][]string {
	reply := map[string]map[string][]string{}

	for _, c := range v.Claims {
		// Skip claims that are objects (have more than one path element)
		if len(c.Path) > 1 {
			continue
		}

		// Skip claims without display information (not relevant for display)
		if len(c.Display) == 0 {
			continue
		}

		for _, d := range c.Display {
			if _, ok := reply[d.Locale]; !ok {
				reply[d.Locale] = map[string][]string{}
			}

			label := d.Label

			for _, p := range c.Path {
				if p != nil {
					reply[d.Locale][label] = append(reply[d.Locale][label], *p)
				}
			}
		}
	}

	return reply
}

// ClaimJSONPath returns the JSON paths for the VCTM claims
func (v *VCTM) ClaimJSONPath() (*VCTMJSONPath, error) {
	if v.Claims == nil {
		return nil, fmt.Errorf("claims are nil")
	}

	reply := &VCTMJSONPath{
		Displayable: map[string]string{},
		AllClaims:   []string{},
	}

	for _, claim := range v.Claims {
		if claim.SVGID != "" {
			reply.Displayable[claim.SVGID] = claim.JSONPath()
		}
		reply.AllClaims = append(reply.AllClaims, claim.JSONPath())
	}

	return reply, nil
}

// VCTMDisplay represents display information for a credential type per SD-JWT VC draft-13 section 8
// Each display object provides locale-specific rendering information for wallets
type VCTMDisplay struct {
	// Locale is the language tag per RFC 5646 (REQUIRED per section 8)
	// Per draft-12+ this field is named "locale" in JSON (changed from "lang" in earlier drafts)
	Locale string `json:"locale"`

	// Name is a human-readable name for end users (REQUIRED per section 8)
	Name string `json:"name"`

	// Description is a human-readable description for end users (OPTIONAL per section 8)
	Description string `json:"description,omitempty"`

	// Rendering contains rendering methods per section 8.1 (OPTIONAL)
	Rendering *Rendering `json:"rendering,omitempty"`
}

// Rendering contains rendering methods for credential display per SD-JWT VC draft-13 section 8.1
// Supports multiple rendering methods (simple, SVG templates)
type Rendering struct {
	// Simple contains basic rendering properties per section 8.1.1 (OPTIONAL)
	// Used for applications that don't support SVG rendering
	Simple SimpleRendering `json:"simple"`

	// SVGTemplates contains SVG-based rendering per section 8.1.2 (OPTIONAL)
	// Array of SVG templates with different properties (landscape/portrait, light/dark, etc.)
	SVGTemplates []SVGTemplates `json:"svg_templates,omitempty"`
}

// SimpleRendering provides basic rendering properties per section 8.1.1
// Intended for applications that don't support SVG rendering
type SimpleRendering struct {
	// Logo contains logo information (OPTIONAL per section 8.1.1.1)
	Logo Logo `json:"logo"`

	// BackgroundImage contains background image information (OPTIONAL per section 8.1.1.2)
	BackgroundImage *Logo `json:"background_image,omitempty"`

	// BackgroundColor is an RGB color value per W3C CSS Color (OPTIONAL per section 8.1.1)
	BackgroundColor string `json:"background_color,omitempty"`

	// TextColor is an RGB color value per W3C CSS Color (OPTIONAL per section 8.1.1)
	TextColor string `json:"text_color,omitempty"`
}

// Logo contains logo or image information per section 8.1.1.1 and 8.1.1.2
type Logo struct {
	// URI pointing to the image (REQUIRED)
	URI string `json:"uri"`

	// URIIntegrity provides Subresource Integrity protection per section 7 (OPTIONAL)
	URIIntegrity string `json:"uri#integrity,omitempty"`

	// AltText is alternative text for the image (OPTIONAL)
	AltText string `json:"alt_text,omitempty"`
}

// SVGTemplates contains SVG template information per section 8.1.2
type SVGTemplates struct {
	// URI pointing to the SVG template (REQUIRED)
	URI string `json:"uri"`

	// URLIntegrity provides Subresource Integrity protection per section 7 (OPTIONAL)
	// Note: Field name uses "URL" but JSON uses "uri#integrity" to match spec
	URLIntegrity string `json:"uri#integrity,omitempty"`

	// Properties specifies template properties per section 8.1.2.1 (OPTIONAL for single template, REQUIRED for multiple)
	Properties SVGTemplateProperties `json:"properties"`
}

// SVGTemplateProperties specifies SVG template characteristics per section 8.1.2.1
// Used to select the best template for display based on device and user preferences
type SVGTemplateProperties struct {
	// Orientation: "portrait" or "landscape" (OPTIONAL)
	Orientation string `json:"orientation,omitempty"`

	// ColorScheme: "light" or "dark" (OPTIONAL)
	ColorScheme string `json:"color_scheme,omitempty"`

	// Contrast: "normal" or "high" (OPTIONAL)
	Contrast string `json:"contrast,omitempty"`
}

// Claim represents credential claim metadata per SD-JWT VC draft-13 section 9
// Provides information for displaying and validating claims
type Claim struct {
	// Path indicates the claim(s) being addressed per section 9.1 (REQUIRED)
	// Array of strings, null values, or non-negative integers
	// - string: select key in object
	// - null: select all elements in array
	// - integer: select specific array index
	Path []*string `json:"path"`

	// Display contains locale-specific display information per section 9.2 (OPTIONAL)
	Display []ClaimDisplay `json:"display,omitempty"`

	// SD indicates selective disclosure rules per section 9.4 (OPTIONAL, default: "allowed")
	// Values: "always", "allowed", "never"
	// - "always": Issuer MUST make the claim selectively disclosable
	// - "allowed": Issuer MAY make the claim selectively disclosable
	// - "never": Issuer MUST NOT make the claim selectively disclosable
	// It is RECOMMENDED to use either "always" or "never" to avoid ambiguity.
	SD string `json:"sd,omitempty"`

	// Mandatory indicates if claim must be present per section 9.3 (OPTIONAL, default: false)
	Mandatory bool `json:"mandatory,omitempty"`

	// SVGID is the identifier for SVG template placeholders per section 8.1.2.2 (OPTIONAL)
	// Must be unique, alphanumeric + underscores, cannot start with digit
	SVGID string `json:"svg_id,omitempty"`
}

// JSONPath returns the JSON path for the claim
func (c *Claim) JSONPath() string {
	if c == nil || c.Path == nil {
		return ""
	}

	reply := "$."
	for _, path := range c.Path {
		reply += fmt.Sprintf("%s.", *path)
	}

	reply = strings.TrimRight(reply, ".")
	return reply
}

// ClaimDisplay provides locale-specific claim display information per SD-JWT VC draft-13 section 9.2
type ClaimDisplay struct {
	// Locale is the language tag per RFC 5646 (REQUIRED)
	// Per draft-12+ this field is named "locale" in JSON (changed from "lang" in earlier drafts)
	Locale string `json:"locale"`

	// Label is a human-readable label for end users (REQUIRED)
	Label string `json:"label"`

	// Description is a human-readable description for end users (OPTIONAL)
	Description string `json:"description,omitempty"`
}

// VCTMJSONPath holds JSON path information for VCTM claims
type VCTMJSONPath struct {
	Displayable map[string]string `json:"displayable"`
	AllClaims   []string          `json:"all_claims"`
}
