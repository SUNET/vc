package sdjwtvc

// VCTM is the Verifiable Credential Type Metadata per SD-JWT VC draft-13 section 6.
// Type Metadata provides information about credential types including:
// - Display properties for rendering credentials in wallets
// - Claim metadata for validation and selective disclosure rules
// - Extensibility through the extends mechanism
// This enables issuers, verifiers, and wallets to process credentials consistently.
type VCTM struct {
	// VCT is the verifiable credential type identifier (REQUIRED per section 6.2).
	// Must match the vct claim value in the SD-JWT VC.
	VCT string `json:"vct" bson:"vct" validate:"required"`

	// Name is a human-readable name for developers (OPTIONAL per section 6.2).
	Name string `json:"name,omitempty" bson:"name,omitempty"`

	// Description is a human-readable description for developers (OPTIONAL per section 6.2).
	Description string `json:"description,omitempty" bson:"description,omitempty"`

	// Comment allows for additional developer notes (extension).
	Comment string `json:"$comment,omitempty" bson:"comment,omitempty"`

	// Display contains rendering information per section 8.
	// Array of display objects for different locales (OPTIONAL per section 6.2).
	Display []VCTMDisplay `json:"display,omitempty" bson:"display,omitempty" validate:"omitempty,dive"`

	// Claims contains claim metadata per section 9.
	// Array of claim information for validation and display (OPTIONAL per section 6.2).
	Claims []Claim `json:"claims,omitempty" bson:"claims,omitempty" validate:"omitempty,dive"`

	// Extends references another type that this type extends (OPTIONAL per section 6.4).
	// URI of the parent type metadata.
	Extends string `json:"extends,omitempty" bson:"extends,omitempty" validate:"omitempty,url"`

	// ExtendsIntegrity provides integrity protection per section 7.
	// Uses Subresource Integrity format (OPTIONAL).
	ExtendsIntegrity string `json:"extends#integrity,omitempty" bson:"extends_integrity,omitempty"`

	// SchemaURI references a JSON Schema for the credential (OPTIONAL per section 6.3).
	SchemaURI string `json:"schema_uri,omitempty" bson:"schema_uri,omitempty" validate:"omitempty,url"`

	// SchemaIntegrity provides integrity protection for SchemaURI per section 7.
	SchemaIntegrity string `json:"schema_uri#integrity,omitempty" bson:"schema_uri_integrity,omitempty"`
}

// SVGValue holds a resolved claim for SVG template rendering.
type SVGValue struct {
	Label string `json:"label"`
	Value any    `json:"value"`
}

// VCTMJSONPath holds JSON path information for VCTM claims
type VCTMJSONPath struct {
	Displayable map[string]string `json:"displayable"`
	AllClaims   []string          `json:"all_claims"`
}

// VCTMDisplay represents display information for a credential type per section 8.
// Each display object provides locale-specific rendering information for wallets.
type VCTMDisplay struct {
	// Locale is the language tag per RFC 5646 (REQUIRED per section 8).
	Locale string `json:"locale" bson:"locale" validate:"required,bcp47_language_tag"`

	// Name is a human-readable name for end users (REQUIRED per section 8).
	Name string `json:"name" bson:"name" validate:"required"`

	// Description is a human-readable description for end users (OPTIONAL per section 8).
	Description string `json:"description,omitempty" bson:"description,omitempty"`

	// Rendering contains rendering methods per section 8.1 (OPTIONAL).
	Rendering *Rendering `json:"rendering,omitempty" bson:"rendering,omitempty" validate:"omitempty"`
}

// Rendering contains rendering methods for credential display per section 8.1.
type Rendering struct {
	// Simple contains basic rendering properties per section 8.1.1 (OPTIONAL).
	Simple *SimpleRendering `json:"simple,omitempty" bson:"simple,omitempty" validate:"omitempty"`

	// SVGTemplates contains SVG-based rendering per section 8.1.2 (OPTIONAL).
	SVGTemplates []SVGTemplates `json:"svg_templates,omitempty" bson:"svg_templates,omitempty" validate:"omitempty,dive"`
}

// SimpleRendering provides basic rendering properties per section 8.1.1.
type SimpleRendering struct {
	// Logo contains logo information (OPTIONAL per section 8.1.1.1).
	Logo *Logo `json:"logo,omitempty" bson:"logo,omitempty" validate:"omitempty"`

	// BackgroundImage contains background image information (OPTIONAL per section 8.1.1.2).
	BackgroundImage *Logo `json:"background_image,omitempty" bson:"background_image,omitempty" validate:"omitempty"`

	// BackgroundColor is an RGB color value per W3C CSS Color (OPTIONAL per section 8.1.1).
	BackgroundColor string `json:"background_color,omitempty" bson:"background_color,omitempty"`

	// TextColor is an RGB color value per W3C CSS Color (OPTIONAL per section 8.1.1).
	TextColor string `json:"text_color,omitempty" bson:"text_color,omitempty"`
}

// Logo contains logo or image information per section 8.1.1.1 and 8.1.1.2.
type Logo struct {
	// URI pointing to the image (REQUIRED).
	URI string `json:"uri" bson:"uri" validate:"required,url"`

	// URIIntegrity provides Subresource Integrity protection per section 7 (OPTIONAL).
	URIIntegrity string `json:"uri#integrity,omitempty" bson:"uri_integrity,omitempty"`

	// AltText is alternative text for the image (OPTIONAL).
	AltText string `json:"alt_text,omitempty" bson:"alt_text,omitempty"`
}

// SVGTemplates contains SVG template information per section 8.1.2.
type SVGTemplates struct {
	// URI pointing to the SVG template (REQUIRED).
	URI string `json:"uri" bson:"uri" validate:"required,url"`

	// URIIntegrity provides Subresource Integrity protection per section 7 (OPTIONAL).
	URIIntegrity string `json:"uri#integrity,omitempty" bson:"uri_integrity,omitempty"`

	// Properties specifies template properties per section 8.1.2.1 (OPTIONAL).
	Properties *SVGTemplateProperties `json:"properties,omitempty" bson:"properties,omitempty" validate:"omitempty"`
}

// SVGTemplateProperties specifies SVG template characteristics per section 8.1.2.1.
type SVGTemplateProperties struct {
	// Orientation: "portrait" or "landscape" (OPTIONAL).
	Orientation string `json:"orientation,omitempty" bson:"orientation,omitempty" validate:"omitempty,oneof=landscape portrait"`

	// ColorScheme: "light" or "dark" (OPTIONAL).
	ColorScheme string `json:"color_scheme,omitempty" bson:"color_scheme,omitempty" validate:"omitempty,oneof=light dark"`

	// Contrast: "normal" or "high" (OPTIONAL).
	Contrast string `json:"contrast,omitempty" bson:"contrast,omitempty" validate:"omitempty,oneof=normal high"`
}

// Claim represents credential claim metadata per section 9.
type Claim struct {
	// Path indicates the claim(s) being addressed per section 9.1 (REQUIRED).
	// Elements: string selects a key, nil selects all array elements.
	Path []*string `json:"path" bson:"path" validate:"required,min=1"`

	// Display contains locale-specific display information per section 9.2 (OPTIONAL).
	Display []ClaimDisplay `json:"display,omitempty" bson:"display,omitempty" validate:"omitempty,dive"`

	// SD indicates selective disclosure rules per section 9.4 (OPTIONAL, default: "allowed").
	// Values: "always", "allowed", "never".
	SD string `json:"sd,omitempty" bson:"sd,omitempty" validate:"omitempty,oneof=always allowed never"`

	// Mandatory indicates if claim must be present per section 9.3 (OPTIONAL, default: false).
	Mandatory bool `json:"mandatory,omitempty" bson:"mandatory,omitempty"`

	// SVGID is the identifier for SVG template placeholders per section 8.1.2.2 (OPTIONAL).
	SVGID string `json:"svg_id,omitempty" bson:"svg_id,omitempty"`
}

// ClaimDisplay provides locale-specific claim display information per section 9.2.
type ClaimDisplay struct {
	// Locale is the language tag per RFC 5646 (REQUIRED).
	Locale string `json:"locale" bson:"locale" validate:"required,bcp47_language_tag"`

	// Label is a human-readable label for end users (REQUIRED).
	Label string `json:"label" bson:"label" validate:"required"`

	// Description is a human-readable description for end users (OPTIONAL).
	Description string `json:"description,omitempty" bson:"description,omitempty"`
}
