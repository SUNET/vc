package mdoc

import (
	"encoding/json"
	"fmt"
)

// MDDLSchema describes an mso_mdoc credential's document type, namespace(s),
// and claims. It is the mdoc analogue of an SD-JWT VCTM: it drives issuance
// generically (namespace, mandatory/optional split, CBOR value encoding) so
// that adding a new mdoc document type requires only a new schema document,
// never a Go code change.
type MDDLSchema struct {
	Format  string                     `json:"format"`
	DocType string                     `json:"doctype"`
	Display []DisplayProperties        `json:"display,omitempty"`
	Claims  map[string]NamespaceClaims `json:"claims,omitempty"`
}

// DisplayProperties describes how the credential should be presented to the
// holder, mirroring registry-cli's mddl.DisplayProperties.
type DisplayProperties struct {
	Locale          string `json:"locale"`
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	Logo            *Logo  `json:"logo,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// Logo describes a display logo image.
type Logo struct {
	URI     string `json:"uri,omitempty"`
	AltText string `json:"alt_text,omitempty"`
}

// NamespaceClaims maps element identifiers to their claim metadata within a
// single mdoc namespace.
type NamespaceClaims map[string]ClaimMetadata

// ClaimMetadata describes a single mdoc data element: whether it is
// mandatory and how its value should be CBOR-encoded (a CDDL type name, e.g.
// "tstr", "full-date", "tdate", "bstr", "array", "map"). Elements describes
// the item/field shape for container ("array"/"map") claims.
type ClaimMetadata struct {
	Mandatory bool                     `json:"mandatory,omitempty"`
	ValueType string                   `json:"value_type,omitempty"`
	Elements  map[string]ClaimMetadata `json:"elements,omitempty"`
}

// LoadMDDLSchema parses and validates a raw MDDL (mso_mdoc) schema document.
func LoadMDDLSchema(raw []byte) (*MDDLSchema, error) {
	var schema MDDLSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, fmt.Errorf("parse MDDL schema: %w", err)
	}
	if schema.Format != "mso_mdoc" {
		return nil, fmt.Errorf("unsupported MDDL format: %q (want %q)", schema.Format, "mso_mdoc")
	}
	if schema.DocType == "" {
		return nil, fmt.Errorf("MDDL schema is missing doctype")
	}
	if len(schema.Claims) == 0 {
		return nil, fmt.Errorf("MDDL schema for doctype %q declares no claims", schema.DocType)
	}
	return &schema, nil
}
