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
	Display   []ClaimDisplay           `json:"display,omitempty"`
	Mandatory bool                     `json:"mandatory,omitempty"`
	ValueType string                   `json:"value_type,omitempty"`
	Elements  map[string]ClaimMetadata `json:"elements,omitempty"`
}

// ClaimDisplay is a localized display label for a claim.
type ClaimDisplay struct {
	Locale string `json:"locale"`
	Name   string `json:"name"`
}

// defaultLocale is used to bucket claims that declare no display info, so
// Attributes() still surfaces every claim rather than silently dropping it.
const defaultLocale = "en-US"

// Attributes returns a map of labels to claim paths for each locale, mirroring
// sdjwtvc.VCTM.Attributes() so callers (e.g. the verifier UI) can treat mdoc
// and sd-jwt credential types uniformly. Claims with no declared Display are
// bucketed under defaultLocale using their raw element ID as the label.
func (s *MDDLSchema) Attributes() map[string]map[string][]*string {
	reply := map[string]map[string][]*string{}

	for namespace, elements := range s.Claims {
		ns := namespace
		for elementID, meta := range elements {
			id := elementID
			path := []*string{&ns, &id}

			if len(meta.Display) == 0 {
				if reply[defaultLocale] == nil {
					reply[defaultLocale] = map[string][]*string{}
				}
				reply[defaultLocale][elementID] = path
				continue
			}

			for _, d := range meta.Display {
				if reply[d.Locale] == nil {
					reply[d.Locale] = map[string][]*string{}
				}
				reply[d.Locale][d.Name] = path
			}
		}
	}

	return reply
}

// Presentation resolves MDDL claims against document data and returns a flat
// map suitable for the consent preview UI, mirroring VCTM.Presentation's
// {label, value} shape. Document data (e.g. from the datastore) is flat -
// keyed by element ID directly, not nested under the mdoc namespace - so
// only the element ID (the path's second segment, per Attributes()) is used
// for lookup.
func (s *MDDLSchema) Presentation(data map[string]any) map[string]any {
	if data == nil || len(s.Claims) == 0 {
		return nil
	}

	attributes := s.Attributes()
	labels := attributes[defaultLocale]
	if labels == nil {
		for _, m := range attributes {
			labels = m
			break
		}
	}

	result := map[string]any{}
	for label, path := range labels {
		if len(path) < 2 || path[1] == nil {
			continue
		}
		elementID := *path[1]
		value, ok := data[elementID]
		if !ok {
			continue
		}
		result[elementID] = map[string]any{
			"label": label,
			"value": value,
		}
	}

	return result
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

	// addElements() (pkg/mdoc/issuer.go) looks up document_data by element
	// identifier alone, without namespace context, since document_data is a
	// flat map. That is safe only if every element identifier is unique
	// across all namespaces the schema declares; otherwise the lookup would
	// be ambiguous (the same value would be used for both claims, and a
	// mandatory/optional mismatch between namespaces could silently mis-fire).
	// Reject such schemas up front rather than mis-issuing credentials.
	seenIn := map[string]string{}
	for namespace, elements := range schema.Claims {
		for elementID := range elements {
			if prev, ok := seenIn[elementID]; ok {
				return nil, fmt.Errorf("MDDL schema for doctype %q declares claim %q in both namespace %q and %q: element identifiers must be unique across namespaces", schema.DocType, elementID, prev, namespace)
			}
			seenIn[elementID] = namespace
		}
	}

	return &schema, nil
}
