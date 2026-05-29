package sdjwtvc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-playground/validator/v10"
)

// Validate checks the VCTM struct against its validation tags.
func (v *VCTM) Validate() error {
	return validator.New().Struct(v)
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

// Presentation resolves VCTM claims against document data and returns a nested
// map suitable for the consent preview UI.
//
// The returned map is keyed by claim name. For single-segment claims and
// displayable parents, the key is the first path element. For multi-segment
// leaf claims without a displayable parent, the key is the last path segment
// (e.g. a claim with path ["address", "country"] is keyed as "country").
//
// Each entry is a map[string]any with "label" and either "value" (leaf claims)
// or "children" (parent claims whose children are also defined in the VCTM
// with display info).
//
// Example output:
//
//	{
//	  "given_name": {"label": "First Name", "value": "Helen"},
//	  "address": {"label": "Address", "children": {
//	    "street_address": {"label": "Residence street", "value": "Tulegatan"},
//	    "country": {"label": "Country of residence", "value": "SE"},
//	  }}
//	}
func (v *VCTM) Presentation(data map[string]any) map[string]any {
	if data == nil || len(v.Claims) == 0 {
		return nil
	}

	// Identify parent paths: claims with display that also have children with display.
	parentPaths := map[string]bool{}
	for _, c := range v.Claims {
		if len(c.Display) == 0 || len(c.Path) <= 1 {
			continue
		}
		// The parent is the path minus the last element.
		parentJP := jsonPathFromSegments(c.Path[:len(c.Path)-1])
		// Only mark as parent if that path also has a displayable claim.
		for _, p := range v.Claims {
			if len(p.Display) > 0 && p.JSONPath() == parentJP {
				parentPaths[parentJP] = true
				break
			}
		}
	}

	result := map[string]any{}

	for _, c := range v.Claims {
		if len(c.Display) == 0 {
			continue
		}

		jp := c.JSONPath()
		label := c.Display[0].Label

		if parentPaths[jp] {
			// This is a parent claim — collect its children.
			children := map[string]any{}
			for _, child := range v.Claims {
				if len(child.Display) == 0 || len(child.Path) <= 1 {
					continue
				}
				childParentJP := jsonPathFromSegments(child.Path[:len(child.Path)-1])
				if childParentJP != jp {
					continue
				}
				childValue := walkPath(data, child.Path)
				if childValue == nil {
					continue
				}
				lastSeg := child.Path[len(child.Path)-1]
				if lastSeg == nil {
					continue // array wildcard — not a named child
				}
				children[*lastSeg] = map[string]any{
					"label": child.Display[0].Label,
					"value": childValue,
				}
			}
			if len(children) > 0 {
				if c.Path[0] == nil {
					continue // no usable key for parent node
				}
				result[*c.Path[0]] = map[string]any{
					"label":    label,
					"children": children,
				}
			}
		} else if !isChildOfDisplayableParent(c.Path, parentPaths) {
			// Leaf claim (not under a parent).
			value := walkPath(data, c.Path)
			if value == nil {
				continue
			}
			var key string
			if len(c.Path) > 1 && c.Path[len(c.Path)-1] != nil {
				key = *c.Path[len(c.Path)-1]
			} else if c.Path[0] != nil {
				key = *c.Path[0]
			} else {
				continue // no usable key segment
			}
			result[key] = map[string]any{
				"label": label,
				"value": value,
			}
		}
	}

	return result
}

// SVGValues resolves claims that have an svg_id against document data and
// returns a flat map keyed by svg_id with label and resolved leaf value.
// This is used for SVG template placeholder substitution.
func (v *VCTM) SVGValues(data map[string]any) map[string]SVGValue {
	if data == nil || len(v.Claims) == 0 {
		return nil
	}

	result := map[string]SVGValue{}
	for _, c := range v.Claims {
		if c.SVGID == "" || len(c.Display) == 0 {
			continue
		}
		value := walkPath(data, c.Path)
		if value == nil {
			continue
		}
		result[c.SVGID] = SVGValue{
			Label: c.Display[0].Label,
			Value: value,
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// JSONPath returns the JSON path for the claim.
// A nil element in Path means "select all elements of an array" per SD-JWT VC §9.1,
// and is emitted as the JSONPath wildcard "[*]".
func (c *Claim) JSONPath() string {
	if c == nil || c.Path == nil {
		return ""
	}

	reply := "$"
	for _, path := range c.Path {
		if path == nil {
			reply += "[*]"
			continue
		}
		reply += "." + *path
	}
	return reply
}

// walkPath resolves a claim path against nested document data.
func walkPath(data map[string]any, path []*string) any {
	var current any = data
	for _, seg := range path {
		if seg == nil {
			return current // array wildcard — return the array as-is
		}
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[*seg]
		if !ok {
			return nil
		}
	}
	return current
}

// jsonPathFromSegments builds a JSONPath string from path segments.
func jsonPathFromSegments(path []*string) string {
	jp := "$"
	for _, p := range path {
		if p == nil {
			jp += "[*]"
		} else {
			jp += "." + *p
		}
	}
	return jp
}

// isChildOfDisplayableParent reports whether any strict prefix of path is
// present in parents (keyed by JSONPath string).
func isChildOfDisplayableParent(path []*string, parents map[string]bool) bool {
	if len(path) <= 1 {
		return false
	}
	prefix := "$"
	for i, p := range path {
		if i == len(path)-1 {
			break // don't check the full path — only strict prefixes
		}
		if p == nil {
			prefix += "[*]"
		} else {
			prefix += "." + *p
		}
		if parents[prefix] {
			return true
		}
	}
	return false
}
