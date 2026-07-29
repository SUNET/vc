package sdjwtvc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

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

// Attributes parse vctm claims and return a map of labels and their paths for each locale.
// Path elements may be nil, representing JSON null (array element access per DCQL Section 7.1).
func (v *VCTM) Attributes() map[string]map[string][]*string {
	reply := map[string]map[string][]*string{}

	for _, c := range v.Claims {
		for _, d := range c.Display {
			if _, ok := reply[d.Locale]; !ok {
				reply[d.Locale] = map[string][]*string{}
			}

			label := d.Label
			path := make([]*string, len(c.Path))
			copy(path, c.Path)
			reply[d.Locale][label] = path
		}
	}

	return reply
}

// AttributesWithoutObjects parse vctm claims and return a map of labels and their paths for each locale,
// excluding claims that represent objects (claims with nested paths)
func (v *VCTM) AttributesWithoutObjects() map[string]map[string][]*string {
	reply := map[string]map[string][]*string{}

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
				reply[d.Locale] = map[string][]*string{}
			}

			label := d.Label
			path := make([]*string, len(c.Path))
			copy(path, c.Path)
			reply[d.Locale][label] = path
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

// Presentation resolves VCTM claims against document data and returns a flat
// map suitable for the consent preview UI.
//
// Every top-level entry is a map[string]any with "label" and either "value"
// (leaf/orphan claims) or "children" (parent claims whose children are also
// defined in the VCTM with display info).
//
// Keys:
//   - Single-segment claims: the path element itself (e.g. "given_name").
//   - Displayable parents: the first path element (e.g. "address").
//   - Multi-segment orphan leaves (no displayable parent): joined path
//     segments (e.g. path ["credentialSubject","givenName","und"] →
//     key "credentialSubject.givenName.und").
//
// Example output:
//
//	{
//	  "given_name":    {"label": "First Name", "value": "Helen"},
//	  "address":       {"label": "Address", "children": {
//	    "street_address": {"label": "Residence street", "value": "Tulegatan"},
//	    "country":        {"label": "Country of residence", "value": "SE"},
//	  }},
//	  "credentialSubject.givenName.und": {"label": "Given name", "value": "Helen"},
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
		if len(c.Display) == 0 || len(c.Path) == 0 {
			continue
		}

		jp := c.JSONPath()
		label := c.Display[0].Label

		if parentPaths[jp] {
			// This is a parent claim — collect its children.
			children := map[string]any{}
			var wildcardValue any
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
					// Array wildcard child — remember the resolved value
					// so the parent can fall back to a leaf entry.
					wildcardValue = childValue
					continue
				}
				children[*lastSeg] = map[string]any{
					"label": child.Display[0].Label,
					"value": childValue,
				}
			}
			if c.Path[0] == nil {
				continue // no usable key for parent node
			}
			if len(children) > 0 {
				result[*c.Path[0]] = map[string]any{
					"label":    label,
					"children": children,
				}
			} else if wildcardValue != nil {
				// All children were array wildcards — emit the parent as
				// a leaf with the resolved array value.
				result[*c.Path[0]] = map[string]any{
					"label": label,
					"value": wildcardValue,
				}
			}
		} else if !isChildOfDisplayableParent(c.Path, parentPaths) {
			// Leaf claim (not under a parent).
			value := walkPath(data, c.Path)
			if value == nil {
				continue
			}
			if c.Path[0] == nil {
				continue // no usable key segment
			}
			// Use the first path segment as key for single-segment claims,
			// or the full JSONPath (without "$." prefix) for multi-segment
			// orphans to avoid collisions and keep the result flat and
			// compatible with the consent UI schema ({label,value}).
			key := *c.Path[0]
			if len(c.Path) > 1 {
				key = c.claimKey()
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

	var reply strings.Builder
	reply.WriteString("$")
	for _, path := range c.Path {
		if path == nil {
			reply.WriteString("[*]")
			continue
		}
		reply.WriteString("." + *path)
	}
	return reply.String()
}

// claimKey returns a stable, unique key for a claim suitable for use in
// the Presentation() result map. For multi-segment paths (e.g.
// ["credentialSubject","givenName","und"]) it joins all non-nil segments
// with "." (e.g. "credentialSubject.givenName.und") to avoid collisions.
func (c *Claim) claimKey() string {
	parts := make([]string, 0, len(c.Path))
	for _, seg := range c.Path {
		if seg != nil {
			parts = append(parts, *seg)
		}
	}
	return strings.Join(parts, ".")
}

// walkPath resolves a claim path against nested document data.
// Returns nil for empty paths, paths that don't resolve, and semantically
// empty values (empty string, empty slice, empty map) so callers can
// uniformly skip absent data with a nil check.
//
// Path segments may contain bracket-index notation (e.g. "hasClaim[0]")
// to select an element from an array-typed field.
func walkPath(data map[string]any, path []*string) any {
	if len(path) == 0 || path[0] == nil {
		return nil
	}
	var current any = data
	for _, seg := range path {
		if seg == nil {
			return normalizeEmpty(current) // array wildcard — return the array as-is
		}
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		key, idx := parseBracketIndex(*seg)
		current, ok = m[key]
		if !ok {
			return nil
		}
		if idx >= 0 {
			arr, ok := current.([]any)
			if !ok || idx >= len(arr) {
				return nil
			}
			current = arr[idx]
		}
	}
	return normalizeEmpty(current)
}

// parseBracketIndex splits a segment like "hasClaim[0]" into ("hasClaim", 0).
// If no bracket-index is present, it returns (seg, -1).
func parseBracketIndex(seg string) (string, int) {
	bracket := strings.IndexByte(seg, '[')
	if bracket < 0 || !strings.HasSuffix(seg, "]") {
		return seg, -1
	}
	idxStr := seg[bracket+1 : len(seg)-1]
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 {
		return seg, -1
	}
	return seg[:bracket], idx
}

// normalizeEmpty returns nil for semantically empty values (empty string,
// empty slice, empty map) so that consent rows with blank data are skipped.
func normalizeEmpty(v any) any {
	switch val := v.(type) {
	case string:
		if val == "" {
			return nil
		}
	case []any:
		if len(val) == 0 {
			return nil
		}
	case map[string]any:
		if len(val) == 0 {
			return nil
		}
	}
	return v
}

// jsonPathFromSegments builds a JSONPath string from path segments.
func jsonPathFromSegments(path []*string) string {
	var jp strings.Builder
	jp.WriteString("$")
	for _, p := range path {
		if p == nil {
			jp.WriteString("[*]")
		} else {
			jp.WriteString("." + *p)
		}
	}
	return jp.String()
}

// isChildOfDisplayableParent reports whether any strict prefix of path is
// present in parents (keyed by JSONPath string).
func isChildOfDisplayableParent(path []*string, parents map[string]bool) bool {
	if len(path) <= 1 {
		return false
	}
	var prefix strings.Builder
	prefix.WriteString("$")
	for i, p := range path {
		if i == len(path)-1 {
			break // don't check the full path — only strict prefixes
		}
		if p == nil {
			prefix.WriteString("[*]")
		} else {
			prefix.WriteString("." + *p)
		}
		if parents[prefix.String()] {
			return true
		}
	}
	return false
}
