package sdjwtvc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/go-playground/validator/v10"
)

// Validate checks the VCTM struct against its validation tags.
func (v *VCTM) Validate() error {
	validate := validator.New()
	validate.RegisterCustomTypeFunc(claimpath.ValidationValue, claimpath.Pointer{})
	return validate.Struct(v)
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
func (v *VCTM) Attributes() map[string]map[string]claimpath.Pointer {
	reply := map[string]map[string]claimpath.Pointer{}

	for _, c := range v.Claims {
		for _, d := range c.Display {
			if _, ok := reply[d.Locale]; !ok {
				reply[d.Locale] = map[string]claimpath.Pointer{}
			}
			reply[d.Locale][d.Label] = c.Path
		}
	}

	return reply
}

// AttributesWithoutObjects parse vctm claims and return a map of labels and their paths for each locale,
// excluding claims that represent objects (claims with nested paths)
func (v *VCTM) AttributesWithoutObjects() map[string]map[string]claimpath.Pointer {
	reply := map[string]map[string]claimpath.Pointer{}

	for _, c := range v.Claims {
		// Skip claims that are objects (have more than one path element)
		if c.Path.Len() > 1 {
			continue
		}

		// Skip claims without display information (not relevant for display)
		if len(c.Display) == 0 {
			continue
		}

		for _, d := range c.Display {
			if _, ok := reply[d.Locale]; !ok {
				reply[d.Locale] = map[string]claimpath.Pointer{}
			}
			reply[d.Locale][d.Label] = c.Path
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

	parentPaths := v.displayableParents()
	result := map[string]any{}
	for _, c := range v.Claims {
		if len(c.Display) == 0 {
			continue
		}
		switch jp := c.JSONPath(); {
		case parentPaths[jp]:
			v.presentParent(result, c, jp, data)
		case !isChildOfDisplayableParent(c.Path, parentPaths):
			presentLeaf(result, c, data)
		}
	}

	return result
}

// displayableParents returns the JSONPath of each displayed claim that has
// a displayed child.
func (v *VCTM) displayableParents() map[string]bool {
	parentPaths := map[string]bool{}
	for _, c := range v.Claims {
		parent, ok := c.Path.Parent()
		if len(c.Display) == 0 || !ok {
			continue
		}
		if parentJP := jsonPathOf(parent); v.displays(parentJP) {
			parentPaths[parentJP] = true
		}
	}
	return parentPaths
}

// displays reports whether a claim with display information has the
// JSONPath jp.
func (v *VCTM) displays(jp string) bool {
	for _, c := range v.Claims {
		if len(c.Display) > 0 && c.JSONPath() == jp {
			return true
		}
	}
	return false
}

// presentParent adds a parent claim with its displayed children, keyed by
// its first path element.
func (v *VCTM) presentParent(result map[string]any, c Claim, jp string, data map[string]any) {
	key, ok := firstKey(c.Path)
	if !ok {
		return // no usable key for parent node
	}
	children, wildcardValue := v.presentChildren(jp, data)
	label := c.Display[0].Label
	switch {
	case len(children) > 0:
		result[key] = map[string]any{
			"label":    label,
			"children": children,
		}
	case wildcardValue != nil:
		// All children were array wildcards — emit the parent as a leaf
		// with the resolved array value.
		result[key] = map[string]any{
			"label": label,
			"value": wildcardValue,
		}
	}
}

// presentChildren returns the displayed children of the parent at
// parentJP, and the value of an array wildcard child.
func (v *VCTM) presentChildren(parentJP string, data map[string]any) (map[string]any, any) {
	children := map[string]any{}
	var wildcardValue any
	for _, child := range v.Claims {
		parent, hasParent := child.Path.Parent()
		last, hasLast := child.Path.Last()
		if len(child.Display) == 0 || !hasParent || !hasLast || jsonPathOf(parent) != parentJP {
			continue
		}
		childValue := walkPath(data, child.Path)
		if childValue == nil {
			continue
		}
		if last.IsAll() {
			// Array wildcard child — remember the resolved value so the
			// parent can fall back to a leaf entry.
			wildcardValue = childValue
			continue
		}
		children[segmentName(last)] = map[string]any{
			"label": child.Display[0].Label,
			"value": childValue,
		}
	}
	return children, wildcardValue
}

// presentLeaf adds a claim that has no displayed parent. A single-segment
// claim is keyed by its path element; a multi-segment orphan by its joined
// path, which keeps the result flat and compatible with the consent UI
// schema ({label,value}).
func presentLeaf(result map[string]any, c Claim, data map[string]any) {
	value := walkPath(data, c.Path)
	key, ok := firstKey(c.Path)
	if value == nil || !ok {
		return
	}
	if c.Path.Len() > 1 {
		key = c.claimKey()
	}
	result[key] = map[string]any{
		"label": c.Display[0].Label,
		"value": value,
	}
}

// firstKey returns the key a claim path starts with.
func firstKey(path claimpath.Pointer) (string, bool) {
	components, err := path.Components()
	if err != nil {
		return "", false
	}
	return components[0].KeyName()
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

// JSONPath returns the JSON path for the claim. A null element selects
// every element of an array per SD-JWT VC §9.1 and is emitted as the
// JSONPath wildcard "[*]"; an index is emitted as "[i]".
func (c *Claim) JSONPath() string {
	if c == nil {
		return ""
	}
	return jsonPathOf(c.Path)
}

// claimKey returns a stable, unique key for a claim suitable for use in
// the Presentation() result map. For multi-segment paths (e.g.
// ["credentialSubject","givenName","und"]) it joins the keys with "."
// (e.g. "credentialSubject.givenName.und") to avoid collisions, and writes
// an index as "[i]" after its key.
func (c *Claim) claimKey() string {
	components, err := c.Path.Components()
	if err != nil {
		return ""
	}
	var key strings.Builder
	for _, component := range components {
		if name, ok := component.KeyName(); ok {
			if key.Len() > 0 {
				key.WriteString(".")
			}
			key.WriteString(name)
			continue
		}
		if index, ok := component.IndexValue(); ok {
			fmt.Fprintf(&key, "[%d]", index)
		}
	}
	return key.String()
}

// walkPath resolves a claim path against nested document data, up to its
// first null: a null selects the array as a whole.
// Returns nil for paths the data does not hold and for semantically empty
// values (empty string, empty slice, empty map) so callers can uniformly
// skip absent data with a nil check.
func walkPath(data map[string]any, path claimpath.Pointer) any {
	components, err := path.Components()
	if err != nil {
		return nil
	}
	upToAll, ok := path.Prefix(slices.IndexFunc(components, claimpath.Component.IsAll))
	if !ok {
		upToAll = path
	}
	value, present, err := claimpath.Nested().Get(data, upToAll)
	if err != nil || !present {
		// A claim the data does not hold is not shown.
		return nil
	}
	return normalizeEmpty(value)
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

// jsonPathOf builds the JSONPath string of a claim path.
func jsonPathOf(path claimpath.Pointer) string {
	components, err := path.Components()
	if err != nil {
		return ""
	}
	var jp strings.Builder
	jp.WriteString("$")
	for _, component := range components {
		jp.WriteString(jsonPathSegment(component))
	}
	return jp.String()
}

// jsonPathSegment is one component of a JSONPath.
func jsonPathSegment(component claimpath.Component) string {
	if name, ok := component.KeyName(); ok {
		return "." + name
	}
	if index, ok := component.IndexValue(); ok {
		return fmt.Sprintf("[%d]", index)
	}
	return "[*]"
}

// segmentName names a child claim by its last path element.
func segmentName(component claimpath.Component) string {
	if name, ok := component.KeyName(); ok {
		return name
	}
	return jsonPathSegment(component)
}

// isChildOfDisplayableParent reports whether any strict prefix of path is
// present in parents (keyed by JSONPath string).
func isChildOfDisplayableParent(path claimpath.Pointer, parents map[string]bool) bool {
	for _, ancestor := range path.Ancestors() {
		if parents[jsonPathOf(ancestor)] {
			return true
		}
	}
	return false
}
