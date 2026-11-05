package credential

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// maxTemplateIndex is the largest array index a claim template renders.
// An operator fills the template in by hand.
const maxTemplateIndex = 255

// ClaimTemplate returns a document that holds an empty string at each of
// the VCTM claims, in the objects and arrays that hold it, so the claims
// path pointer of each claim selects it in the document.
//
//   - A key adds an object member.
//   - An index i makes an array of i+1 elements.
//   - Null makes an array of at least one element, and declares its claim
//     in every element.
//   - An element no claim declares is null.
//
// A claim whose path starts with null or an index is skipped: the
// document is an object. ClaimTemplate refuses a claim declared as an
// object and as an array, and an index above 255.
func ClaimTemplate(claims []sdjwtvc.Claim) (map[string]any, error) {
	root := &allowNode{}
	for i := range claims {
		components, err := claims[i].Path.Components()
		if err != nil {
			return nil, fmt.Errorf("VCTM claim %s: %w", claims[i].JSONPath(), err)
		}
		if _, isKey := components[0].KeyName(); isKey {
			insertAllowPath(root, components)
		}
	}
	return root.templateObject(nil)
}

// templateValue renders the claim at path: an empty string when no claim
// continues below it, an object for keys, and an array for null and
// indices.
func (n *allowNode) templateValue(path []claimpath.Component) (any, error) {
	switch {
	case n == nil:
		return nil, nil
	case len(n.children) == 0:
		return "", nil
	}
	object, length := false, uint(0)
	for component := range n.children {
		if _, isKey := component.KeyName(); isKey {
			object = true
			continue
		}
		index, _ := component.IndexValue()
		if index > maxTemplateIndex {
			p, err := claimpath.FromComponents(append(slices.Clip(path), component))
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("VCTM claim %s: a claim template renders arrays up to index %d", p, maxTemplateIndex)
		}
		length = max(length, index+1)
	}
	if !object {
		return n.templateArray(path, length)
	}
	if length > 0 {
		p, err := claimpath.FromComponents(path)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("VCTM declares the claim %s as an object and as an array", p)
	}
	return n.templateObject(path)
}

// templateArray renders the elements below n as an array of length
// elements. Each element holds the claims null and its index declare.
func (n *allowNode) templateArray(path []claimpath.Component, length uint) ([]any, error) {
	all := n.children[claimpath.All()]
	array := make([]any, length)
	for i := range array {
		index := claimpath.Index(uint(i))
		element, err := mergeAllowNodes(all, n.children[index]).templateValue(append(slices.Clip(path), index))
		if err != nil {
			return nil, err
		}
		array[i] = element
	}
	return array, nil
}

// templateObject renders the keys below n as an object.
func (n *allowNode) templateObject(path []claimpath.Component) (map[string]any, error) {
	object := make(map[string]any, len(n.children))
	for component, child := range n.children {
		key, _ := component.KeyName()
		value, err := child.templateValue(append(slices.Clip(path), component))
		if err != nil {
			return nil, err
		}
		object[key] = value
	}
	return object, nil
}
