package credential

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// maxTemplateIndex is the largest array index a claim template renders.
// An operator fills the template in by hand.
const maxTemplateIndex = 255

// Template is the claim template of a VCTM.
type Template struct {
	// Document holds an empty string at each of the VCTM claims.
	Document map[string]any
	// ObjectAndArray lists the claims the VCTM declares as an object and
	// as an array, in pointer order. Document renders each as an object.
	ObjectAndArray []claimpath.Pointer
}

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
// A claim declared as an object and as an array renders as the earlier
// release rendered every claim: an object of the keys below it, with null
// and indices skipped. A claim without a path component, and one whose
// path starts with null or an index, is skipped: the document is an
// object. ClaimTemplate refuses an index above 255.
func ClaimTemplate(claims []sdjwtvc.Claim) (Template, error) {
	root := &allowNode{}
	for i := range claims {
		if _, isKey := claims[i].Path.FirstKey(); !isKey {
			continue
		}
		components, err := claims[i].Path.Components()
		if err != nil {
			return Template{}, fmt.Errorf("VCTM claim %s: %w", claims[i].JSONPath(), err)
		}
		insertAllowPath(root, components)
	}
	var r templateRenderer
	document, err := r.object(root, nil)
	if err != nil {
		return Template{}, err
	}
	slices.SortFunc(r.objectAndArray, func(a, b claimpath.Pointer) int { return strings.Compare(a.String(), b.String()) })
	return Template{Document: document, ObjectAndArray: r.objectAndArray}, nil
}

// templateRenderer renders a claim template, and records the claims it
// renders as objects because the VCTM declares them as objects and as
// arrays.
type templateRenderer struct {
	objectAndArray []claimpath.Pointer
}

// value renders the claim n declares at path: an empty string when no
// claim continues below it, an object for keys, and an array for null and
// indices.
func (r *templateRenderer) value(n *allowNode, path []claimpath.Component) (any, error) {
	switch {
	case n == nil:
		return nil, nil
	case len(n.children) == 0:
		return "", nil
	}
	object, array, largest := false, false, uint(0)
	for component := range n.children {
		if _, isKey := component.KeyName(); isKey {
			object = true
			continue
		}
		array = true
		index, _ := component.IndexValue()
		largest = max(largest, index)
	}
	switch {
	case object && array:
		return r.earlier(n, path)
	case object:
		return r.object(n, path)
	case largest > maxTemplateIndex:
		p, err := claimpath.FromComponents(append(slices.Clip(path), claimpath.Index(largest)))
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("VCTM claim %s: a claim template renders arrays up to index %d", p, maxTemplateIndex)
	}
	return r.array(n, path, largest+1)
}

// array renders the elements below n as an array of length elements.
// Each element holds the claims null and its index declare.
func (r *templateRenderer) array(n *allowNode, path []claimpath.Component, length uint) ([]any, error) {
	all := n.children[claimpath.All()]
	array := make([]any, length)
	for i := range array {
		index := claimpath.Index(uint(i))
		element, err := r.value(mergeAllowNodes(all, n.children[index]), append(slices.Clip(path), index))
		if err != nil {
			return nil, err
		}
		array[i] = element
	}
	return array, nil
}

// object renders the keys below n as an object.
func (r *templateRenderer) object(n *allowNode, path []claimpath.Component) (map[string]any, error) {
	object := make(map[string]any, len(n.children))
	for component, child := range n.children {
		key, _ := component.KeyName()
		value, err := r.value(child, append(slices.Clip(path), component))
		if err != nil {
			return nil, err
		}
		object[key] = value
	}
	return object, nil
}

// earlier renders the claim n declares at path as the earlier release
// rendered it, and records it.
func (r *templateRenderer) earlier(n *allowNode, path []claimpath.Component) (any, error) {
	p, err := claimpath.FromComponents(path)
	if err != nil {
		return nil, err
	}
	r.objectAndArray = append(r.objectAndArray, p)
	return earlierValue(n), nil
}

// earlierValue renders the claim n declares as the earlier release
// rendered every claim: an empty string where no claim continues below
// it, and otherwise an object of the keys below it, with null and indices
// skipped.
func earlierValue(n *allowNode) any {
	if len(n.children) == 0 {
		return ""
	}
	members := earlierMembers(n)
	object := make(map[string]any, len(members))
	for key, child := range members {
		object[key] = earlierValue(child)
	}
	return object
}

// earlierMembers returns the keys below n, with null and indices skipped,
// each with the claims every path through it declares.
func earlierMembers(n *allowNode) map[string]*allowNode {
	members := map[string]*allowNode{}
	for component, child := range n.children {
		if key, isKey := component.KeyName(); isKey {
			members[key] = mergeAllowNodes(members[key], child)
			continue
		}
		for key, grandchild := range earlierMembers(child) {
			members[key] = mergeAllowNodes(members[key], grandchild)
		}
	}
	return members
}
