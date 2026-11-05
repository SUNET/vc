package credential

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// FilterAgainstVCTM returns a copy of doc containing only the keys declared
// by the VCTM's claim paths, recursively into nested maps and arrays. Keys
// the VCTM does not list are dropped. This is the anti-PII-leak choke point
// for credentials whose document data is assembled from an external source
// (e.g. a presented credential's own claims): even if upstream forwards
// more claims than intended, only VCTM-declared paths reach the issuer.
//
// A VCTM claim path that starts with null or an index is skipped: the
// document is an object. A null in the middle of a path descends into
// every array element, an index into that element only.
//
// An array the VCTM selects only with null keeps the elements with
// something left, in order. An array the VCTM indexes keeps each element
// at its index, so a pointer with an index selects the same claim in the
// filtered document: a declared element with nothing left stays as its
// empty form ({}, [] or null) while a later element is kept, and the
// elements after the last kept one are dropped.
//
// Sibling keys inside a nested object are dropped when the VCTM only
// declares specific children — e.g. a VCTM path [address, locality] lets
// address.locality through but drops address.street.
//
// It refuses a VCTM CheckFilterable refuses.
func FilterAgainstVCTM(doc map[string]any, vctm *sdjwtvc.VCTM) (map[string]any, error) {
	if vctm == nil {
		return map[string]any{}, nil
	}
	tree, err := buildAllowTree(vctm)
	if err != nil {
		return nil, err
	}
	filtered, _ := filterMap(doc, tree)
	if filtered == nil {
		return map[string]any{}, nil
	}
	return filtered, nil
}

// CheckFilterable refuses a VCTM FilterAgainstVCTM cannot filter: a claim
// without a path, and an array whose declared indices are not 0 to k
// while the VCTM selects none of its elements with null. Keeping an
// element at its index keeps every element before it.
func CheckFilterable(vctm *sdjwtvc.VCTM) error {
	if vctm == nil {
		return nil
	}
	_, err := buildAllowTree(vctm)
	return err
}

// allowNode describes the subset of a nested value that is permitted. A nil
// children map means "all sub-values allowed". Children are keyed by the
// claims path component that selects them: a key, null for every array
// element, or an index.
type allowNode struct {
	// leaf marks that the exact path terminates here (whole value allowed).
	leaf bool
	// children indexes the components that continue a declared path.
	children map[claimpath.Component]*allowNode
}

func buildAllowTree(vctm *sdjwtvc.VCTM) (*allowNode, error) {
	root := &allowNode{}
	for _, c := range vctm.Claims {
		components, err := c.Path.Components()
		if err != nil {
			return nil, fmt.Errorf("VCTM claim %s: %w", c.JSONPath(), err)
		}
		if _, ok := components[0].KeyName(); !ok {
			continue
		}
		insertAllowPath(root, components)
	}
	if err := root.checkIndices(nil); err != nil {
		return nil, err
	}
	return root, nil
}

// checkIndices refuses an array below node, at path, whose declared
// indices are not 0 to k while null declares none of its elements.
func (n *allowNode) checkIndices(path []claimpath.Component) error {
	var indices []uint
	for _, component := range slices.SortedFunc(maps.Keys(n.children), compareComponents) {
		if index, ok := component.IndexValue(); ok {
			indices = append(indices, index)
		}
		if err := n.children[component].checkIndices(append(slices.Clip(path), component)); err != nil {
			return err
		}
	}
	if len(indices) == 0 || n.children[claimpath.All()] != nil {
		return nil
	}
	for want, index := range indices {
		if index != uint(want) {
			array, err := claimpath.FromComponents(path)
			if err != nil {
				return err
			}
			return fmt.Errorf("VCTM declares elements %v of the array %s: the issuer filters an array the VCTM indexes from 0 without a gap, or selects with null", indices, array)
		}
	}
	return nil
}

// compareComponents orders keys before null before indices, keys by name
// and indices by value.
func compareComponents(a, b claimpath.Component) int {
	rank := func(c claimpath.Component) int {
		if _, ok := c.KeyName(); ok {
			return 0
		}
		if c.IsAll() {
			return 1
		}
		return 2
	}
	if ra, rb := rank(a), rank(b); ra != rb {
		return ra - rb
	}
	if ka, ok := a.KeyName(); ok {
		kb, _ := b.KeyName()
		return strings.Compare(ka, kb)
	}
	ia, _ := a.IndexValue()
	ib, _ := b.IndexValue()
	return cmp.Compare(ia, ib)
}

// indexed reports whether the VCTM declares an element of the array at
// node by its index.
func (n *allowNode) indexed() bool {
	for component := range n.children {
		if _, ok := component.IndexValue(); ok {
			return true
		}
	}
	return false
}

func insertAllowPath(node *allowNode, path []claimpath.Component) {
	cur := node
	for _, component := range path {
		if cur.children == nil {
			cur.children = map[claimpath.Component]*allowNode{}
		}
		next, ok := cur.children[component]
		if !ok {
			next = &allowNode{}
			cur.children[component] = next
		}
		cur = next
	}
	cur.leaf = true
}

// filterMap returns the filtered copy of m under node. The bool reports
// whether anything survived (used by parents to decide whether to keep an
// otherwise-empty container).
func filterMap(m map[string]any, node *allowNode) (map[string]any, bool) {
	if node == nil {
		return nil, false
	}
	// A leaf permits the whole value, even if the VCTM also declares
	// descendants — a path such as "address" alongside "address.locality"
	// means the whole address object is allowed; without this short-cut
	// the sibling fields the parent permits would be silently dropped.
	if node.leaf {
		return m, len(m) > 0
	}
	out := make(map[string]any, len(node.children))
	for component, child := range node.children {
		key, isKey := component.KeyName()
		if !isKey {
			continue
		}
		v, present := m[key]
		if !present {
			continue
		}
		if filtered, keep := filterValue(v, child); keep {
			out[key] = filtered
		}
	}
	return out, len(out) > 0
}

func filterValue(v any, node *allowNode) (any, bool) {
	if node == nil {
		return nil, false
	}
	// Leaf wins: whole value allowed even if the VCTM also declares
	// descendants under the same path (see filterMap for the parallel
	// map-side comment).
	if node.leaf && len(node.children) == 0 {
		return v, true
	}
	switch tv := v.(type) {
	case map[string]any:
		return filterMap(tv, node)
	case []any:
		return filterArray(tv, node)
	case []string:
		// Mapped claims (and as_array: true) commonly produce concrete
		// slices such as []string. Normalise to []any so a VCTM path
		// like ["nationalities", null] can filter/retain its elements
		// instead of dropping the entire declared claim.
		anySlice := make([]any, len(tv))
		for i, s := range tv {
			anySlice[i] = s
		}
		return filterArray(anySlice, node)
	default:
		if node.leaf {
			return v, true
		}
		return nil, false
	}
}

func filterArray(tv []any, node *allowNode) (any, bool) {
	all := node.children[claimpath.All()]
	if node.indexed() {
		return filterIndexedArray(tv, node, all)
	}
	if all == nil {
		if node.leaf {
			return tv, true
		}
		return nil, false
	}
	out := make([]any, 0, len(tv))
	for _, e := range tv {
		if filtered, keep := filterValue(e, all); keep {
			out = append(out, filtered)
		}
	}
	return out, len(out) > 0
}

// filterIndexedArray keeps each element of an array the VCTM indexes at
// its index. The declared indices are 0 to k, or null declares every
// element.
func filterIndexedArray(tv []any, node, all *allowNode) (any, bool) {
	out := make([]any, 0, len(tv))
	kept := 0
	for i, e := range tv {
		element := mergeAllowNodes(all, node.children[claimpath.Index(uint(i))])
		if element == nil {
			break
		}
		filtered, keep := filterValue(e, element)
		if !keep {
			filtered = emptyForm(e)
		}
		out = append(out, filtered)
		if keep {
			kept = len(out)
		}
	}
	return out[:kept], kept > 0
}

// emptyForm is the value of an element with nothing left: an empty object
// or array, or null.
func emptyForm(v any) any {
	switch v.(type) {
	case map[string]any:
		return map[string]any{}
	case []any, []string:
		return []any{}
	}
	return nil
}

// mergeAllowNodes returns the node that permits what either a or b
// permits: an array element can be declared by null and by its index.
func mergeAllowNodes(a, b *allowNode) *allowNode {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	merged := &allowNode{leaf: a.leaf || b.leaf, children: map[claimpath.Component]*allowNode{}}
	for component, child := range a.children {
		merged.children[component] = child
	}
	for component, child := range b.children {
		merged.children[component] = mergeAllowNodes(merged.children[component], child)
	}
	return merged
}
