package credential

import "github.com/SUNET/vc/pkg/sdjwtvc"

// FilterAgainstVCTM returns a copy of doc containing only the keys declared
// by the VCTM's claim paths, recursively into nested maps and arrays. Keys
// the VCTM does not list are dropped. This is the anti-PII-leak choke point
// for credentials whose document data is assembled from an external source
// (e.g. a presented credential's own claims): even if upstream forwards
// more claims than intended, only VCTM-declared paths reach the issuer.
//
// A VCTM claim with an empty path is skipped defensively. A nil segment in
// the middle of a path is treated as "descend into every array element".
//
// Sibling keys inside a nested object are dropped when the VCTM only
// declares specific children — e.g. a VCTM path [address, locality] lets
// address.locality through but drops address.street.
func FilterAgainstVCTM(doc map[string]any, vctm *sdjwtvc.VCTM) map[string]any {
	if vctm == nil {
		return map[string]any{}
	}
	tree := buildAllowTree(vctm)
	filtered, _ := filterMap(doc, tree)
	if filtered == nil {
		return map[string]any{}
	}
	return filtered
}

// allowNode describes the subset of a nested value that is permitted. A nil
// children map means "all sub-values allowed". A non-nil children map with
// a wildcard entry ("*") means "every array element is filtered by the
// wildcard subtree".
type allowNode struct {
	// leaf marks that the exact path terminates here (whole value allowed).
	leaf bool
	// children indexes named sub-keys. The "*" key means array-elementwise.
	children map[string]*allowNode
}

const arrayWildcardKey = "*"

func buildAllowTree(vctm *sdjwtvc.VCTM) *allowNode {
	root := &allowNode{}
	for _, c := range vctm.Claims {
		if len(c.Path) == 0 {
			continue
		}
		if c.Path[0] == nil {
			continue
		}
		insertAllowPath(root, c.Path)
	}
	return root
}

func insertAllowPath(node *allowNode, path []*string) {
	cur := node
	for _, seg := range path {
		key := arrayWildcardKey
		if seg != nil {
			key = *seg
		}
		if cur.children == nil {
			cur.children = map[string]*allowNode{}
		}
		next, ok := cur.children[key]
		if !ok {
			next = &allowNode{}
			cur.children[key] = next
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
	if node.leaf && node.children == nil {
		return m, len(m) > 0
	}
	out := make(map[string]any, len(node.children))
	for k, child := range node.children {
		if k == arrayWildcardKey {
			continue
		}
		v, present := m[k]
		if !present {
			continue
		}
		if filtered, keep := filterValue(v, child); keep {
			out[k] = filtered
		}
	}
	return out, len(out) > 0
}

func filterValue(v any, node *allowNode) (any, bool) {
	if node == nil {
		return nil, false
	}
	if node.leaf && node.children == nil {
		return v, true
	}
	switch tv := v.(type) {
	case map[string]any:
		return filterMap(tv, node)
	case []any:
		wildcard := node.children[arrayWildcardKey]
		if wildcard == nil {
			if node.leaf {
				return v, true
			}
			return nil, false
		}
		out := make([]any, 0, len(tv))
		for _, e := range tv {
			if filtered, keep := filterValue(e, wildcard); keep {
				out = append(out, filtered)
			}
		}
		return out, len(out) > 0
	default:
		if node.leaf {
			return v, true
		}
		return nil, false
	}
}
