package legacyclaims

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"gopkg.in/yaml.v2"
)

// unwrap returns the node an anchor or a tag annotates. An alias is an
// error: the upgrade reads each claim where it is written.
func unwrap(n ast.Node) (ast.Node, error) {
	n = annotated(n)
	if alias, ok := n.(*ast.AliasNode); ok {
		return nil, fmt.Errorf("%s is an alias; write the claims it stands for in place", alias.GetPath())
	}
	return n, nil
}

// annotated returns the node an anchor or a tag annotates.
func annotated(n ast.Node) ast.Node {
	for {
		switch v := n.(type) {
		case *ast.AnchorNode:
			n = v.Value
		case *ast.TagNode:
			n = v.Value
		default:
			return n
		}
	}
}

// isNull reports whether a node holds nothing.
func isNull(n ast.Node) bool {
	if n == nil {
		return true
	}
	_, null := n.(*ast.NullNode)
	return null
}

// isMappingNode reports whether n is a mapping. goccy/go-yaml parses a
// block mapping of one entry as that entry.
func isMappingNode(n ast.Node) bool {
	switch n.(type) {
	case *ast.MappingNode, *ast.MappingValueNode:
		return true
	}
	return false
}

// entries returns the entries of a mapping. A null node has none.
func entries(n ast.Node) ([]*ast.MappingValueNode, error) {
	n, err := unwrap(n)
	if err != nil {
		return nil, err
	}
	switch v := n.(type) {
	case nil, *ast.NullNode:
		return nil, nil
	case *ast.MappingNode:
		return v.Values, nil
	case *ast.MappingValueNode:
		return []*ast.MappingValueNode{v}, nil
	}
	return nil, fmt.Errorf("%s is no mapping", n.GetPath())
}

// items returns the elements of a sequence. A null node has none.
func items(n ast.Node) ([]ast.Node, error) {
	n, err := unwrap(n)
	if err != nil {
		return nil, err
	}
	switch v := n.(type) {
	case nil, *ast.NullNode:
		return nil, nil
	case *ast.SequenceNode:
		return v.Values, nil
	}
	return nil, fmt.Errorf("%s is no sequence", n.GetPath())
}

// keyOf returns the text of an entry's key.
func keyOf(entry *ast.MappingValueNode) (string, error) {
	scalar, ok := entry.Key.(ast.ScalarNode)
	if !ok {
		return "", fmt.Errorf("%s has a key that is no scalar", entry.GetPath())
	}
	if s, ok := scalar.(*ast.StringNode); ok {
		return s.Value, nil
	}
	return scalar.GetToken().Value, nil
}

// child returns the value of a mapping's entry key, or nil.
func child(n ast.Node, key string) (*ast.MappingValueNode, error) {
	list, err := entries(n)
	if err != nil {
		return nil, err
	}
	for _, entry := range list {
		k, err := keyOf(entry)
		if err != nil {
			return nil, err
		}
		if k == key {
			return entry, nil
		}
	}
	return nil, nil
}

// decoded returns the values of key that gopkg.in/yaml.v2 decodes from the
// mapping n, in the order it decodes them: each entry of key, and where a
// merge key stands, the values of key in the mappings it merges, the first
// mapping of a list last. The last value is the one a struct keeps.
func decoded(n ast.Node, key string) ([]ast.Node, error) {
	list, err := entries(n)
	if err != nil {
		return nil, err
	}
	var values []ast.Node
	for _, entry := range list {
		if _, merge := entry.Key.(*ast.MergeKeyNode); !merge {
			name, err := keyOf(entry)
			if err != nil {
				return nil, err
			}
			if name == key {
				values = append(values, entry.Value)
			}
			continue
		}
		sources, err := mergedMappings(entry.Value)
		if err != nil {
			return nil, err
		}
		for _, source := range slices.Backward(sources) {
			merged, err := decoded(source, key)
			if err != nil {
				return nil, err
			}
			values = append(values, merged...)
		}
	}
	return values, nil
}

// mergedMappings returns the mappings a merge key merges: its value, or
// each item of a sequence.
func mergedMappings(n ast.Node) ([]ast.Node, error) {
	n, err := unwrap(n)
	if err != nil {
		return nil, err
	}
	if s, ok := n.(*ast.SequenceNode); ok {
		return s.Values, nil
	}
	return []ast.Node{n}, nil
}

// descend returns the node at a path of mapping keys, or nil when a key
// is absent.
func descend(n ast.Node, keys ...string) (ast.Node, error) {
	for _, key := range keys {
		entry, err := child(n, key)
		if err != nil || entry == nil {
			return nil, err
		}
		n = entry.Value
	}
	return n, nil
}

// dottedName returns the claim name a scalar spells, and whether the node
// is a scalar main reads as a string.
func dottedName(n ast.Node) (string, bool) {
	switch v := n.(type) {
	case *ast.StringNode:
		return v.Value, true
	case *ast.IntegerNode, *ast.FloatNode, *ast.BoolNode, *ast.InfinityNode, *ast.NanNode:
		return v.GetToken().Value, true
	}
	return "", false
}

// plainKey returns the quoted text of a plain scalar that main read as the
// string key of its text, and that the strict decoder reads as another
// type: a boolean, a float or a negative integer, such as true or 1.5. A
// non-negative integer is an array index (OpenID4VP 1.0 section 7).
func plainKey(n ast.Node) (string, bool) {
	tk := n.GetToken()
	if tk == nil || isNull(n) || tk.Type == token.DoubleQuoteType || tk.Type == token.SingleQuoteType {
		return "", false
	}
	if _, ok := n.(ast.ScalarNode); !ok {
		return "", false
	}
	var value any
	if err := yaml.Unmarshal([]byte(tk.Value), &value); err != nil {
		return "", false
	}
	switch v := value.(type) {
	case string, uint64:
		return "", false
	case int:
		if v >= 0 {
			return "", false
		}
	case int64:
		if v >= 0 {
			return "", false
		}
	}
	return strconv.Quote(tk.Value), true
}

// pointerOf reads a node written as a claims path pointer: a sequence of
// keys, nulls and indices.
func pointerOf(n ast.Node) (claimpath.Pointer, error) {
	list, err := items(n)
	if err != nil {
		return claimpath.Pointer{}, err
	}
	components := make([]claimpath.Component, 0, len(list))
	for _, item := range list {
		c, err := componentOf(item)
		if err != nil {
			return claimpath.Pointer{}, fmt.Errorf("%s: %w", item.GetPath(), err)
		}
		components = append(components, c)
	}
	return claimpath.FromComponents(components)
}

func componentOf(n ast.Node) (claimpath.Component, error) {
	n, err := unwrap(n)
	if err != nil {
		return claimpath.Component{}, err
	}
	switch v := n.(type) {
	case *ast.NullNode:
		return claimpath.All(), nil
	case *ast.IntegerNode:
		index, err := strconv.ParseUint(v.GetToken().Value, 10, 0)
		if err != nil {
			return claimpath.Component{}, fmt.Errorf("%s is no array index", v.GetToken().Value)
		}
		return claimpath.Index(uint(index)), nil
	}
	if name, ok := dottedName(n); ok && name != "" {
		return claimpath.Key(name), nil
	}
	return claimpath.Component{}, fmt.Errorf("%s is no key, null or array index", n.GetPath())
}

// plainScalar matches a key YAML reads back as the same string when it is
// written without quotes in a flow collection.
var plainScalar = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

// reservedWords are plain scalars YAML 1.1 or 1.2 reads as a null or a
// boolean.
var reservedWords = map[string]bool{
	"null": true, "true": true, "false": true, "yes": true, "no": true,
	"on": true, "off": true, "y": true, "n": true,
}

// scalarText renders a key as a YAML flow scalar.
func scalarText(key string) string {
	if plainScalar.MatchString(key) && !reservedWords[strings.ToLower(key)] {
		return key
	}
	return strconv.Quote(key)
}

// pointerText renders a pointer as a YAML flow sequence.
func pointerText(p claimpath.Pointer) (string, error) {
	components, err := p.Components()
	if err != nil {
		return "", err
	}
	parts := make([]string, len(components))
	for i, c := range components {
		if key, ok := c.KeyName(); ok {
			parts[i] = scalarText(key)
			continue
		}
		if index, ok := c.IndexValue(); ok {
			parts[i] = strconv.FormatUint(uint64(index), 10)
			continue
		}
		parts[i] = "null"
	}
	return "[" + strings.Join(parts, ", ") + "]", nil
}
