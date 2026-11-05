package legacyclaims

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"gopkg.in/yaml.v2"
)

// ErrInPlace refuses a rewrite in place of a document whose YAML aliases,
// merge keys or repeated keys read claim spellings that the rewrite cannot
// reach, or would give another meaning.
var ErrInPlace = errors.New("its YAML aliases, merge keys or repeated keys read claim spellings that cannot be rewritten in place")

// maxFlattened bounds the text the aliases of a document expand to.
const maxFlattened = 64 << 20

// layout is what flattening reads of a document beyond its nodes.
type layout struct {
	// targets maps each alias to the node its anchor names.
	targets map[*ast.AliasNode]ast.Node
	// owners maps each node of a block collection to the position of the
	// key or dash that holds it.
	owners map[ast.Node]*token.Position
	// special holds each node whose text holds an alias, a merge key or a
	// key its mapping repeats.
	special map[ast.Node]bool
}

// scanLayout reads the layout of a document's root.
func scanLayout(root ast.Node) (layout, error) {
	l := layout{
		targets: map[*ast.AliasNode]ast.Node{},
		owners:  map[ast.Node]*token.Position{},
		special: map[ast.Node]bool{},
	}
	_, err := l.scan(root, nil, map[string]ast.Node{})
	return l, err
}

// scan reads the layout of n and the nodes below it, in document order.
// owner is the position of the key or dash that holds n in a block
// collection, and nil elsewhere. anchors maps each anchor name to the node
// it names, and a later anchor of the same name replaces it, as in
// gopkg.in/yaml.v2.
func (l *layout) scan(n ast.Node, owner *token.Position, anchors map[string]ast.Node) (bool, error) {
	if n == nil {
		return false, nil
	}
	if owner != nil {
		l.owners[n] = owner
	}
	special, err := l.scanBelow(n, owner, anchors)
	if special {
		l.special[n] = true
	}
	return special, err
}

func (l *layout) scanBelow(n ast.Node, owner *token.Position, anchors map[string]ast.Node) (bool, error) {
	switch v := n.(type) {
	case *ast.AnchorNode:
		anchors[v.Name.GetToken().Value] = v.Value
		return l.scan(v.Value, owner, anchors)
	case *ast.TagNode:
		return l.scan(v.Value, owner, anchors)
	case *ast.AliasNode:
		name := v.Value.GetToken().Value
		target, ok := anchors[name]
		if !ok {
			return false, fmt.Errorf("line %d: unknown anchor '%s' referenced", v.GetToken().Position.Line, name)
		}
		l.targets[v] = target
		return true, nil
	case *ast.MappingNode:
		return l.scanEntries(v.Values, v.IsFlowStyle, anchors)
	case *ast.MappingValueNode:
		return l.scanEntries([]*ast.MappingValueNode{v}, v.IsFlowStyle, anchors)
	case *ast.SequenceNode:
		special := false
		for i, item := range v.Values {
			s, err := l.scan(item, entryPosition(v, i), anchors)
			if err != nil {
				return false, err
			}
			special = special || s
		}
		return special, nil
	case *ast.MappingKeyNode:
		return l.scan(v.Value, nil, anchors)
	}
	return false, nil
}

// scanEntries reads the layout of the entries of a mapping.
func (l *layout) scanEntries(entries []*ast.MappingValueNode, flow bool, anchors map[string]ast.Node) (bool, error) {
	special := false
	names := map[string]bool{}
	for _, mv := range entries {
		if _, merge := mv.Key.(*ast.MergeKeyNode); merge {
			special = true
		} else if name, ok := scalarKey(unwrapKey(mv.Key)); ok {
			special = special || names[name]
			names[name] = true
		}
		keySpecial, err := l.scan(mv.Key, nil, anchors)
		if err != nil {
			return false, err
		}
		var owner *token.Position
		if !flow {
			owner = mv.Key.GetToken().Position
		}
		valueSpecial, err := l.scan(mv.Value, owner, anchors)
		if err != nil {
			return false, err
		}
		special = special || keySpecial || valueSpecial
	}
	return special, nil
}

// entryPosition returns the position of the dash of item i of a block
// sequence, and nil for a flow sequence.
func entryPosition(s *ast.SequenceNode, i int) *token.Position {
	if s.IsFlowStyle || i >= len(s.Entries) || s.Entries[i] == nil || s.Entries[i].Start == nil {
		return nil
	}
	return s.Entries[i].Start.Position
}

// unwrapKey returns the key an anchor or a tag annotates.
func unwrapKey(key ast.Node) ast.Node {
	for {
		switch v := key.(type) {
		case *ast.AnchorNode:
			key = v.Value
		case *ast.TagNode:
			key = v.Value
		default:
			return key
		}
	}
}

// scalarKey returns the text of a scalar key.
func scalarKey(key ast.Node) (string, bool) {
	switch v := key.(type) {
	case *ast.StringNode:
		return v.Value, true
	case *ast.AnchorNode, *ast.TagNode, *ast.AliasNode, *ast.MergeKeyNode, *ast.MappingKeyNode:
		return "", false
	case ast.ScalarNode:
		if tk := v.GetToken(); tk != nil {
			return tk.Value, true
		}
	}
	return "", false
}

// Flattens reports whether the document holds an alias, a merge key or a
// key a mapping repeats.
func (d *Document) Flattens() bool {
	return d.root != nil && d.layout.special[d.root]
}

// Resolve parses the YAML text of file as Parse does. When the document
// holds an alias, a merge key or a key a mapping repeats, the upgrade
// reads the text gopkg.in/yaml.v2 decodes from it into a value of type
// root: each alias as the node it names, and each mapping as the entries
// it sets, less the keys no field of a struct reads. Each rewrite names
// the line of file that holds the spelling.
func Resolve(file string, src []byte, root reflect.Type) (*Document, error) {
	d, err := Parse(file, src)
	if err != nil || !d.Flattens() {
		return d, err
	}
	f := d.flattener()
	if err := f.value([]ast.Node{d.root}, root, -1); err != nil {
		return nil, d.fail(err)
	}
	f.out.write("\n", lastLine(d.root))
	flat, err := Parse(file, f.out.buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%s: the text without aliases, merge keys and repeated keys: %w", file, err)
	}
	if flat.Flattens() {
		return nil, fmt.Errorf("%s: the text without aliases, merge keys and repeated keys still holds one", file)
	}
	flat.origin = f.out.origin
	return flat, nil
}

// rootKeys returns the keys the root mapping of the document sets,
// through its merge keys.
func (d *Document) rootKeys() ([]string, error) {
	f := d.flattener()
	if d.root == nil || !f.isMapping(d.root) {
		return nil, nil
	}
	fields, err := f.fields([]ast.Node{d.root}, nil)
	if err != nil {
		return nil, d.fail(err)
	}
	keys := make([]string, len(fields))
	for i, field := range fields {
		keys[i] = field.name
	}
	return keys, nil
}

// segment is a part of the flattened text that comes from one line of the
// file. It reaches to the start of the next segment.
type segment struct{ start, line int }

// output is the flattened text and the line of the file each part of it
// comes from.
type output struct {
	buf    bytes.Buffer
	origin []segment
}

// write appends text that comes from line of the file.
func (o *output) write(text string, line int) {
	if n := len(o.origin); n == 0 || o.origin[n-1].line != line {
		o.origin = append(o.origin, segment{start: o.buf.Len(), line: line})
	}
	o.buf.WriteString(text)
}

// newline starts a line at column col.
func (o *output) newline(col, line int) {
	indentation := strings.Repeat(" ", max(col-1, 0))
	if o.buf.Len() == 0 {
		o.write(indentation, line)
		return
	}
	o.write("\n"+indentation, line)
}

// flattener writes the text gopkg.in/yaml.v2 decodes from a document,
// without aliases, merge keys or repeated keys. It copies each part of the
// text that holds none of them, re-indented.
type flattener struct {
	d   *Document
	out output
	// expanding holds the nodes the aliases being written name, and
	// merging the mappings whose merge keys are being read.
	expanding, merging map[ast.Node]bool
	// decodes counts the values written, aliased those written for an
	// alias, and depth the aliases being written, which gopkg.in/yaml.v2's
	// limit on aliasing reads.
	decodes, aliased, depth int
}

func (d *Document) flattener() *flattener {
	return &flattener{d: d, expanding: map[ast.Node]bool{}, merging: map[ast.Node]bool{}}
}

// value writes the value of an entry or a sequence item whose key or dash
// is at column col of the line being written. A field that a mapping sets
// more than once has several layers, which value writes as the one value
// gopkg.in/yaml.v2 decodes from them into type t.
func (f *flattener) value(layers []ast.Node, t reflect.Type, col int) error {
	if err := f.count(); err != nil {
		return err
	}
	return f.write(layers, t, col)
}

func (f *flattener) write(layers []ast.Node, t reflect.Type, col int) error {
	if len(layers) == 1 {
		switch v := layers[0].(type) {
		case *ast.AnchorNode:
			return f.write([]ast.Node{v.Value}, t, col)
		case *ast.TagNode:
			start, end, err := f.d.tokenSpan(v.Start)
			if err != nil {
				return err
			}
			f.out.write(" "+string(f.d.src[start:end]), v.Start.Position.Line)
			return f.write([]ast.Node{v.Value}, t, col)
		case *ast.AliasNode:
			return f.alias(v, t, col)
		}
		if !f.d.layout.special[layers[0]] {
			copied, err := f.copy(layers[0], col)
			if copied || err != nil {
				return err
			}
		}
	}
	switch v := f.target(layers[len(layers)-1]).(type) {
	case *ast.MappingNode, *ast.MappingValueNode:
		return f.mapping(layers, t, col)
	case *ast.SequenceNode:
		return f.sequence(v, t, col)
	}
	return f.scalar(layers[len(layers)-1], col)
}

// count counts a value, and refuses the aliasing gopkg.in/yaml.v2
// refuses.
func (f *flattener) count() error {
	f.decodes++
	if f.depth > 0 {
		f.aliased++
	}
	if f.aliased > 100 && f.decodes > 1000 && float64(f.aliased)/float64(f.decodes) > allowedAliasRatio(f.decodes) {
		return errors.New("document contains excessive aliasing")
	}
	if f.out.buf.Len() > maxFlattened {
		return fmt.Errorf("the aliases expand beyond %d bytes", maxFlattened)
	}
	return nil
}

// allowedAliasRatio is gopkg.in/yaml.v2's bound on the share of values
// decoded for an alias.
func allowedAliasRatio(decodes int) float64 {
	const low, high = 400000, 4000000
	switch {
	case decodes <= low:
		return 0.99
	case decodes >= high:
		return 0.10
	}
	return 0.99 - 0.89*(float64(decodes-low)/float64(high-low))
}

// alias writes the node an alias names.
func (f *flattener) alias(v *ast.AliasNode, t reflect.Type, col int) error {
	target := f.d.layout.targets[v]
	if f.expanding[target] {
		return fmt.Errorf("line %d: anchor '%s' value contains itself", v.GetToken().Position.Line, v.Value.GetToken().Value)
	}
	f.expanding[target] = true
	f.depth++
	err := f.value([]ast.Node{target}, t, col)
	f.depth--
	delete(f.expanding, target)
	return err
}

// target returns the node an anchor, a tag or an alias stands for.
func (f *flattener) target(n ast.Node) ast.Node {
	for range len(f.d.layout.targets) + 1 {
		switch v := n.(type) {
		case *ast.AnchorNode:
			n = v.Value
		case *ast.TagNode:
			n = v.Value
		case *ast.AliasNode:
			n = f.d.layout.targets[v]
		default:
			return n
		}
	}
	return n
}

// isMapping reports whether a node stands for a mapping.
func (f *flattener) isMapping(n ast.Node) bool {
	switch f.target(n).(type) {
	case *ast.MappingNode, *ast.MappingValueNode:
		return true
	}
	return false
}

// field is a key a mapping sets, and the values gopkg.in/yaml.v2 decodes
// into it in order.
type field struct {
	key    ast.MapKeyNode
	name   string
	layers []ast.Node
}

// fields returns the keys the layers of a mapping set, in the order of
// their first entry, as gopkg.in/yaml.v2 decodes the layers into type t:
// a merge key sets the entries of its mappings where it stands, the first
// mapping of a list last, and a later entry replaces an earlier one. A
// mapping that sets a field of a struct again adds to it when the field
// is a struct, whose fields it sets, or a map, which it adds entries to.
func (f *flattener) fields(layers []ast.Node, t reflect.Type) ([]*field, error) {
	var out []*field
	byName := map[string]*field{}
	set := func(key ast.MapKeyNode, value ast.Node) error {
		name, err := f.keyName(key)
		if err != nil {
			return err
		}
		prev := byName[name]
		switch {
		case prev == nil:
			field := &field{key: key, name: name, layers: []ast.Node{value}}
			byName[name] = field
			out = append(out, field)
		case combines(t, name) && f.isMapping(prev.layers[len(prev.layers)-1]) && f.isMapping(value):
			prev.layers = append(prev.layers, value)
		default:
			prev.layers = []ast.Node{value}
		}
		return nil
	}
	for _, layer := range layers {
		if err := f.apply(layer, set); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// apply calls set for each entry of the mapping n stands for, in the order
// gopkg.in/yaml.v2 decodes them.
func (f *flattener) apply(n ast.Node, set func(ast.MapKeyNode, ast.Node) error) error {
	mapping := f.target(n)
	if f.merging[mapping] {
		return fmt.Errorf("line %d: a merge key merges the mapping that holds it", n.GetToken().Position.Line)
	}
	f.merging[mapping] = true
	defer delete(f.merging, mapping)
	list, err := entries(mapping)
	if err != nil {
		return err
	}
	for _, mv := range list {
		if _, merge := mv.Key.(*ast.MergeKeyNode); !merge {
			if err := set(mv.Key, mv.Value); err != nil {
				return err
			}
			continue
		}
		sources, err := f.mergeSources(mv.Value)
		if err != nil {
			return err
		}
		for _, source := range slices.Backward(sources) {
			if err := f.apply(source, set); err != nil {
				return err
			}
		}
	}
	return nil
}

// mergeSources returns the mappings a merge key merges.
func (f *flattener) mergeSources(n ast.Node) ([]ast.Node, error) {
	sources := []ast.Node{n}
	if s, ok := f.target(n).(*ast.SequenceNode); ok {
		sources = s.Values
	}
	if slices.ContainsFunc(sources, func(s ast.Node) bool { return !f.isMapping(s) }) {
		return nil, fmt.Errorf("line %d: map merge requires map or sequence of maps as the value", n.GetToken().Position.Line)
	}
	return sources, nil
}

// keyName returns the text of a key, through an anchor, a tag or an alias.
func (f *flattener) keyName(key ast.MapKeyNode) (string, error) {
	if name, ok := scalarKey(f.target(key)); ok {
		return name, nil
	}
	return "", fmt.Errorf("line %d: a key that is no scalar", key.GetToken().Position.Line)
}

// keyText returns the text of a key as written, through an anchor, a tag
// or an alias.
func (f *flattener) keyText(key ast.MapKeyNode) (string, error) {
	n := f.target(key)
	if _, ok := scalarKey(n); !ok {
		return "", fmt.Errorf("line %d: a key that is no scalar", key.GetToken().Position.Line)
	}
	return f.d.text(n)
}

// mapping writes the mapping the layers set, in block style. It leaves
// out each field of a struct that gopkg.in/yaml.v2 skips.
func (f *flattener) mapping(layers []ast.Node, t reflect.Type, col int) error {
	fields, err := f.fields(layers, t)
	if err != nil {
		return err
	}
	written := false
	for _, field := range fields {
		ft, read := fieldType(t, field.name)
		if !read {
			continue
		}
		line := field.key.GetToken().Position.Line
		text, err := f.keyText(field.key)
		if err != nil {
			return err
		}
		f.out.newline(col+2, line)
		f.out.write(text+":", line)
		if err := f.value(field.layers, ft, col+2); err != nil {
			return err
		}
		written = true
	}
	if !written {
		f.out.write(" {}", f.target(layers[0]).GetToken().Position.Line)
	}
	return nil
}

// sequence writes a sequence in block style.
func (f *flattener) sequence(s *ast.SequenceNode, t reflect.Type, col int) error {
	if len(s.Values) == 0 {
		f.out.write(" []", s.GetToken().Position.Line)
		return nil
	}
	element := elementType(t)
	for i, item := range s.Values {
		line := item.GetToken().Position.Line
		if dash := entryPosition(s, i); dash != nil {
			line = dash.Line
		}
		f.out.newline(col+2, line)
		f.out.write("-", line)
		if err := f.value([]ast.Node{item}, element, col+2); err != nil {
			return err
		}
	}
	return nil
}

// scalar writes a scalar of a flow collection that spans lines. Each line
// after the first starts one column past the key or dash, which leaves the
// value of a plain or quoted scalar as it was.
func (f *flattener) scalar(n ast.Node, col int) error {
	tk := n.GetToken()
	start, end, err := f.d.tokenSpan(tk)
	if err != nil {
		return err
	}
	for i, line := range strings.Split(string(f.d.src[start:end]), "\n") {
		if i == 0 {
			f.out.write(" "+line, tk.Position.Line)
			continue
		}
		f.out.newline(col+1, tk.Position.Line+i)
		f.out.write(strings.TrimLeft(line, " \t"), tk.Position.Line+i)
	}
	return nil
}

// copy writes the text of a node that holds no alias, merge key or
// repeated key, re-indented to a key or dash at column col. It reports
// false when the text cannot move there, and write writes the node from
// its parts instead.
func (f *flattener) copy(n ast.Node, col int) (bool, error) {
	switch v := n.(type) {
	case *ast.MappingNode:
		if !v.IsFlowStyle && len(v.Values) > 0 {
			return f.copyBlock(n, v.Values[0].Key.GetToken(), col)
		}
	case *ast.MappingValueNode:
		if !v.IsFlowStyle {
			return f.copyBlock(n, v.Key.GetToken(), col)
		}
	case *ast.SequenceNode:
		if !v.IsFlowStyle && len(v.Entries) > 0 {
			return f.copyBlock(n, v.Entries[0].Start, col)
		}
	}
	return f.copyInline(n, col)
}

// copyBlock writes a block collection from its first token, on the line
// after the key or dash at column col and at column col+2. The lines after
// the first move as far as the first token.
func (f *flattener) copyBlock(n ast.Node, first *token.Token, col int) (bool, error) {
	if first == nil || first.Position == nil {
		return false, nil
	}
	start, err := f.d.offset(first.Position)
	if err != nil {
		return false, err
	}
	line := first.Position.Line
	rest, ok := f.moved(line+1, f.lastLine(n), col+2-first.Position.Column, col)
	if !ok {
		return false, nil
	}
	f.out.newline(col+2, line)
	f.out.write(strings.TrimRight(string(f.d.src[start:f.d.lineEnd(line)]), "\r"), line)
	for i, text := range rest {
		f.out.write("\n"+text, line+1+i)
	}
	return true, nil
}

// copyInline writes a node on the line of its key or dash. The lines after
// the first move as far as the key or dash.
func (f *flattener) copyInline(n ast.Node, col int) (bool, error) {
	if tk := n.GetToken(); isNull(n) && (tk == nil || strings.TrimSpace(tk.Origin) == "") {
		return true, nil
	}
	start, err := f.startOffset(n)
	if err != nil {
		return false, err
	}
	line := f.d.lineOf(start)
	last := f.lastLine(n)
	if last == line {
		end, err := f.endOffset(n)
		if err != nil {
			return false, err
		}
		f.out.write(" "+string(f.d.src[start:end]), line)
		return true, nil
	}
	owner := f.d.layout.owners[n]
	if owner == nil {
		return false, nil
	}
	rest, ok := f.moved(line+1, last, col-owner.Column, -1)
	if !ok {
		return false, nil
	}
	f.out.write(" "+strings.TrimRight(string(f.d.src[start:f.d.lineEnd(line)]), "\r"), line)
	for i, text := range rest {
		f.out.write("\n"+text, line+1+i)
	}
	return true, nil
}

// lastLine returns the last line of a node's text, and with a block
// scalar that keeps its final line breaks, the blank lines after it.
func (f *flattener) lastLine(n ast.Node) int {
	last := lastLine(n)
	keeps := false
	ast.Walk(visitFunc(func(child ast.Node) {
		if literal, ok := child.(*ast.LiteralNode); ok && strings.Contains(literal.Start.Value, "+") {
			keeps = true
		}
	}), n)
	for keeps && last < len(f.d.lines) && len(bytes.TrimSpace(f.d.src[f.d.lineStart(last+1):f.d.lineEnd(last+1)])) == 0 {
		last++
	}
	return last
}

// moved returns lines first through last of the file, each moved shift
// columns. It reports false when a line would start before column 1, or a
// line other than a blank line or a comment before column floor+1.
func (f *flattener) moved(first, last, shift, floor int) ([]string, bool) {
	lines := make([]string, 0, max(last-first+1, 0))
	for line := first; line <= last; line++ {
		text := strings.TrimRight(string(f.d.src[f.d.lineStart(line):f.d.lineEnd(line)]), "\r")
		content := strings.TrimLeft(text, " ")
		indentation := len(text) - len(content) + shift
		blank := strings.TrimSpace(content) == ""
		switch {
		case blank && indentation < 0:
			lines = append(lines, "")
			continue
		case indentation < 0, !blank && !strings.HasPrefix(content, "#") && indentation < floor:
			return nil, false
		}
		lines = append(lines, strings.Repeat(" ", indentation)+content)
	}
	return lines, true
}

// startOffset returns the offset of the first token of a node written
// inline.
func (f *flattener) startOffset(n ast.Node) (int, error) {
	switch v := n.(type) {
	case *ast.MappingNode:
		if v.IsFlowStyle {
			return f.d.offset(v.Start.Position)
		}
	case *ast.SequenceNode:
		if v.IsFlowStyle {
			return f.d.offset(v.Start.Position)
		}
	case *ast.LiteralNode:
		start, _, err := f.d.tokenSpan(v.Start)
		return start, err
	}
	start, _, err := f.d.tokenSpan(n.GetToken())
	return start, err
}

// endOffset returns the offset just past a node written on one line.
func (f *flattener) endOffset(n ast.Node) (int, error) {
	if v, ok := n.(*ast.LiteralNode); ok {
		_, end, err := f.d.tokenSpan(v.Start)
		return end, err
	}
	_, end, err := f.d.span(n)
	return end, err
}

// yamlUnmarshaler is the interface of a type that decodes its own YAML.
var yamlUnmarshaler = reflect.TypeFor[yaml.Unmarshaler]()

// claimMappingsType decodes the claim_mappings the earlier release read as
// a map.
var claimMappingsType = reflect.TypeFor[openid4vp.ClaimMappings]()

// decodesItself reports whether a type decodes its own YAML.
func decodesItself(t reflect.Type) bool {
	return t.Implements(yamlUnmarshaler) || reflect.PointerTo(t).Implements(yamlUnmarshaler)
}

// indirect returns the type a pointer type points to.
func indirect(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// isStruct reports whether gopkg.in/yaml.v2 decodes a mapping into the
// fields of a value of type t.
func isStruct(t reflect.Type) bool {
	t = indirect(t)
	return t != nil && t.Kind() == reflect.Struct && !decodesItself(t)
}

// combines reports whether a mapping that sets the field name of a struct
// of type parent again adds to the field's value: a struct, a map, or a
// map of claims of the earlier release.
func combines(parent reflect.Type, name string) bool {
	if !isStruct(parent) {
		return false
	}
	t, read := fieldType(parent, name)
	t = indirect(t)
	if !read || t == nil {
		return false
	}
	if decodesItself(t) {
		return t == claimMappingsType
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Map, reflect.Slice:
		return true
	}
	return false
}

// fieldType returns the type of the value at key name of a mapping
// decoded into type t, or nil when that type is unknown, and whether
// gopkg.in/yaml.v2 reads the value. It skips the value of a key no field
// of a struct names.
func fieldType(t reflect.Type, name string) (reflect.Type, bool) {
	t = indirect(t)
	switch {
	case t == nil || decodesItself(t):
		return nil, true
	case t.Kind() == reflect.Map:
		return t.Elem(), true
	case t.Kind() == reflect.Interface:
		return t, true
	case t.Kind() != reflect.Struct:
		return nil, true
	}
	for i := range t.NumField() {
		sf := t.Field(i)
		key, flags, _ := strings.Cut(sf.Tag.Get("yaml"), ",")
		switch {
		case key == "-" || !sf.IsExported():
			continue
		case slices.Contains(strings.Split(flags, ","), "inline"):
			if inner, read := fieldType(sf.Type, name); read {
				return inner, true
			}
			continue
		case key == "":
			key = strings.ToLower(sf.Name)
		}
		if key == name {
			return sf.Type, true
		}
	}
	return nil, false
}

// elementType returns the type of the items of a sequence decoded into
// type t.
func elementType(t reflect.Type) reflect.Type {
	t = indirect(t)
	switch {
	case t == nil || decodesItself(t):
		return nil
	case t.Kind() == reflect.Slice, t.Kind() == reflect.Array:
		return t.Elem()
	case t.Kind() == reflect.Interface:
		return t
	}
	return nil
}
