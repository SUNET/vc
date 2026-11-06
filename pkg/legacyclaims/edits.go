package legacyclaims

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
)

// reader reads main's dotted name of a claim in one role.
type reader func(name string) (claimpath.Pointer, error)

// pointer reads the claims path pointer a node holds. A scalar is main's
// dotted name: read rewrites it as a sequence and records the rewrite. It
// returns the zero pointer for a null node, and the dotted name it
// rewrote, which is empty when the node holds no scalar.
func (d *Document) pointer(n ast.Node, read reader) (claimpath.Pointer, string, error) {
	c, err := readClaim(n, read)
	if err != nil || c.name == "" {
		return c.path, "", err
	}
	return c.path, c.name, d.replaceScalar(c.node, c.path)
}

// claimNode is the claim a node holds: a pointer, or main's dotted name
// and the pointer a role reads it as.
type claimNode struct {
	path claimpath.Pointer
	// name is the dotted name, and node its scalar; name is empty for a
	// node that holds a pointer or null.
	name string
	node ast.Node
}

// readClaim reads the claim a node holds, reading a dotted name with
// read.
func readClaim(n ast.Node, read reader) (claimNode, error) {
	n, err := unwrap(n)
	if err != nil || isNull(n) {
		return claimNode{}, err
	}
	name, scalar := dottedName(n)
	if !scalar {
		p, err := pointerOf(n)
		return claimNode{path: p}, err
	}
	if name == "" {
		return claimNode{}, fmt.Errorf("%s: the claim name is empty", n.GetPath())
	}
	p, err := read(name)
	if err != nil {
		return claimNode{}, fmt.Errorf("%s: %w", n.GetPath(), err)
	}
	return claimNode{path: p, name: name, node: n}, nil
}

// carry writes a dotted name that a role looked up as one top-level key
// before the claim its pointer names. The loader replaces the scalar with
// the mapping {dotted: <name>, path: <pointer>}, which reads in that
// order; the converter leaves the scalar as written. Both record the
// spelling with the reason the converter leaves it.
func (d *Document) carry(c claimNode, convert bool) error {
	text, err := pointerText(c.path)
	if err != nil {
		return err
	}
	start, end, err := d.span(c.node)
	if err != nil {
		return err
	}
	if !convert {
		d.replace(start, end, "{dotted: "+scalarText(c.name)+", path: "+text+"}")
	}
	key := strconv.Quote(c.name)
	note := fmt.Sprintf("it reads the key %s before %s; write %s when the claims hold no key %s", key, text, text, key)
	return d.recordKept(c.node, string(d.src[start:end]), text, note)
}

// ErrUpgradedRef refuses the mapping {dotted, path} where a file writes a
// claim. The loader writes that mapping for a dotted name a role looks up
// as one top-level key first. A file writes the name, which warns at load,
// or a claims path pointer.
var ErrUpgradedRef = errors.New("the mapping {dotted, path} is the form the loader gives a dotted claim name; write the name or a claims path pointer")

// refuseUpgradedRefs refuses the mapping {dotted, path} where n holds it
// as a claim: as the value of one of keys, or as an element of a sequence
// that value is. It reads each mapping a merge key adds where the merge
// key writes it. The loader resolves each alias before it reads a file,
// and the decode of that text meets the mapping an alias stands for.
func refuseUpgradedRefs(n ast.Node, keys ...string) error {
	if isNull(n) {
		return nil
	}
	var found ast.Node
	ast.Walk(visitFunc(func(child ast.Node) {
		entry, ok := child.(*ast.MappingValueNode)
		if !ok || found != nil {
			return
		}
		name, ok := scalarKey(annotated(entry.Key))
		if !ok || !slices.Contains(keys, name) {
			return
		}
		claims := []ast.Node{entry.Value}
		if list, ok := annotated(entry.Value).(*ast.SequenceNode); ok {
			claims = list.Values
		}
		if i := slices.IndexFunc(claims, isUpgradedRef); i >= 0 {
			found = claims[i]
		}
	}), n)
	if found != nil {
		return fmt.Errorf("%s: %w", found.GetPath(), ErrUpgradedRef)
	}
	return nil
}

// isUpgradedRef reports whether a node is a mapping with the key dotted.
func isUpgradedRef(n ast.Node) bool {
	var list []*ast.MappingValueNode
	switch v := annotated(n).(type) {
	case *ast.MappingNode:
		list = v.Values
	case *ast.MappingValueNode:
		list = []*ast.MappingValueNode{v}
	}
	return slices.ContainsFunc(list, func(entry *ast.MappingValueNode) bool {
		name, ok := scalarKey(annotated(entry.Key))
		return ok && name == "dotted"
	})
}

// replaceScalar replaces a scalar with the sequence of a pointer.
func (d *Document) replaceScalar(n ast.Node, p claimpath.Pointer) error {
	text, err := pointerText(p)
	if err != nil {
		return err
	}
	start, end, err := d.span(n)
	if err != nil {
		return err
	}
	d.replace(start, end, text)
	return d.record(n, string(d.src[start:end]), text)
}

// listEntry is one entry of a map keyed by dotted names, in the list form.
type listEntry struct {
	// keyField names the field the key becomes, such as "path".
	keyField string
	// key is the pointer the dotted key reads as.
	key claimpath.Pointer
	// dotted is set when the loader carries the dotted key beside key:
	// it writes the mapping {dotted, path}, and records the pointer.
	dotted string
	// valueField names the field the value becomes, such as "values".
	valueField string
	// value replaces a scalar value when set.
	value *claimpath.Pointer
	// omitEmpty leaves out the value field when the value is an empty
	// list, which reads as no value.
	omitEmpty bool
	// note ends the rewrite record with what else the entry changes.
	note string
}

// convertMap rewrites a map keyed by dotted names in the list form, one
// item per entry, and records one rewrite per entry. entry gives the list
// item of each map entry.
func (d *Document) convertMap(n ast.Node, entry func(key string, value ast.Node) (listEntry, error)) error {
	n, err := unwrap(n)
	if err != nil {
		return err
	}
	mapping, ok := n.(*ast.MappingNode)
	if !ok {
		return fmt.Errorf("%s is no mapping", n.GetPath())
	}
	if mapping.IsFlowStyle {
		if err := d.flowBrackets(mapping); err != nil {
			return err
		}
	}
	for _, mv := range mapping.Values {
		key, err := keyOf(mv)
		if err != nil {
			return err
		}
		item, err := entry(key, mv.Value)
		if err != nil {
			return fmt.Errorf("%s: %w", mv.GetPath(), err)
		}
		if err := d.convertEntry(mapping, mv, item); err != nil {
			return err
		}
	}
	return nil
}

// flowBrackets turns the braces of a flow mapping into the brackets of a
// flow sequence.
func (d *Document) flowBrackets(mapping *ast.MappingNode) error {
	start, end, err := d.flowSpan(mapping.Start, mapping.End)
	if err != nil {
		return err
	}
	d.replace(start, start+1, "[")
	d.replace(end-1, end, "]")
	return nil
}

// convertEntry rewrites one map entry as a list item.
func (d *Document) convertEntry(mapping *ast.MappingNode, mv *ast.MappingValueNode, item listEntry) error {
	keyStart, _, err := d.span(mv.Key)
	if err != nil {
		return err
	}
	colon, err := d.offset(mv.Start.Position)
	if err != nil {
		return err
	}
	keyText, err := pointerText(item.key)
	if err != nil {
		return err
	}
	oldKey := string(d.src[keyStart:colon])
	head := item.keyField + ": " + keyText
	written := head
	if item.dotted != "" {
		written = item.keyField + ": {dotted: " + scalarText(item.dotted) + ", path: " + keyText + "}"
	}
	empty, err := isEmptyList(mv.Value)
	if err != nil {
		return err
	}
	if item.omitEmpty && empty {
		return d.convertBareEntry(mapping, mv, item, keyStart, strings.TrimSpace(oldKey), written, head)
	}
	if mapping.IsFlowStyle {
		d.replace(keyStart, colon+1, "{"+written+", "+item.valueField+":")
	} else {
		column := mv.Key.GetToken().Position.Column
		d.replace(keyStart, colon+1, "- "+written+"\n"+strings.Repeat(" ", column+1)+item.valueField+":")
		if keyLine := mv.Key.GetToken().Position.Line; !isNull(mv.Value) && lastLine(mv.Value) > keyLine {
			d.indent(keyLine+1, lastLine(mv.Value), 2)
		}
	}
	valueText, err := d.convertValue(mv, item)
	if err != nil {
		return err
	}
	if mapping.IsFlowStyle {
		end, err := d.valueEnd(mv)
		if err != nil {
			return err
		}
		d.insert(end, "}")
	}
	return d.record(mv, strings.TrimSpace(oldKey)+": "+valueText.old, "{"+head+", "+item.valueField+": "+valueText.new+"}"+item.note)
}

// convertBareEntry rewrites a map entry whose value is an empty list as a
// list item without the value field: written in the text, and head in the
// record.
func (d *Document) convertBareEntry(mapping *ast.MappingNode, mv *ast.MappingValueNode, item listEntry, keyStart int, oldKey, written, head string) error {
	end, err := d.valueEnd(mv)
	if err != nil {
		return err
	}
	if mapping.IsFlowStyle {
		d.replace(keyStart, end, "{"+written+"}")
	} else {
		d.replace(keyStart, end, "- "+written)
	}
	return d.record(mv, oldKey+": []", "{"+head+"}"+item.note)
}

// isEmptyList reports whether a node is a sequence without elements.
func isEmptyList(n ast.Node) (bool, error) {
	n, err := unwrap(n)
	if err != nil {
		return false, err
	}
	sequence, ok := n.(*ast.SequenceNode)
	return ok && len(sequence.Values) == 0, nil
}

// valueTexts are the old and the new text of an entry's value, for a
// rewrite record.
type valueTexts struct{ old, new string }

// convertValue rewrites the value of an entry when the list item replaces
// it, and returns its texts.
func (d *Document) convertValue(mv *ast.MappingValueNode, item listEntry) (valueTexts, error) {
	if isNull(mv.Value) {
		return valueTexts{"null", "null"}, nil
	}
	old, err := d.text(mv.Value)
	if err != nil {
		old = "…"
	}
	if item.value == nil {
		return valueTexts{old, old}, nil
	}
	value, err := unwrap(mv.Value)
	if err != nil {
		return valueTexts{}, err
	}
	text, err := pointerText(*item.value)
	if err != nil {
		return valueTexts{}, err
	}
	start, end, err := d.span(value)
	if err != nil {
		return valueTexts{}, err
	}
	d.replace(start, end, text)
	return valueTexts{old, text}, nil
}

// valueEnd returns the offset just past an entry's value, or past its
// colon when the value is implicit.
func (d *Document) valueEnd(mv *ast.MappingValueNode) (int, error) {
	if isNull(mv.Value) && (mv.Value == nil || mv.Value.GetToken() == nil || strings.TrimSpace(mv.Value.GetToken().Origin) == "") {
		colon, err := d.offset(mv.Start.Position)
		return colon + 1, err
	}
	value, err := unwrap(mv.Value)
	if err != nil {
		return 0, err
	}
	_, end, err := d.span(value)
	return end, err
}

// addEntry adds the entry key: value to a mapping, after the entry after.
func (d *Document) addEntry(mapping *ast.MappingNode, after *ast.MappingValueNode, key, value string) error {
	if mapping.IsFlowStyle {
		end, err := d.valueEnd(after)
		if err != nil {
			return err
		}
		d.insert(end, ", "+key+": "+value)
		return nil
	}
	column := after.Key.GetToken().Position.Column
	d.insertLine(lastLine(after), strings.Repeat(" ", column-1)+key+": "+value)
	return nil
}

// insertLine inserts a line of text after line.
func (d *Document) insertLine(line int, text string) {
	if line < len(d.lines) {
		d.insert(d.lineStart(line+1), text+"\n")
		return
	}
	if d.endsInNewline() {
		d.insert(len(d.src), text+"\n")
		return
	}
	d.insert(len(d.src), "\n"+text)
}

// appendItems appends flow items to a sequence, or to a mapping convertMap
// rewrites as one.
func (d *Document) appendItems(n ast.Node, texts []string) error {
	n, err := unwrap(n)
	if err != nil {
		return err
	}
	switch v := n.(type) {
	case *ast.SequenceNode:
		if v.IsFlowStyle {
			return d.appendFlow(v.End, len(v.Values) > 0, texts)
		}
		column := v.Start.Position.Column
		return d.appendBlock(lastLine(v), column, texts)
	case *ast.MappingNode:
		if v.IsFlowStyle {
			return d.appendFlow(v.End, len(v.Values) > 0, texts)
		}
		column := v.Values[0].Key.GetToken().Position.Column
		return d.appendBlock(lastLine(v), column, texts)
	}
	return fmt.Errorf("%s is no sequence or mapping", n.GetPath())
}

// appendFlow inserts items before the closing indicator of a flow
// collection.
func (d *Document) appendFlow(end *token.Token, nonEmpty bool, texts []string) error {
	if end == nil {
		return errors.New("a flow collection has no end")
	}
	at, err := d.offset(end.Position)
	if err != nil {
		return err
	}
	text := strings.Join(texts, ", ")
	if nonEmpty {
		text = ", " + text
	}
	d.insert(at, text)
	return nil
}

// appendBlock inserts block sequence items, at column, after line.
func (d *Document) appendBlock(line, column int, texts []string) error {
	for _, text := range texts {
		d.insertLine(line, strings.Repeat(" ", column-1)+"- "+text)
	}
	return nil
}

// prependItems inserts flow items before the first item of a sequence.
func (d *Document) prependItems(n ast.Node, texts []string) error {
	n, err := unwrap(n)
	if err != nil {
		return err
	}
	sequence, ok := n.(*ast.SequenceNode)
	if !ok {
		return fmt.Errorf("%s is no sequence", n.GetPath())
	}
	if sequence.IsFlowStyle {
		start, _, err := d.flowSpan(sequence.Start, sequence.End)
		if err != nil {
			return err
		}
		text := strings.Join(texts, ", ")
		if len(sequence.Values) > 0 {
			text += ", "
		}
		d.insert(start+1, text)
		return nil
	}
	dash, err := d.offset(sequence.Start.Position)
	if err != nil {
		return err
	}
	indentation := strings.Repeat(" ", sequence.Start.Position.Column-1)
	var b strings.Builder
	for _, text := range texts {
		b.WriteString("- " + text + "\n" + indentation)
	}
	d.insert(dash, b.String())
	return nil
}
