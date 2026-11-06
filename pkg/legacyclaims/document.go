package legacyclaims

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
)

// Document is the YAML text of one file and the edits that upgrade it.
// Each edit splices the text, so every byte outside an edit, comments
// included, stays as written.
type Document struct {
	file string
	src  []byte
	// lines holds the byte offset at which each line starts.
	lines []int
	root  ast.Node
	// layout is what Resolve reads of the aliases, merge keys and repeated
	// keys below the root.
	layout layout
	// origin maps the text Resolve writes to the lines of the file, and is
	// nil for the text of the file.
	origin []segment
	edits  []edit
	// rewrites holds one record per spelling the edits upgrade.
	rewrites []Rewrite
}

// edit replaces src[start:end] with text. An edit with start == end
// inserts text.
type edit struct {
	start, end int
	text       string
}

// Rewrite is one claim spelling of an earlier release the upgrade
// rewrote, and where it was.
type Rewrite struct {
	// File is the file name.
	File string
	// Path is the YAML path of the spelling, such as
	// $.apigw.data_sources.presentation.scopes.x.from.pid.required_claims.
	Path string
	// Line is the line of the spelling, from 1.
	Line int
	// Old is the spelling as written.
	Old string
	// New is the spelling that replaces it.
	New string
	// Note says why the upgrade leaves the spelling as written, and is
	// empty when the upgrade rewrites it.
	Note string
}

// Parse parses the YAML text of file. Like gopkg.in/yaml.v2, it reads the
// first document of a stream, and a mapping may repeat a key. Comments
// before the first "---" belong to no document, and a document of comments
// holds nothing.
func Parse(file string, src []byte) (*Document, error) {
	parsed, err := parser.ParseBytes(src, parser.ParseComments, parser.AllowDuplicateMapKey())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	d := &Document{file: file, src: src, lines: lineStarts(src)}
	for _, doc := range parsed.Docs {
		_, comments := doc.Body.(*ast.CommentGroupNode)
		if comments && doc.Start == nil {
			continue
		}
		if !comments {
			d.root = doc.Body
		}
		break
	}
	if d.layout, err = scanLayout(d.root); err != nil {
		return nil, d.fail(err)
	}
	return d, nil
}

// fileLine returns the line of the file that holds an offset of the text.
func (d *Document) fileLine(offset int) int {
	if d.origin == nil {
		return d.lineOf(offset)
	}
	i, found := slices.BinarySearchFunc(d.origin, offset, func(s segment, offset int) int { return s.start - offset })
	if !found {
		i--
	}
	return d.origin[max(i, 0)].line
}

// lineAt returns the line of the file at a position of the text.
func (d *Document) lineAt(pos *token.Position) (int, error) {
	if pos == nil {
		return 0, errors.New("a YAML token has no position in the text")
	}
	if d.origin == nil {
		return pos.Line, nil
	}
	offset, err := d.offset(pos)
	if err != nil {
		return 0, err
	}
	return d.fileLine(offset), nil
}

// fail names the file in an error of an upgrade.
func (d *Document) fail(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", d.file, err)
}

// lineStarts returns the byte offset of the start of each line of src.
func lineStarts(src []byte) []int {
	starts := []int{0}
	for i, b := range src {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// Rewrites returns one record per upgraded spelling, in document order.
func (d *Document) Rewrites() []Rewrite {
	out := slices.Clone(d.rewrites)
	slices.SortStableFunc(out, func(a, b Rewrite) int { return a.Line - b.Line })
	return out
}

// Bytes returns the text with every edit applied.
func (d *Document) Bytes() ([]byte, error) {
	edits := slices.Clone(d.edits)
	slices.SortStableFunc(edits, func(a, b edit) int {
		if a.start != b.start {
			return a.start - b.start
		}
		// An insertion at an offset goes before a replacement there.
		return (a.end - a.start) - (b.end - b.start)
	})
	var out bytes.Buffer
	at := 0
	for _, e := range edits {
		if e.start < at {
			return nil, fmt.Errorf("%s: two upgrades of the claim spellings overlap at line %d", d.file, d.fileLine(e.start))
		}
		out.Write(d.src[at:e.start])
		out.WriteString(e.text)
		at = e.end
	}
	out.Write(d.src[at:])
	return out.Bytes(), nil
}

// lineOf returns the line, from 1, of a byte offset.
func (d *Document) lineOf(offset int) int {
	i, found := slices.BinarySearch(d.lines, offset)
	if found {
		return i + 1
	}
	return i
}

// replace replaces src[start:end] with text.
func (d *Document) replace(start, end int, text string) {
	d.edits = append(d.edits, edit{start: start, end: end, text: text})
}

// insert inserts text at offset.
func (d *Document) insert(offset int, text string) {
	d.edits = append(d.edits, edit{start: offset, end: offset, text: text})
}

// record notes an upgraded spelling at node.
func (d *Document) record(node ast.Node, old, new string) error {
	return d.recordKept(node, old, new, "")
}

// recordKept notes a spelling at node with the note that says why
// migrate_claim_paths leaves it as written; an empty note records an
// upgraded spelling.
func (d *Document) recordKept(node ast.Node, old, new, note string) error {
	line, err := d.lineAt(node.GetToken().Position)
	if err != nil {
		return err
	}
	d.rewrites = append(d.rewrites, Rewrite{
		File: d.file,
		Path: node.GetPath(),
		Line: line,
		Old:  old,
		New:  new,
		Note: note,
	})
	return nil
}

// offset returns the byte offset of a token position. A column counts
// runes.
func (d *Document) offset(pos *token.Position) (int, error) {
	if pos == nil || pos.Line < 1 || pos.Line > len(d.lines) || pos.Column < 1 {
		return 0, errors.New("a YAML token has no position in the text")
	}
	at := d.lines[pos.Line-1]
	for range pos.Column - 1 {
		if at >= len(d.src) || d.src[at] == '\n' {
			return 0, fmt.Errorf("line %d has no column %d", pos.Line, pos.Column)
		}
		_, size := utf8.DecodeRune(d.src[at:])
		at += size
	}
	return at, nil
}

// tokenSpan returns the byte range of a token's text.
func (d *Document) tokenSpan(tk *token.Token) (int, int, error) {
	if tk == nil {
		return 0, 0, errors.New("a YAML node has no token")
	}
	start, err := d.offset(tk.Position)
	if err != nil {
		return 0, 0, err
	}
	text := strings.TrimSpace(tk.Origin)
	if text == "" || !bytes.HasPrefix(d.src[start:], []byte(text)) {
		return 0, 0, fmt.Errorf("line %d: the text of %q is not where its token says", d.fileLine(start), tk.Value)
	}
	return start, start + len(text), nil
}

// span returns the byte range of a node written on one line: a scalar, or
// a flow collection.
func (d *Document) span(n ast.Node) (int, int, error) {
	switch v := n.(type) {
	case *ast.MappingNode:
		if v.IsFlowStyle {
			return d.flowSpan(v.Start, v.End)
		}
	case *ast.SequenceNode:
		if v.IsFlowStyle {
			return d.flowSpan(v.Start, v.End)
		}
	case *ast.AnchorNode, *ast.AliasNode, *ast.TagNode, *ast.LiteralNode:
	default:
		return d.tokenSpan(n.GetToken())
	}
	line, err := d.lineAt(n.GetToken().Position)
	if err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("line %d: %s is no scalar or flow collection", line, n.GetPath())
}

// flowSpan returns the byte range from a flow collection's opening
// indicator through its closing one.
func (d *Document) flowSpan(start, end *token.Token) (int, int, error) {
	if start == nil || end == nil {
		return 0, 0, errors.New("a flow collection has no bounds")
	}
	from, err := d.offset(start.Position)
	if err != nil {
		return 0, 0, err
	}
	to, err := d.offset(end.Position)
	if err != nil {
		return 0, 0, err
	}
	return from, to + 1, nil
}

// text returns the source text of a node written on one line.
func (d *Document) text(n ast.Node) (string, error) {
	start, end, err := d.span(n)
	if err != nil {
		return "", err
	}
	return string(d.src[start:end]), nil
}

// lastLine returns the last line a node's text reaches.
func lastLine(n ast.Node) int {
	last := 0
	ast.Walk(visitFunc(func(child ast.Node) {
		if _, comment := child.(*ast.CommentGroupNode); comment {
			return
		}
		tk := child.GetToken()
		if tk == nil || tk.Position == nil {
			return
		}
		line := tk.Position.Line + strings.Count(strings.TrimSpace(tk.Origin), "\n")
		last = max(last, line)
		if end := endToken(child); end != nil && end.Position != nil {
			last = max(last, end.Position.Line)
		}
	}), n)
	return last
}

// endToken returns the closing indicator of a flow collection.
func endToken(n ast.Node) *token.Token {
	switch v := n.(type) {
	case *ast.MappingNode:
		return v.End
	case *ast.SequenceNode:
		return v.End
	}
	return nil
}

type visitFunc func(ast.Node)

func (f visitFunc) Visit(n ast.Node) ast.Visitor {
	f(n)
	return f
}

// lineEnd returns the offset of the newline that ends line, or the end of
// the text.
func (d *Document) lineEnd(line int) int {
	if line < len(d.lines) {
		return d.lines[line] - 1
	}
	return len(d.src)
}

// lineStart returns the offset at which line starts, or the end of the
// text after the last line.
func (d *Document) lineStart(line int) int {
	if line-1 < len(d.lines) {
		return d.lines[line-1]
	}
	return len(d.src)
}

// indent indents every non-blank line from first through last by n
// spaces.
func (d *Document) indent(first, last, n int) {
	for line := first; line <= last && line <= len(d.lines); line++ {
		start, end := d.lineStart(line), d.lineEnd(line)
		if len(bytes.TrimSpace(d.src[start:end])) > 0 {
			d.insert(start, strings.Repeat(" ", n))
		}
	}
}

// endsInNewline reports whether the text ends with a newline.
func (d *Document) endsInNewline() bool {
	return len(d.src) > 0 && d.src[len(d.src)-1] == '\n'
}
