// Package sexp implements restricted S-expressions as defined in the SPOCP specification.
// This follows the canonical form from Rivest's S-expressions where each atom is
// prefixed by its length in the format: <length>:<data>
package sexp

import (
	"fmt"
	"strconv"
	"strings"
)

// Element represents any element in an S-expression
type Element interface {
	String() string
	IsAtom() bool
	IsList() bool
	IsStarForm() bool
}

// Atom represents an octet string in canonical form
type Atom struct {
	Value string
}

func (a *Atom) String() string {
	return fmt.Sprintf("%d:%s", len(a.Value), a.Value)
}

func (a *Atom) IsAtom() bool     { return true }
func (a *Atom) IsList() bool     { return false }
func (a *Atom) IsStarForm() bool { return false }

// List represents an S-expression list
type List struct {
	Tag      string    // First element (must be an atom)
	Elements []Element // Remaining elements
}

func (l *List) String() string {
	var sb strings.Builder
	sb.WriteString("(")
	sb.WriteString(fmt.Sprintf("%d:%s", len(l.Tag), l.Tag))
	for _, elem := range l.Elements {
		sb.WriteString(elem.String())
	}
	sb.WriteString(")")
	return sb.String()
}

func (l *List) IsAtom() bool     { return false }
func (l *List) IsList() bool     { return true }
func (l *List) IsStarForm() bool { return false }

// NewAtom creates a new Atom
func NewAtom(value string) *Atom {
	return &Atom{Value: value}
}

// NewList creates a new List with the given tag and elements
func NewList(tag string, elements ...Element) *List {
	return &List{Tag: tag, Elements: elements}
}

// Parser parses canonical S-expressions
type Parser struct {
	input string
	pos   int
}

// NewParser creates a new parser for the given input
func NewParser(input string) *Parser {
	return &Parser{input: input, pos: 0}
}

// Parse parses the input and returns an Element
func (p *Parser) Parse() (Element, error) {
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unexpected end of input")
	}

	if p.input[p.pos] == '(' {
		return p.parseList()
	}
	return p.parseAtom()
}

// parseAtom parses a length-prefixed atom: <length>:<data>
func (p *Parser) parseAtom() (*Atom, error) {
	// Find the colon
	colonPos := strings.IndexByte(p.input[p.pos:], ':')
	if colonPos == -1 {
		return nil, fmt.Errorf("expected ':' in atom at position %d", p.pos)
	}
	colonPos += p.pos

	// Parse the length
	lengthStr := p.input[p.pos:colonPos]
	length, err := strconv.Atoi(lengthStr)
	if err != nil {
		return nil, fmt.Errorf("invalid length '%s' at position %d: %v", lengthStr, p.pos, err)
	}

	// Extract the data
	dataStart := colonPos + 1
	dataEnd := dataStart + length
	if dataEnd > len(p.input) {
		return nil, fmt.Errorf("atom data exceeds input length at position %d", p.pos)
	}

	value := p.input[dataStart:dataEnd]
	p.pos = dataEnd

	return NewAtom(value), nil
}

// parseList parses an S-expression list: (<tag> <elements>...)
func (p *Parser) parseList() (*List, error) {
	if p.input[p.pos] != '(' {
		return nil, fmt.Errorf("expected '(' at position %d", p.pos)
	}
	p.pos++ // skip '('

	// Parse the tag (must be an atom)
	tag, err := p.parseAtom()
	if err != nil {
		return nil, fmt.Errorf("failed to parse list tag: %v", err)
	}

	// Parse elements until we hit ')'
	var elements []Element
	for p.pos < len(p.input) && p.input[p.pos] != ')' {
		elem, err := p.Parse()
		if err != nil {
			return nil, err
		}
		elements = append(elements, elem)
	}

	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unclosed list starting at tag '%s'", tag.Value)
	}

	p.pos++ // skip ')'

	return NewList(tag.Value, elements...), nil
}

// AdvancedForm converts canonical form to human-readable advanced form
func AdvancedForm(elem Element) string {
	switch e := elem.(type) {
	case *Atom:
		return e.Value
	case *List:
		var parts []string
		parts = append(parts, e.Tag)
		for _, el := range e.Elements {
			parts = append(parts, AdvancedForm(el))
		}
		return "(" + strings.Join(parts, " ") + ")"
	default:
		return ""
	}
}
