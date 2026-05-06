package issuance

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"
)

// ParseAdvancedSExp parses a human-readable ("advanced form") S-expression into
// a sexp.Element. This allows users to write rules as:
//
//	(credential (scope org_cred)(acr urn:example:loa3)(email_verified true))
//
// instead of canonical form:
//
//	(10:credential(5:scope8:org_cred)(3:acr19:urn:example:loa3)(14:email_verified4:true))
//
// It also supports star forms:
//
//	(*)                        → wildcard
//	(* prefix urn:example:)    → prefix match
//	(* suffix @example.com)    → suffix match
//	(* set loa3 loa4)          → set match
func ParseAdvancedSExp(input string) (sexp.Element, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty S-expression")
	}

	p := &advancedParser{input: []rune(input), pos: 0}
	elem, err := p.parse()
	if err != nil {
		return nil, err
	}

	// Ensure we consumed all input.
	p.skipWhitespace()
	if p.pos < len(p.input) {
		return nil, fmt.Errorf("unexpected trailing input at position %d", p.pos)
	}
	return elem, nil
}

type advancedParser struct {
	input []rune
	pos   int
}

func (p *advancedParser) skipWhitespace() {
	for p.pos < len(p.input) && unicode.IsSpace(p.input[p.pos]) {
		p.pos++
	}
}

func (p *advancedParser) parse() (sexp.Element, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unexpected end of input")
	}

	if p.input[p.pos] == '(' {
		return p.parseList()
	}
	return p.parseAtom()
}

func (p *advancedParser) parseAtom() (*sexp.Atom, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unexpected end of input, expected atom")
	}

	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] != '(' && p.input[p.pos] != ')' && !unicode.IsSpace(p.input[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return nil, fmt.Errorf("empty atom at position %d", start)
	}
	return sexp.NewAtom(string(p.input[start:p.pos])), nil
}

func (p *advancedParser) parseList() (sexp.Element, error) {
	if p.input[p.pos] != '(' {
		return nil, fmt.Errorf("expected '(' at position %d", p.pos)
	}
	p.pos++ // skip '('

	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unclosed '('")
	}

	// Parse the tag atom.
	tag, err := p.parseAtom()
	if err != nil {
		return nil, fmt.Errorf("failed to parse list tag: %w", err)
	}

	// Handle star forms: tag == "*"
	if tag.Value == "*" {
		return p.parseStarForm()
	}

	// Parse remaining elements until ')'.
	var elements []sexp.Element
	for {
		p.skipWhitespace()
		if p.pos >= len(p.input) {
			return nil, fmt.Errorf("unclosed list '%s'", tag.Value)
		}
		if p.input[p.pos] == ')' {
			p.pos++ // skip ')'
			return sexp.NewList(tag.Value, elements...), nil
		}
		elem, err := p.parse()
		if err != nil {
			return nil, err
		}
		elements = append(elements, elem)
	}
}

func (p *advancedParser) parseStarForm() (sexp.Element, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unclosed star form")
	}

	// (*) → wildcard
	if p.input[p.pos] == ')' {
		p.pos++
		return &starform.Wildcard{}, nil
	}

	// Read the star form type: set, prefix, suffix, range...
	formType, err := p.parseAtom()
	if err != nil {
		return nil, fmt.Errorf("failed to parse star form type: %w", err)
	}

	switch formType.Value {
	case "prefix":
		return p.parsePrefixSuffix(true)
	case "suffix":
		return p.parsePrefixSuffix(false)
	case "set":
		return p.parseSet()
	default:
		return nil, fmt.Errorf("unsupported star form type %q", formType.Value)
	}
}

func (p *advancedParser) parsePrefixSuffix(isPrefix bool) (sexp.Element, error) {
	p.skipWhitespace()
	value, err := p.parseAtom()
	if err != nil {
		return nil, fmt.Errorf("expected value for prefix/suffix star form: %w", err)
	}
	p.skipWhitespace()
	if p.pos >= len(p.input) || p.input[p.pos] != ')' {
		return nil, fmt.Errorf("expected ')' to close prefix/suffix star form")
	}
	p.pos++
	if isPrefix {
		return &starform.Prefix{Value: value.Value}, nil
	}
	return &starform.Suffix{Value: value.Value}, nil
}

func (p *advancedParser) parseSet() (sexp.Element, error) {
	var elements []sexp.Element
	for {
		p.skipWhitespace()
		if p.pos >= len(p.input) {
			return nil, fmt.Errorf("unclosed set star form")
		}
		if p.input[p.pos] == ')' {
			p.pos++
			if len(elements) == 0 {
				return nil, fmt.Errorf("empty set star form")
			}
			return &starform.Set{Elements: elements}, nil
		}
		elem, err := p.parse()
		if err != nil {
			return nil, err
		}
		elements = append(elements, elem)
	}
}
