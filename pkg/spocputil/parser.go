// Package spocputil provides shared utilities for working with SPOCP
// S-expressions, including parsing human-readable "advanced form" into
// sexp.Element trees and loading rules from files.
package spocputil

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	spocp "github.com/sirosfoundation/go-spocp"
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

// LoadRulesFromFile reads human-readable SPOCP rules (one per line) from a
// file and adds them to the engine using ParseAdvancedSExp. If validate is
// non-nil, each parsed rule is passed to it (with a source string
// identifying the file and line number) before being added; a returned
// error aborts loading.
func LoadRulesFromFile(engine *spocp.AdaptiveEngine, path string, validate func(elem sexp.Element, source string) error) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip blanks and comments
		}
		elem, err := ParseAdvancedSExp(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}
		if validate != nil {
			if err := validate(elem, fmt.Sprintf("%s line %d", path, lineNum)); err != nil {
				return err
			}
		}
		engine.AddRuleElement(elem)
	}
	return scanner.Err()
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
		// Treat a bare * inside a tagged list as a wildcard star form,
		// so (method *) is equivalent to (method (*)).
		// Treat a trailing * (e.g. /api/v1/*) as a prefix star form,
		// so (path /api/v1/*) is equivalent to (path (* prefix /api/v1/)).
		if atom, ok := elem.(*sexp.Atom); ok {
			if atom.Value == "*" {
				elem = &starform.Wildcard{}
			} else if before, found := strings.CutSuffix(atom.Value, "*"); found {
				elem = &starform.Prefix{Value: before}
			}
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
