// Package starform implements star forms for restricted S-expressions.
// Star forms are special constructs that represent sets of possible values.
package starform

import (
	"fmt"
	"strings"
	"time"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// StarForm is the interface for all star form types
type StarForm interface {
	sexp.Element
	IsStarForm() bool
	Match(value sexp.Element) bool
	Type() string
}

// Wildcard represents (*) - matches any single element
type Wildcard struct{}

func (w *Wildcard) String() string                { return "(1:*)" }
func (w *Wildcard) IsAtom() bool                  { return false }
func (w *Wildcard) IsList() bool                  { return false }
func (w *Wildcard) IsStarForm() bool              { return true }
func (w *Wildcard) Type() string                  { return "wildcard" }
func (w *Wildcard) Match(value sexp.Element) bool { return true }

// Set represents (* set <elements>...) - matches any element in the set
type Set struct {
	Elements []sexp.Element
}

func (s *Set) String() string {
	var sb strings.Builder
	sb.WriteString("(1:*3:set")
	for _, elem := range s.Elements {
		sb.WriteString(elem.String())
	}
	sb.WriteString(")")
	return sb.String()
}

func (s *Set) IsAtom() bool     { return false }
func (s *Set) IsList() bool     { return false }
func (s *Set) IsStarForm() bool { return true }
func (s *Set) Type() string     { return "set" }
func (s *Set) Match(value sexp.Element) bool {
	// Value matches if it equals any element in the set
	for _, elem := range s.Elements {
		if elementsEqual(value, elem) {
			return true
		}
	}
	return false
}

// RangeType represents the type of range
type RangeType string

const (
	RangeAlpha   RangeType = "alpha"
	RangeNumeric RangeType = "numeric"
	RangeDate    RangeType = "date"
	RangeTime    RangeType = "time"
	RangeIPv4    RangeType = "ipv4"
	RangeIPv6    RangeType = "ipv6"
)

// RangeOp represents a range comparison operator
type RangeOp string

const (
	OpLT RangeOp = "lt" // less than
	OpLE RangeOp = "le" // less than or equal
	OpGT RangeOp = "gt" // greater than
	OpGE RangeOp = "ge" // greater than or equal
)

// RangeBound represents a range boundary with operator and value
type RangeBound struct {
	Op    RangeOp
	Value string
}

// Range represents (* range <type> <bounds>...)
type Range struct {
	RangeType  RangeType
	LowerBound *RangeBound // ge or gt
	UpperBound *RangeBound // le or lt
}

func (r *Range) String() string {
	var sb strings.Builder
	sb.WriteString("(1:*5:range")

	switch r.RangeType {
	case RangeAlpha:
		sb.WriteString("5:alpha")
	case RangeNumeric:
		sb.WriteString("7:numeric")
	case RangeDate:
		sb.WriteString("4:date")
	case RangeTime:
		sb.WriteString("4:time")
	case RangeIPv4:
		sb.WriteString("4:ipv4")
	case RangeIPv6:
		sb.WriteString("4:ipv6")
	}

	if r.LowerBound != nil {
		sb.WriteString(fmt.Sprintf("2:%s%d:%s", r.LowerBound.Op, len(r.LowerBound.Value), r.LowerBound.Value))
	}
	if r.UpperBound != nil {
		sb.WriteString(fmt.Sprintf("2:%s%d:%s", r.UpperBound.Op, len(r.UpperBound.Value), r.UpperBound.Value))
	}

	sb.WriteString(")")
	return sb.String()
}

func (r *Range) IsAtom() bool     { return false }
func (r *Range) IsList() bool     { return false }
func (r *Range) IsStarForm() bool { return true }
func (r *Range) Type() string     { return "range" }

func (r *Range) Match(value sexp.Element) bool {
	atom, ok := value.(*sexp.Atom)
	if !ok {
		return false
	}

	switch r.RangeType {
	case RangeNumeric:
		return r.matchNumeric(atom.Value)
	case RangeAlpha:
		return r.matchAlpha(atom.Value)
	case RangeDate, RangeTime:
		return r.matchDateTime(atom.Value)
	case RangeIPv4, RangeIPv6:
		return r.matchIP(atom.Value)
	}
	return false
}

func (r *Range) matchNumeric(value string) bool {
	// Simple numeric comparison
	if r.LowerBound != nil {
		if value < r.LowerBound.Value {
			return false
		}
		if r.LowerBound.Op == OpGT && value == r.LowerBound.Value {
			return false
		}
	}
	if r.UpperBound != nil {
		if value > r.UpperBound.Value {
			return false
		}
		if r.UpperBound.Op == OpLT && value == r.UpperBound.Value {
			return false
		}
	}
	return true
}

func (r *Range) matchAlpha(value string) bool {
	// Lexicographic comparison
	if r.LowerBound != nil {
		if value < r.LowerBound.Value {
			return false
		}
		if r.LowerBound.Op == OpGT && value == r.LowerBound.Value {
			return false
		}
	}
	if r.UpperBound != nil {
		if value > r.UpperBound.Value {
			return false
		}
		if r.UpperBound.Op == OpLT && value == r.UpperBound.Value {
			return false
		}
	}
	return true
}

func (r *Range) matchDateTime(value string) bool {
	// For time-only ranges, do simple string comparison
	if r.RangeType == RangeTime {
		return r.matchAlpha(value) // Simple lexicographic comparison works for HH:MM:SS
	}

	// Parse and compare timestamps for date ranges
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return false
	}

	if r.LowerBound != nil {
		lower, err := time.Parse(time.RFC3339, r.LowerBound.Value)
		if err != nil {
			return false
		}
		if t.Before(lower) {
			return false
		}
		if r.LowerBound.Op == OpGT && t.Equal(lower) {
			return false
		}
	}

	if r.UpperBound != nil {
		upper, err := time.Parse(time.RFC3339, r.UpperBound.Value)
		if err != nil {
			return false
		}
		if t.After(upper) {
			return false
		}
		if r.UpperBound.Op == OpLT && t.Equal(upper) {
			return false
		}
	}

	return true
}

func (r *Range) matchIP(value string) bool {
	// Basic IP comparison - simplified for now
	if r.LowerBound != nil && value < r.LowerBound.Value {
		return false
	}
	if r.UpperBound != nil && value > r.UpperBound.Value {
		return false
	}
	return true
}

// Prefix represents (* prefix <string>) - matches strings with the given prefix
type Prefix struct {
	Value string
}

func (p *Prefix) String() string {
	return fmt.Sprintf("(1:*6:prefix%d:%s)", len(p.Value), p.Value)
}

func (p *Prefix) IsAtom() bool     { return false }
func (p *Prefix) IsList() bool     { return false }
func (p *Prefix) IsStarForm() bool { return true }
func (p *Prefix) Type() string     { return "prefix" }

func (p *Prefix) Match(value sexp.Element) bool {
	atom, ok := value.(*sexp.Atom)
	if !ok {
		return false
	}
	return strings.HasPrefix(atom.Value, p.Value)
}

// Suffix represents (* suffix <string>) - matches strings with the given suffix
type Suffix struct {
	Value string
}

func (s *Suffix) String() string {
	return fmt.Sprintf("(1:*6:suffix%d:%s)", len(s.Value), s.Value)
}

func (s *Suffix) IsAtom() bool     { return false }
func (s *Suffix) IsList() bool     { return false }
func (s *Suffix) IsStarForm() bool { return true }
func (s *Suffix) Type() string     { return "suffix" }

func (s *Suffix) Match(value sexp.Element) bool {
	atom, ok := value.(*sexp.Atom)
	if !ok {
		return false
	}
	return strings.HasSuffix(atom.Value, s.Value)
}

// Helper function to compare elements for equality
func elementsEqual(a, b sexp.Element) bool {
	// Both atoms
	if a.IsAtom() && b.IsAtom() {
		aAtom := a.(*sexp.Atom)
		bAtom := b.(*sexp.Atom)
		return aAtom.Value == bAtom.Value
	}

	// Both lists
	if a.IsList() && b.IsList() {
		aList := a.(*sexp.List)
		bList := b.(*sexp.List)

		if aList.Tag != bList.Tag {
			return false
		}

		if len(aList.Elements) != len(bList.Elements) {
			return false
		}

		for i := range aList.Elements {
			if !elementsEqual(aList.Elements[i], bList.Elements[i]) {
				return false
			}
		}
		return true
	}

	return false
}
