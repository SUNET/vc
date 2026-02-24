// Package compare implements the partial order comparison algorithm for S-expressions.
// This implements the '<=' relation as defined in section 6 of the SPOCP specification.
package compare

import (
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"
)

// LessPermissive returns true if S is less permissive than T (S <= T).
// This means that rule S grants fewer permissions than rule T.
//
// The algorithm follows section 6 of the SPOCP specification:
// 1. T = (*) -> true (wildcard matches anything)
// 2. S and T are strings and S == T -> true
// 3. S is a string and T is a star form that contains S -> true
// 4. S and T are range forms where T contains S -> true
// 5. S and T are prefix forms where T contains S -> true
// 6. S and T are suffix forms where T contains S -> true
// 7. S and T are lists, len(T) <= len(S), and S[i] <= T[i] for all i in T -> true
// 8. S is a set and all elements of S <= T -> true
// 9. T is a set and S <= some element of T -> true
func LessPermissive(s, t sexp.Element) bool {
	// Rule 1: T is wildcard
	if t.IsStarForm() {
		if wc, ok := t.(*starform.Wildcard); ok && wc != nil {
			return true
		}
	}

	// Rule 2: Both are atoms and equal
	if s.IsAtom() && t.IsAtom() {
		sAtom := s.(*sexp.Atom)
		tAtom := t.(*sexp.Atom)
		return sAtom.Value == tAtom.Value
	}

	// Rule 3: S is atom, T is star form that matches S
	if s.IsAtom() && t.IsStarForm() {
		sf, ok := t.(starform.StarForm)
		if ok && sf.Match(s) {
			return true
		}
	}

	// Rule 4, 5, 6: Both are star forms of the same type
	if s.IsStarForm() && t.IsStarForm() {
		return compareStarForms(s, t)
	}

	// Rule 7: Both are lists
	if s.IsList() && t.IsList() {
		sList := s.(*sexp.List)
		tList := t.(*sexp.List)
		return compareLists(sList, tList)
	}

	// Rule 8: S is a set, all elements of S <= T
	if s.IsStarForm() {
		if sSet, ok := s.(*starform.Set); ok {
			for _, elem := range sSet.Elements {
				if !LessPermissive(elem, t) {
					return false
				}
			}
			return true
		}
	}

	// Rule 9: T is a set, S <= some element of T
	if t.IsStarForm() {
		if tSet, ok := t.(*starform.Set); ok {
			for _, elem := range tSet.Elements {
				if LessPermissive(s, elem) {
					return true
				}
			}
			return false
		}
	}

	return false
}

// compareLists implements rule 7: list comparison
// S <= T if len(T) <= len(S) and S[i] <= T[i] for all i in 0..len(T)-1
func compareLists(s, t *sexp.List) bool {
	// Tags must match
	if s.Tag != t.Tag {
		return false
	}

	// S must have at least as many elements as T
	if len(s.Elements) < len(t.Elements) {
		return false
	}

	// Each element of T must be satisfied by corresponding element in S
	for i := 0; i < len(t.Elements); i++ {
		if !LessPermissive(s.Elements[i], t.Elements[i]) {
			return false
		}
	}

	return true
}

// compareStarForms compares two star forms
func compareStarForms(s, t sexp.Element) bool {
	// Both must be star forms
	sSF, sOk := s.(starform.StarForm)
	tSF, tOk := t.(starform.StarForm)
	if !sOk || !tOk {
		return false
	}

	// If T is wildcard, S <= T
	if _, ok := tSF.(*starform.Wildcard); ok {
		return true
	}

	// If S is wildcard but T is not, S is NOT <= T
	if _, ok := sSF.(*starform.Wildcard); ok {
		return false
	}

	// Compare ranges
	sRange, sIsRange := sSF.(*starform.Range)
	tRange, tIsRange := tSF.(*starform.Range)
	if sIsRange && tIsRange {
		return compareRanges(sRange, tRange)
	}

	// Compare prefixes
	sPrefix, sIsPrefix := sSF.(*starform.Prefix)
	tPrefix, tIsPrefix := tSF.(*starform.Prefix)
	if sIsPrefix && tIsPrefix {
		return comparePrefixes(sPrefix, tPrefix)
	}

	// Compare suffixes
	sSuffix, sIsSuffix := sSF.(*starform.Suffix)
	tSuffix, tIsSuffix := tSF.(*starform.Suffix)
	if sIsSuffix && tIsSuffix {
		return compareSuffixes(sSuffix, tSuffix)
	}

	return false
}

// compareRanges checks if range S is contained in range T
func compareRanges(s, t *starform.Range) bool {
	// Must be same type
	if s.RangeType != t.RangeType {
		return false
	}

	// S's range must be contained in T's range
	// T's lower bound must be <= S's lower bound
	if t.LowerBound != nil && s.LowerBound != nil {
		if t.LowerBound.Value > s.LowerBound.Value {
			return false
		}
	} else if t.LowerBound != nil && s.LowerBound == nil {
		return false
	}

	// T's upper bound must be >= S's upper bound
	if t.UpperBound != nil && s.UpperBound != nil {
		if t.UpperBound.Value < s.UpperBound.Value {
			return false
		}
	} else if t.UpperBound != nil && s.UpperBound == nil {
		return false
	}

	return true
}

// comparePrefixes checks if prefix S is contained in prefix T
// S <= T if T's prefix is a prefix of S's prefix
// e.g., "conf" <= "con" because "con" matches more strings
func comparePrefixes(s, t *starform.Prefix) bool {
	// T's prefix must be a prefix of S's prefix (or equal)
	// This means T is more general than S
	return len(t.Value) <= len(s.Value) &&
		s.Value[:len(t.Value)] == t.Value
}

// compareSuffixes checks if suffix S is contained in suffix T
// S <= T if T's suffix is a suffix of S's suffix
func compareSuffixes(s, t *starform.Suffix) bool {
	// T's suffix must be a suffix of S's suffix (or equal)
	// This means T is more general than S
	return len(t.Value) <= len(s.Value) &&
		s.Value[len(s.Value)-len(t.Value):] == t.Value
}

// Normalize normalizes an S-expression by joining ranges and atoms in sets
func Normalize(elem sexp.Element) sexp.Element {
	if !elem.IsStarForm() {
		return elem
	}

	set, ok := elem.(*starform.Set)
	if !ok {
		return elem
	}

	// TODO: Implement set normalization (joining ranges of same type, etc.)
	// For now, return as-is
	return set
}
