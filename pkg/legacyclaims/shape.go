// Package legacyclaims upgrades the claim spellings of earlier releases in
// the YAML text of a configuration: a dotted claim name becomes a claims
// path pointer (OpenID4VP 1.0 section 7), and a map keyed by dotted names
// becomes the list form. The rewritten text keeps every comment, so the
// same upgrade serves the loader and the migrate_claim_paths command.
package legacyclaims

import (
	"errors"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"
)

// isoNamespace is the namespace a dotted mdoc name without a dot reads
// as: the presented mdoc claims carry each of its elements under the bare
// element identifier too.
const isoNamespace = "org.iso.18013.5.1"

// Shape reads a dotted claim name the way the role that holds it looked
// the name up.
type Shape struct {
	kind reading
	// document locates a top-level key of the document.
	document claimpath.Shape
}

type reading uint8

const (
	nestedReading reading = iota + 1
	qualifiedReading
	documentReading
)

// Nested reads a dotted name as one key per segment: a claim of a
// JSON-based credential, or of a JSON object a mapping writes.
func Nested() Shape {
	return Shape{kind: nestedReading, document: claimpath.Nested()}
}

// MDocQualified reads a dotted name of a presented mdoc as [namespace,
// element], split at its last dot. A name whose last dot is its first or
// last character, or that has no dot, is an element of org.iso.18013.5.1.
func MDocQualified() Shape {
	return Shape{kind: qualifiedReading, document: claimpath.MDocQualified()}
}

// DocumentData reads a dotted name of the document data of an issued
// credential, whose shape is document, as one key per segment. In an
// mdoc's document data, a first segment the MDDL declares as an element
// gains the first declaring namespace in sorted order.
func DocumentData(document claimpath.Shape) Shape {
	return Shape{kind: documentReading, document: document}
}

// Dotted reads a dotted claim name as a claims path pointer. Each dot
// separates two keys, so an empty segment is an empty key.
func (s Shape) Dotted(name string) (claimpath.Pointer, error) {
	if s.kind == qualifiedReading {
		namespace, element := qualified(name)
		return claimpath.Keys(namespace, element), nil
	}
	if s.kind == 0 {
		return claimpath.Pointer{}, errors.New("the shape is unset")
	}
	segments := strings.Split(name, ".")
	first, err := s.document.Key(segments[0])
	if err != nil {
		return claimpath.Pointer{}, fmt.Errorf("%q: %w", name, err)
	}
	for _, segment := range segments[1:] {
		first = first.Append(claimpath.Key(segment))
	}
	return first, nil
}

// qualified returns the namespace and element identifier of main's dotted
// name of a presented mdoc claim.
func qualified(name string) (namespace, element string) {
	if i := strings.LastIndex(name, "."); i > 0 && i < len(name)-1 {
		return name[:i], name[i+1:]
	}
	return isoNamespace, name
}

// Literal reads a claim name as one key, the whole name: main's
// age_over_thresholds, yyyymmdd_to_iso and swamid_highest_assurance_level
// looked their input up, and wrote their output, at that key. A presented
// mdoc holds a claim under its qualified name, the key Dotted locates.
func (s Shape) Literal(name string) (claimpath.Pointer, error) {
	switch s.kind {
	case qualifiedReading:
		return s.Dotted(name)
	case 0:
		return claimpath.Pointer{}, errors.New("the shape is unset")
	}
	return s.document.Key(name)
}

// TopLevel reads the name of a top-level key of the document.
func (s Shape) TopLevel(name string) (claimpath.Pointer, error) {
	if strings.Contains(name, ".") {
		return claimpath.Pointer{}, fmt.Errorf("%q names no top-level claim", name)
	}
	if s.kind == 0 {
		return claimpath.Pointer{}, errors.New("the shape is unset")
	}
	return s.document.Key(name)
}
