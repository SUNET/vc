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
// element], split at its last dot. A name without a dot is an element of
// org.iso.18013.5.1.
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

// Dotted reads a dotted claim name as a claims path pointer.
func (s Shape) Dotted(name string) (claimpath.Pointer, error) {
	segments, err := split(name)
	if err != nil {
		return claimpath.Pointer{}, err
	}
	if s.kind == qualifiedReading {
		if len(segments) == 1 {
			return claimpath.Keys(isoNamespace, name), nil
		}
		i := strings.LastIndex(name, ".")
		return claimpath.Keys(name[:i], name[i+1:]), nil
	}
	if s.kind == 0 {
		return claimpath.Pointer{}, errors.New("the shape is unset")
	}
	first, err := s.document.Key(segments[0])
	if err != nil {
		return claimpath.Pointer{}, fmt.Errorf("%q: %w", name, err)
	}
	for _, segment := range segments[1:] {
		first = first.Append(claimpath.Key(segment))
	}
	return first, nil
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

// split returns the segments of a dotted name, each non-empty.
func split(name string) ([]string, error) {
	segments := strings.Split(name, ".")
	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("the dotted claim name %q has an empty segment", name)
		}
	}
	return segments, nil
}
