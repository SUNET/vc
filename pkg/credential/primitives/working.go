package primitives

import (
	"errors"
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/claimpath"
)

// Shapes are how a derivation list's claims are held: the source claims
// it reads, and the document of the credential it issues, which it
// writes.
type Shapes struct {
	Source claimpath.Shape
	Issued claimpath.Shape
}

// Working is the claims map a derivation list runs on: the source claims
// and the claims its earlier derivations wrote. It implements Claims.
type Working struct {
	claims  map[string]any
	shapes  Shapes
	written []claimpath.Pointer
}

// NewWorking returns the working claims of a derivation list over claims.
func NewWorking(claims map[string]any, shapes Shapes) *Working {
	return &Working{claims: claims, shapes: shapes}
}

// Input implements Claims. A claim whose structure does not match the
// pointer is the data's fault, so the error is ErrInvalidClaimInput.
func (w *Working) Input(p claimpath.Pointer) (any, bool, error) {
	value, present, err := w.InputShape(p).Get(w.claims, p)
	if errors.Is(err, claimpath.ErrMismatch) {
		return nil, false, fmt.Errorf("%w: %w", ErrInvalidClaimInput, err)
	}
	return value, present, err
}

// Issued implements Claims.
func (w *Working) Issued(p claimpath.Pointer) (any, bool, error) {
	return w.shapes.Issued.Get(w.claims, p)
}

// Named implements Claims.
func (w *Working) Named(name string) (claimpath.Pointer, error) {
	return w.shapes.Issued.Key(name)
}

// InputShape returns the shape an input pointer reads: the issued shape
// when an earlier derivation writes the pointer or a prefix of it, the
// source shape otherwise.
func (w *Working) InputShape(p claimpath.Pointer) claimpath.Shape {
	if writtenBefore(w.written, p) {
		return w.shapes.Issued
	}
	return w.shapes.Source
}

// Write writes value at a pointer into the issued claims.
func (w *Working) Write(p claimpath.Pointer, value any) error {
	return w.shapes.Issued.Set(w.claims, p, value)
}

// Wrote records the claims a derivation writes, for the inputs of the
// derivations after it.
func (w *Working) Wrote(outputs []claimpath.Pointer) {
	w.written = append(w.written, outputs...)
}

// writtenBefore reports whether one of written is p or a prefix of it.
func writtenBefore(written []claimpath.Pointer, p claimpath.Pointer) bool {
	return slices.ContainsFunc(written, func(q claimpath.Pointer) bool { return p.HasPrefix(q) })
}

// CheckDerivations checks that every claim a derivation list reads or
// writes is one claim its shape locates.
//
//   - An output, and the input of a primitive that writes in place, is a
//     claim of the issued credential's document.
//   - An input is a claim of the source data, or of the issued document
//     when an earlier derivation of the list writes it or a claim above it.
//   - An opening input is a claim of the source data.
func CheckDerivations(list []Derivation, shapes Shapes) error {
	var written []claimpath.Pointer
	for i := range list {
		a, name, err := list[i].selected()
		if err != nil {
			return fmt.Errorf("derivations[%d]: %w", i, err)
		}
		if err := checkArgs(a, shapes, written); err != nil {
			return fmt.Errorf("derivations[%d].%s.%w", i, name, err)
		}
		outputs, err := list[i].Outputs(shapes.Issued.Key)
		if err != nil {
			return fmt.Errorf("derivations[%d].%s: %w", i, name, err)
		}
		written = append(written, outputs...)
	}
	return nil
}

// checkArgs checks the claims of one primitive's arguments.
func checkArgs(a Applier, shapes Shapes, written []claimpath.Pointer) error {
	if hc, ok := a.(*HashCommitmentArgs); ok {
		return hc.checkInputs(shapes.Source)
	}
	if output, ok := outputOf(a); ok {
		if _, err := shapes.Issued.LocateOne(output); err != nil {
			return fmt.Errorf("output: %w", err)
		}
	}
	input, ok := pointerField(a, "Input")
	if !ok {
		return nil
	}
	space := shapes.Source
	if writtenBefore(written, *input) {
		space = shapes.Issued
	}
	if _, err := space.LocateOne(*input); err != nil {
		return fmt.Errorf("input: %w", err)
	}
	return nil
}
