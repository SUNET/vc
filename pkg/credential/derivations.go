package credential

import (
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/model"
)

// ApplyDerivations runs each configured derivation against `claims` and
// returns the accumulated derived claims (empty map when `list` is empty).
// A per-derivation failure short-circuits with a wrapped error naming the
// offending index.
//
// Each derivation's inputs include both the original claims and every claim
// produced by earlier list entries, so a pipeline such as
//
//	yyyymmdd_to_iso(birthdate_raw -> birthdate) followed by
//	age_over_thresholds(birthdate -> age_over_*)
//
// works without a caller having to pre-merge intermediates. An input reads
// the issued claims when an earlier derivation writes it or a prefix of it,
// and the source claims otherwise; see primitives.Working.
//
// A derivation writes each output claim at its path, so one that targets a
// nested path (e.g. ["identity", "email"]) leaves a sibling nested claim
// (identity.name) produced by an earlier step in place.
func ApplyDerivations(list []primitives.Derivation, claims map[string]any, now time.Time, shapes primitives.Shapes) (map[string]any, error) {
	out, _, err := ApplyDerivationsReplacing(list, claims, now, nil, shapes)
	return out, err
}

// ApplyScopeDerivations runs the derivations a data source configures for
// a credential scope over claims, and merges what they write into claims.
// It returns the claims the scope's hash_commitment openings read, taken
// before the derivations change them (primitives.OpeningInputs).
func ApplyScopeDerivations(cfg *model.Cfg, src model.SourceScope, claims map[string]any, now time.Time) (map[string]any, error) {
	list := cfg.APIGW.DataSources.DerivationsForSource(src.Scope, src.Source)
	if len(list) == 0 {
		return nil, nil
	}
	shapes, err := cfg.DerivationShapes(src)
	if err != nil {
		return nil, err
	}
	openingClaims, err := primitives.OpeningInputs(list, claims, shapes.Source)
	if err != nil {
		return nil, err
	}
	derived, replaced, err := ApplyDerivationsReplacing(list, claims, now, nil, shapes)
	if err != nil {
		return nil, err
	}
	return openingClaims, MergeDerived(claims, derived, replaced)
}

// ApplyDerivationsPinned is ApplyDerivations with claims that stay
// authoritative THROUGHOUT the chain.
//
// Each step's output feeds the next, so restoring a value only at the end
// is not enough: a step converting a stored 19700101 into birth_date, and
// a later one computing age_over_18 from it, produce an age for the
// stored date. Putting the real birth_date back afterwards leaves that
// age behind - a credential asserting an age the presented date does not
// support, which is worse than the overwrite it was meant to repair,
// because it looks consistent.
//
// Pinned values are restored into the working claims after every step, so
// a dependent derivation reads the value that will actually be issued.
// They are left in the returned outputs, so a caller can still see which
// derivations tried to write them.
func ApplyDerivationsPinned(list []primitives.Derivation, claims map[string]any, now time.Time, pinned map[string]any, shapes primitives.Shapes) (map[string]any, error) {
	out, _, err := ApplyDerivationsReplacing(list, claims, now, pinned, shapes)
	return out, err
}

// ApplyDerivationsReplacing is ApplyDerivationsPinned that also returns the
// locations of the copies that wrote a value, which MergeDerived clears in
// the document before it merges the outputs.
func ApplyDerivationsReplacing(list []primitives.Derivation, claims map[string]any, now time.Time, pinned map[string]any, shapes primitives.Shapes) (map[string]any, []claimpath.Pointer, error) {
	out := make(map[string]any)
	var replaced []claimpath.Pointer
	workingClaims := CloneNestedClaims(claims)
	// CLONED on every restoration, not assigned. A write lands INTO
	// existing nested maps, so handing the pin itself to working lets the
	// next step mutate it: a derivation changing a presented
	// address.country from DK to SE changes the pin too, and every later
	// step - and the caller's final restoration - then uses the derived
	// value while believing it is the proved one. Cloning the SNAPSHOT
	// once is not enough; it has to be cloned each time it goes back in.
	restore := func() {
		for name, value := range pinned {
			workingClaims[name] = cloneValue(value)
		}
	}
	restore()
	working := primitives.NewWorking(workingClaims, shapes)
	generated := provenance{}
	for i, d := range list {
		if d.HashCommitment != nil {
			// Its opening comes from HashCommitmentArgs.NewOpening.
			continue
		}
		copied, err := applyDerivation(working, workingClaims, out, d, now, generated, shapes)
		if err != nil {
			return nil, nil, fmt.Errorf("derivations[%d]: %w", i, err)
		}
		if !copied.IsZero() {
			replaced = append(replaced, copied)
		}
		restore()
	}
	return out, replaced, nil
}

// applyDerivation runs one derivation, writes its outputs into the working
// claims and into out, and records their provenance. It returns the
// location of a copy's output when the copy wrote a value.
func applyDerivation(working *primitives.Working, workingClaims, out map[string]any, d primitives.Derivation, now time.Time, generated provenance, shapes primitives.Shapes) (claimpath.Pointer, error) {
	input, inputLocation, err := inputOf(working, d)
	if err != nil {
		return claimpath.Pointer{}, err
	}
	inputGenerated := !inputLocation.IsZero() && generated.of(inputLocation)
	writes, err := d.Apply(working, now)
	if err != nil {
		if errors.Is(err, primitives.ErrInvalidClaimInput) && inputGenerated {
			// %v, not %w: the input came from an earlier derivation, so this is a configuration fault.
			return claimpath.Pointer{}, fmt.Errorf("input %s was generated by an earlier derivation: %v", input, err)
		}
		return claimpath.Pointer{}, err
	}
	isGenerated := !d.ReformatsInput() || inputGenerated
	for _, w := range writes {
		if err := writeOutput(working, workingClaims, out, w, isGenerated, generated, shapes.Issued); err != nil {
			return claimpath.Pointer{}, err
		}
	}
	outputs, err := d.Outputs(shapes.Issued.Dotted)
	if err != nil {
		return claimpath.Pointer{}, err
	}
	working.Wrote(outputs)
	if d.Copy == nil || len(writes) == 0 {
		return claimpath.Pointer{}, nil
	}
	output, err := shapes.Issued.Locate(d.Copy.Output)
	if err != nil {
		return claimpath.Pointer{}, err
	}
	generated.carry(inputLocation, output)
	return output, nil
}

// writeOutput writes one output of a derivation into the working claims
// and into out, and records its provenance.
func writeOutput(working *primitives.Working, workingClaims, out map[string]any, w primitives.Write, isGenerated bool, generated provenance, issued claimpath.Shape) error {
	location, err := issued.Locate(w.Path)
	if err != nil {
		return err
	}
	generated.record(workingClaims, location, w.Value, isGenerated)
	if err := working.Write(w.Path, cloneValue(w.Value)); err != nil {
		return err
	}
	return issued.Set(out, w.Path, w.Value)
}

// inputOf returns the claim a derivation reads, and its location in the
// working claims.
func inputOf(working *primitives.Working, d primitives.Derivation) (claimpath.Pointer, claimpath.Pointer, error) {
	input, ok := d.Input()
	if !ok {
		return claimpath.Pointer{}, claimpath.Pointer{}, nil
	}
	location, err := working.InputShape(input).Locate(input)
	if err != nil {
		return claimpath.Pointer{}, claimpath.Pointer{}, err
	}
	return input, location, nil
}

// provenance records, by location in the working claims, whether a
// claim's value is generated: output of a computing primitive, or a
// reformatting of such output. A location without an entry holds holder
// data.
type provenance map[string]located

// located is the provenance of the claim at location.
type located struct {
	location  claimpath.Pointer
	generated bool
}

func (p provenance) set(location claimpath.Pointer, generated bool) {
	p[location.String()] = located{location: location, generated: generated}
}

// of reports whether the claim at location is generated.
func (p provenance) of(location claimpath.Pointer) bool {
	return p[location.String()].generated
}

// record tags the claims a write at location makes: every leaf of value
// with isGenerated, and every object the write makes with true, since the
// holder never supplied it. Objects on the way to location that already
// exist in existing keep their provenance.
func (p provenance) record(existing map[string]any, location claimpath.Pointer, value any, isGenerated bool) {
	for _, ancestor := range location.Ancestors() {
		if _, present, err := claimpath.Nested().Get(existing, ancestor); err == nil && !present {
			p.set(ancestor, true)
		}
	}
	p.recordLeaves(location, value, isGenerated)
}

// recordLeaves tags value at location: an object as generated, and each of
// its leaves with isGenerated.
func (p provenance) recordLeaves(location claimpath.Pointer, value any, isGenerated bool) {
	object, isMap := value.(map[string]any)
	if !isMap {
		p.set(location, isGenerated)
		return
	}
	p.set(location, true)
	for key, item := range object {
		p.recordLeaves(location.Append(claimpath.Key(key)), item, isGenerated)
	}
}

// carry gives each location under a copy's output the provenance of the
// same location under its input, so a copied object keeps which of its
// fields are generated. The copy replaced the whole output subtree, so the
// provenance recorded there before is dropped.
func (p provenance) carry(input, output claimpath.Pointer) {
	copied := p.of(input)
	var carried []located
	for key, entry := range p {
		if rebased, ok := entry.location.Rebase(input, output); ok && strictlyUnder(entry.location, input) {
			carried = append(carried, located{location: rebased, generated: entry.generated})
		}
		if strictlyUnder(entry.location, output) {
			delete(p, key)
		}
	}
	for _, entry := range carried {
		p.set(entry.location, entry.generated)
	}
	p.set(output, copied)
}

// strictlyUnder reports whether location is a claim inside the claim at
// parent.
func strictlyUnder(location, parent claimpath.Pointer) bool {
	return location.Len() > parent.Len() && location.HasPrefix(parent)
}

// MergeDerived merges the output of ApplyDerivationsReplacing into dst. A
// copy replaces the whole claim at its output location, so a field dst
// already holds at a location in replaced does not outlive the copied
// value.
func MergeDerived(dst, derived map[string]any, replaced []claimpath.Pointer) error {
	for _, location := range replaced {
		if err := claimpath.Nested().Delete(dst, location); err != nil {
			return err
		}
	}
	MergeNestedClaims(dst, derived)
	return nil
}

// MergeNestedClaims deep-merges src into dst. When both dst[k] and src[k]
// are map[string]any, their contents are merged recursively; otherwise
// src[k] replaces dst[k]. This preserves sibling nested claims when a
// derivation produces only a subset of a parent map's keys.
func MergeNestedClaims(dst, src map[string]any) {
	for k, v := range src {
		sm, srcIsMap := v.(map[string]any)
		if !srcIsMap {
			dst[k] = v
			continue
		}
		dm, dstIsMap := dst[k].(map[string]any)
		if !dstIsMap {
			dst[k] = v
			continue
		}
		MergeNestedClaims(dm, sm)
	}
}

// cloneValue deep-copies a claim value so nothing handed out shares
// mutable structure with the original. Maps and slices only: everything
// else a claim carries is immutable.
func cloneValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return v
	}
}

// CloneNestedClaims returns a copy of src with nested map[string]any values
// cloned recursively so later in-place merges on the working map do not
// mutate the caller's original claims map.
func CloneNestedClaims(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		if m, ok := v.(map[string]any); ok {
			out[k] = CloneNestedClaims(m)
			continue
		}
		out[k] = v
	}
	return out
}
