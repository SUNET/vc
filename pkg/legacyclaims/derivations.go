package legacyclaims

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"

	"github.com/goccy/go-yaml/ast"
)

// derivations upgrades a derivation list. An input reads the source data,
// or the issued document when an earlier derivation of the list writes it
// or a claim above it: main ran each derivation on the source claims
// merged with the earlier outputs. An output reads the issued document,
// where main wrote it. written holds the outputs of derivations the
// upgrade put before the list's own.
//
// A primitive that readsLiterally reads each claim name as one key. Each
// other primitive reads a name as one key per segment, or as one key when
// an earlier derivation writes that key: main's lookup tried the whole
// name first.
func (u *configUpgrade) derivations(list ast.Node, source, issued *lazy, written []claimpath.Pointer) error {
	nodes, err := items(list)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(nodes, hasDottedClaim) {
		return nil
	}
	for _, node := range nodes {
		steps, err := entries(node)
		if err != nil {
			return err
		}
		for _, step := range steps {
			name, err := keyOf(step)
			if err != nil {
				return err
			}
			outputs, err := u.derivation(name, step.Value, source, issued, written)
			if err != nil {
				return fmt.Errorf("%s: %w", step.GetPath(), err)
			}
			written = append(written, outputs...)
		}
	}
	return nil
}

// hasDottedClaim reports whether a derivation spells a claim as main's
// dotted name.
func hasDottedClaim(n ast.Node) bool {
	found := false
	ast.Walk(visitFunc(func(child ast.Node) {
		entry, ok := child.(*ast.MappingValueNode)
		if !ok {
			return
		}
		key, err := keyOf(entry)
		if err != nil {
			return
		}
		switch key {
		case "input", "output":
			found = found || scalarClaim(entry.Value)
		case "inputs":
			list, err := items(entry.Value)
			found = found || (err == nil && slices.ContainsFunc(list, scalarClaim))
		}
	}), n)
	return found
}

// scalarClaim reports whether a node spells a claim as a scalar.
func scalarClaim(n ast.Node) bool {
	n, err := unwrap(n)
	if err != nil {
		return false
	}
	_, ok := dottedName(n)
	return ok
}

// derivation upgrades one derivation's claims, and returns the claims it
// writes.
func (u *configUpgrade) derivation(name string, args ast.Node, source, issued *lazy, written []claimpath.Pointer) ([]claimpath.Pointer, error) {
	if name == "hash_commitment" {
		return nil, u.openingInputs(args, source)
	}
	literal := readsLiterally(name)
	input, err := child(args, "input")
	if err != nil {
		return nil, err
	}
	var in inputClaim
	if input != nil {
		if in, err = u.input(input.Value, source, issued, written, literal); err != nil {
			return nil, fmt.Errorf("input: %w", err)
		}
	}
	output, err := child(args, "output")
	if err != nil {
		return nil, err
	}
	if output != nil && !emptyClaim(output.Value) {
		out, _, err := u.pointer(output.Value, issued.reader(literal))
		if err != nil {
			return nil, fmt.Errorf("output: %w", err)
		}
		return []claimpath.Pointer{out}, nil
	}
	switch {
	case name == "age_over_thresholds":
		return ageOutputs(args, issued)
	case writesInPlace(name) && !in.path.IsZero():
		return u.inPlace(args, input, output, in, issued.reader(literal))
	}
	return nil, nil
}

// readsLiterally reports whether main's primitive looked its input up, and
// wrote its output, at one key: the whole claim name.
func readsLiterally(name string) bool {
	switch name {
	case "age_over_thresholds", "yyyymmdd_to_iso", "swamid_highest_assurance_level":
		return true
	}
	return false
}

// inputClaim is a derivation's input, and main's dotted name when the
// input spelled one.
type inputClaim struct {
	path   claimpath.Pointer
	dotted string
	record int
}

// input reads a derivation's input: in the literal reading when literal
// is set, and otherwise in the literal reading of a key an earlier
// derivation writes, or in the dotted reading.
func (u *configUpgrade) input(n ast.Node, source, issued *lazy, written []claimpath.Pointer, literal bool) (inputClaim, error) {
	readings := []bool{true}
	if !literal {
		readings = append(readings, false)
	}
	read := func(name string) (claimpath.Pointer, error) {
		if len(written) > 0 {
			if _, err := issued.read(); err != nil {
				return claimpath.Pointer{}, err
			}
			for _, reading := range readings {
				if p, err := issued.reader(reading)(name); err == nil && writtenBefore(written, p) {
					return p, nil
				}
			}
		}
		return source.reader(literal)(name)
	}
	path, name, err := u.pointer(n, read)
	if err != nil || name == "" {
		return inputClaim{path: path}, err
	}
	return inputClaim{path: path, dotted: name, record: len(u.rewrites) - 1}, nil
}

// writtenBefore reports whether one of written is p or a claim above it.
func writtenBefore(written []claimpath.Pointer, p claimpath.Pointer) bool {
	return slices.ContainsFunc(written, func(q claimpath.Pointer) bool { return p.HasPrefix(q) })
}

// emptyClaim reports whether an output is absent: null, or main's empty
// string.
func emptyClaim(n ast.Node) bool {
	n, err := unwrap(n)
	if err != nil {
		return false
	}
	name, scalar := dottedName(n)
	return isNull(n) || (scalar && name == "")
}

// inPlace returns the claim a primitive writes without an output: its
// input's claim. main wrote it at the input's name in the issued
// document, which read reads, so when that reads as another pointer than
// the input, the upgrade writes the output.
func (u *configUpgrade) inPlace(args ast.Node, input, output *ast.MappingValueNode, in inputClaim, read reader) ([]claimpath.Pointer, error) {
	if in.dotted == "" {
		return []claimpath.Pointer{in.path}, nil
	}
	out, err := read(in.dotted)
	if err != nil {
		return nil, fmt.Errorf("output: %w", err)
	}
	if out.Equal(in.path) {
		return []claimpath.Pointer{out}, nil
	}
	text, err := pointerText(out)
	if err != nil {
		return nil, err
	}
	u.rewrites[in.record].New += "; output: " + text
	if output != nil {
		return []claimpath.Pointer{out}, u.setOutput(output, text)
	}
	mapping, err := unwrap(args)
	if err != nil {
		return nil, err
	}
	m, ok := mapping.(*ast.MappingNode)
	if !ok {
		return nil, fmt.Errorf("%s is no mapping", args.GetPath())
	}
	return []claimpath.Pointer{out}, u.addEntry(m, input, "output", text)
}

// setOutput writes text as an output that is null or empty.
func (u *configUpgrade) setOutput(output *ast.MappingValueNode, text string) error {
	value, err := unwrap(output.Value)
	if err != nil {
		return err
	}
	if !isNull(value) {
		start, end, err := u.span(value)
		if err != nil {
			return err
		}
		u.replace(start, end, text)
		return nil
	}
	return u.setNull(output, text)
}

// writesInPlace reports whether a primitive writes its input's claim when
// its output is unset: its arguments have an Input and an optional Output.
func writesInPlace(name string) bool {
	for field := range reflect.TypeFor[primitives.Derivation]().Fields() {
		if yamlKey(field) != name || field.Type.Kind() != reflect.Pointer {
			continue
		}
		args := field.Type.Elem()
		_, hasInput := args.FieldByName("Input")
		output, hasOutput := args.FieldByName("Output")
		return hasInput && hasOutput && strings.Contains(output.Tag.Get("yaml"), "omitempty")
	}
	return false
}

// yamlKey returns the key a struct field decodes.
func yamlKey(field reflect.StructField) string {
	key, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
	return key
}

// ageOutputs returns the claims age_over_thresholds writes: two per
// threshold, at top-level keys of the issued document.
func ageOutputs(args ast.Node, issued *lazy) ([]claimpath.Pointer, error) {
	thresholds, err := descend(args, "thresholds")
	if err != nil {
		return nil, err
	}
	list, err := items(thresholds)
	if err != nil {
		return nil, err
	}
	var out []claimpath.Pointer
	for _, item := range list {
		threshold, err := strconv.Atoi(item.GetToken().Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", item.GetPath(), err)
		}
		for _, name := range primitives.AgeClaimNames(threshold) {
			p, err := issued.topLevel(name)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// openingInputs reads the claims an opening reads in the source data.
func (u *configUpgrade) openingInputs(args ast.Node, source *lazy) error {
	for _, generator := range []string{"hkdf", "hmac"} {
		inputs, err := descend(args, "opening", generator, "inputs")
		if err != nil {
			return err
		}
		list, err := items(inputs)
		if err != nil {
			return err
		}
		for _, item := range list {
			if _, _, err := u.pointer(item, source.dotted); err != nil {
				return err
			}
		}
	}
	input, err := descend(args, "opening", "claim", "input")
	if err != nil {
		return err
	}
	_, _, err = u.pointer(input, source.dotted)
	return err
}
