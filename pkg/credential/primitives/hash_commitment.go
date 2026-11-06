package primitives

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/base64url"
	"github.com/SUNET/vc/pkg/claimpath"
)

// HashCommitmentArgs fulfils the to_wallet hash_commitment entry at Path.
type HashCommitmentArgs struct {
	// Path is the claims path pointer of the to_wallet entry it fulfils.
	Path claimpath.Pointer `yaml:"path" validate:"required,nonempty_keys" doc_example:"[\"eu.europa.ec.eudi.nym_auth.1\", \"ssc\"]"`
	// Opening produces the opening.
	Opening OpeningArgs `yaml:"opening" validate:"required"`
}

// OpeningArgs produces the opening of a hash commitment.
//
// Exactly one field is set.
type OpeningArgs struct {
	// HKDF derives the opening from a secret and claims of the source
	// data.
	HKDF *HKDFOpeningArgs `yaml:"hkdf,omitempty"`
	// HMAC derives the opening from a secret and claims of the source
	// data.
	HMAC *HMACOpeningArgs `yaml:"hmac,omitempty"`
	// Random draws a random opening.
	Random *RandomOpeningArgs `yaml:"random,omitempty"`
	// Claim takes the opening from a claim of the source data.
	Claim *ClaimOpeningArgs `yaml:"claim,omitempty"`
}

// RandomOpeningArgs draws the opening from crypto/rand.
type RandomOpeningArgs struct {
	// Bytes is the opening length, 16 to 64.
	Bytes int `yaml:"bytes" validate:"required" doc_example:"16"`
}

// ClaimOpeningArgs takes the opening from a claim of the source data.
//
// The claim holds a per-subject secret as base64url text, decoding to 16 to
// 64 bytes. The secret stays out of the credential: the configuration is
// refused when the credential carries the claim or another derivation
// reads it.
type ClaimOpeningArgs struct {
	// Input is the claim of the source data that holds the opening. A
	// presentation source lists it in its required_claims.
	Input claimpath.Ref `yaml:"input" validate:"required" doc_example:"[\"nym_auth_opening\"]"`
}

// Apply implements Applier. The derivation pipeline skips hash_commitment,
// whose opening comes from NewOpening.
func (a *HashCommitmentArgs) Apply(Claims, time.Time) ([]Write, error) {
	return nil, errors.New("hash_commitment produces its opening through NewOpening")
}

// outputs implements ownOutputs: hash_commitment writes no claim of the
// source data.
func (a *HashCommitmentArgs) outputs(func(string) (claimpath.Pointer, error)) ([]claimpath.Pointer, error) {
	return nil, nil
}

// checkInputs checks that each opening input is one claim of the source
// data.
func (a *HashCommitmentArgs) checkInputs(source claimpath.Shape) error {
	generator, err := a.Opening.generator()
	if err != nil {
		return fmt.Errorf("opening: %w", err)
	}
	if claim, ok := generator.(*ClaimOpeningArgs); ok {
		if _, err := source.LocateOne(claim.Input.Path); err != nil {
			return fmt.Errorf("opening.claim.input: %w", err)
		}
		return nil
	}
	for i, input := range generator.inputs() {
		if _, err := source.LocateOne(input.Path); err != nil {
			return fmt.Errorf("opening.%s.inputs[%d]: %w", generator.name(), i, err)
		}
	}
	return nil
}

// HashCommitmentFor returns the hash_commitment derivation of list for
// path.
func HashCommitmentFor(list []Derivation, path claimpath.Pointer) *HashCommitmentArgs {
	for _, d := range list {
		if d.HashCommitment != nil && d.HashCommitment.Path.Equal(path) {
			return d.HashCommitment
		}
	}
	return nil
}

// OpeningInputs returns the claims of source, held in shape, that the
// hash_commitment derivations of list read as opening inputs. Each is a
// deep copy of the claim at the input's leading keys, held where source
// holds it, so a later write into source or a filter on it leaves them as
// they were. An input upgraded from a dotted name takes the top-level key
// of that name when source holds it. An input source lacks is left out.
func OpeningInputs(list []Derivation, source map[string]any, shape claimpath.Shape) (map[string]any, error) {
	var out map[string]any
	for _, d := range list {
		if d.HashCommitment == nil {
			continue
		}
		_, inputs, err := d.HashCommitment.Opening.Inputs()
		if err != nil {
			return nil, err
		}
		for _, input := range inputs {
			location, value, present, err := openingInput(source, shape, input)
			if err != nil {
				return nil, err
			}
			if !present {
				continue
			}
			if out == nil {
				out = map[string]any{}
			}
			if err := claimpath.Nested().Set(out, location, cloneClaimValue(value)); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// openingInput returns the claim of source an opening input reads, and
// the location source holds it at: the top-level key of the input's
// dotted name when source holds it, and the input's leading keys
// otherwise.
func openingInput(source map[string]any, shape claimpath.Shape, input claimpath.Ref) (claimpath.Pointer, any, bool, error) {
	if value, ok := input.Literal(source); ok {
		dotted, _ := input.Dotted()
		return claimpath.Keys(dotted), value, true, nil
	}
	keys, ok := input.Path.KeyPrefix()
	if !ok {
		return claimpath.Pointer{}, nil, false, fmt.Errorf("opening input %s starts with no key", input)
	}
	location, err := shape.LocateOne(keys)
	if err != nil {
		return claimpath.Pointer{}, nil, false, err
	}
	value, present, err := shape.Get(source, keys)
	if errors.Is(err, claimpath.ErrMismatch) {
		return claimpath.Pointer{}, nil, false, nil
	}
	return location, value, present, err
}

// NewOpening produces the opening from the claims of the source data,
// held in the source shape.
func (a *HashCommitmentArgs) NewOpening(claims map[string]any, source claimpath.Shape) ([]byte, error) {
	generator, err := a.Opening.generator()
	if err != nil {
		return nil, err
	}
	return generator.open(claims, source)
}

// openingGenerator produces an opening from the claims of the source data.
type openingGenerator interface {
	// name is the generator's key under opening.
	name() string
	// inputs are the claims of the source data the generator reads.
	inputs() []claimpath.Ref
	open(claims map[string]any, source claimpath.Shape) ([]byte, error)
	// validate checks what the configuration fixes: the length, and a
	// secret.
	validate() error
}

// generator returns the one generator the opening sets.
func (o OpeningArgs) generator() (openingGenerator, error) {
	var set []openingGenerator
	if o.HKDF != nil {
		set = append(set, o.HKDF)
	}
	if o.HMAC != nil {
		set = append(set, o.HMAC)
	}
	if o.Random != nil {
		set = append(set, o.Random)
	}
	if o.Claim != nil {
		set = append(set, o.Claim)
	}
	if len(set) != 1 {
		return nil, errors.New("set exactly one of hkdf, hmac, random and claim")
	}
	return set[0], nil
}

// Validate checks that the opening can be produced: one generator is set,
// its length is in range, and a keyed generator's secret loads.
func (o OpeningArgs) Validate() error {
	generator, err := o.generator()
	if err != nil {
		return err
	}
	return generator.validate()
}

// Inputs returns the key of the generator the opening sets, and the claims
// of the source data it reads.
func (o OpeningArgs) Inputs() (generator string, claims []claimpath.Ref, err error) {
	g, err := o.generator()
	if err != nil {
		return "", nil, err
	}
	return g.name(), slices.Clone(g.inputs()), nil
}

// Keyed returns the generator of an opening that sets hkdf or hmac alone.
func (o OpeningArgs) Keyed() (ValueOpener, bool) {
	generator, err := o.generator()
	if err != nil {
		return nil, false
	}
	keyed, ok := generator.(ValueOpener)
	return keyed, ok
}

// lengthRange is the lengths an opening takes, in bytes.
type lengthRange struct{ min, max int }

// openingLengths is the range of an opening. Its floor is 128 bits, the
// entropy section 4.1 of the auxiliary data extension requires.
var openingLengths = lengthRange{min: 16, max: 64}

func (r lengthRange) check(n int) error {
	if n < r.min || n > r.max {
		return fmt.Errorf("an opening has %d to %d bytes, got %d", r.min, r.max, n)
	}
	return nil
}

// inputClaim returns the value of the claim an opening input names in the
// source data, held in the source shape, which is a string. An input
// upgraded from a dotted name reads the top-level key of that name when
// the claims hold it.
func inputClaim(claims map[string]any, source claimpath.Shape, input claimpath.Ref) (string, error) {
	value, present := input.Literal(claims)
	if !present {
		var err error
		value, present, err = source.Get(claims, input.Path)
		if errors.Is(err, claimpath.ErrMismatch) {
			value, present = nil, false
		} else if err != nil {
			return "", err
		}
	}
	s, ok := value.(string)
	if !present || !ok {
		// The value is personal data, so the error names the claim only.
		return "", fmt.Errorf("%w: opening input %s must be a string", ErrInvalidClaimInput, input)
	}
	return s, nil
}

func (a *RandomOpeningArgs) name() string            { return "random" }
func (a *RandomOpeningArgs) inputs() []claimpath.Ref { return nil }

func (a *RandomOpeningArgs) validate() error {
	if err := openingLengths.check(a.Bytes); err != nil {
		return fmt.Errorf("%s: %w", a.name(), err)
	}
	return nil
}

func (a *RandomOpeningArgs) open(map[string]any, claimpath.Shape) ([]byte, error) {
	opening := make([]byte, a.Bytes)
	if _, err := rand.Read(opening); err != nil {
		return nil, err
	}
	return opening, nil
}

func (a *ClaimOpeningArgs) name() string            { return "claim" }
func (a *ClaimOpeningArgs) inputs() []claimpath.Ref { return []claimpath.Ref{a.Input} }

// validate accepts every claim: its value is checked when it is read.
func (a *ClaimOpeningArgs) validate() error {
	return nil
}

func (a *ClaimOpeningArgs) open(claims map[string]any, source claimpath.Shape) ([]byte, error) {
	value, err := inputClaim(claims, source, a.Input)
	if err != nil {
		return nil, err
	}
	// The value is a secret, so each error names the claim only.
	opening, err := base64url.Decode(value)
	if err != nil {
		return nil, fmt.Errorf("%w: opening input %s: %w", ErrInvalidClaimInput, a.Input, err)
	}
	if err := openingLengths.check(len(opening)); err != nil {
		return nil, fmt.Errorf("%w: opening input %s: %w", ErrInvalidClaimInput, a.Input, err)
	}
	return opening, nil
}
