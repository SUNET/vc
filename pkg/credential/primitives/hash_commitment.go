package primitives

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/base64url"
)

// HashCommitmentArgs configures the hash_commitment primitive.
type HashCommitmentArgs struct {
	// Path is the claims path pointer of the entry.
	Path []string `yaml:"path" validate:"required,min=1,dive,required" doc_example:"[\"eu.europa.ec.eudi.nym_auth.1\", \"ssc\"]"`
	// Opening produces the opening of a to_wallet entry. The wallet holds
	// the opening of a to_issuer entry.
	Opening *OpeningArgs `yaml:"opening,omitempty"`
	// Unique sets the key the commitment is unique per.
	Unique *UniqueArgs `yaml:"unique,omitempty"`
}

// UniqueArgs configures unique.
//
// The issuer accepts one commitment per value of key, until an operator
// resets it.
type UniqueArgs struct {
	// Key lists claims path pointers of the credential. An empty list
	// makes one commitment for the entry.
	Key [][]string `yaml:"key" validate:"required,dive,min=1,dive,required" doc_example:"[[\"eu.europa.ec.eudi.nym_auth.1\", \"ssc\"]]"`
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
	// Input is the claim of the source data that holds the opening.
	// Supports dot-notation claim paths and literal dotted keys. A
	// presentation source lists it in its required_claims.
	Input string `yaml:"input" validate:"required" doc_example:"\"nym_auth_opening\""`
}

// Apply implements Applier. The Credential Endpoint applies
// hash_commitment.
func (a *HashCommitmentArgs) Apply(map[string]any, time.Time) (map[string]any, error) {
	return nil, errors.New("the Credential Endpoint applies hash_commitment")
}

// HashCommitmentFor returns the hash_commitment derivation of list for
// path.
func HashCommitmentFor(list []Derivation, path []string) *HashCommitmentArgs {
	for _, d := range list {
		if d.HashCommitment != nil && slices.Equal(d.HashCommitment.Path, path) {
			return d.HashCommitment
		}
	}
	return nil
}

// OpeningInputs returns the claims of source that the hash_commitment
// derivations of list read as opening inputs, each a deep copy held under
// its path as one literal key, so a later write into source or a filter on
// it leaves them as they were. An input source lacks is left out.
func OpeningInputs(list []Derivation, source map[string]any) map[string]any {
	var out map[string]any
	for _, d := range list {
		if d.HashCommitment == nil || d.HashCommitment.Opening == nil {
			continue
		}
		_, inputs, err := d.HashCommitment.Opening.Inputs()
		if err != nil {
			continue
		}
		for _, path := range inputs {
			value, present := lookupClaim(source, path)
			if !present {
				continue
			}
			if out == nil {
				out = map[string]any{}
			}
			out[path] = cloneClaimValue(value)
		}
	}
	return out
}

// NewOpening produces the opening from the claims of the source data.
func (a *HashCommitmentArgs) NewOpening(claims map[string]any) ([]byte, error) {
	if a.Opening == nil {
		return nil, fmt.Errorf("hash_commitment %q configures no opening", a.Path)
	}
	generator, err := a.Opening.generator()
	if err != nil {
		return nil, err
	}
	return generator.open(claims)
}

// openingGenerator produces an opening from the claims of the source data.
type openingGenerator interface {
	// name is the generator's key under opening.
	name() string
	// inputs are the claims of the source data the generator reads.
	inputs() []string
	open(claims map[string]any) ([]byte, error)
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
func (o OpeningArgs) Inputs() (generator string, claims []string, err error) {
	g, err := o.generator()
	if err != nil {
		return "", nil, err
	}
	return g.name(), g.inputs(), nil
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

// inputClaim returns the value of the claim at path of the source data,
// which is a string.
func inputClaim(claims map[string]any, path string) (string, error) {
	value, present := lookupClaim(claims, path)
	s, ok := value.(string)
	if !present || !ok {
		// The value is personal data, so the error names the claim only.
		return "", fmt.Errorf("%w: opening input %q must be a string", ErrInvalidClaimInput, path)
	}
	return s, nil
}

func (a *RandomOpeningArgs) name() string     { return "random" }
func (a *RandomOpeningArgs) inputs() []string { return nil }

func (a *RandomOpeningArgs) validate() error {
	if err := openingLengths.check(a.Bytes); err != nil {
		return fmt.Errorf("%s: %w", a.name(), err)
	}
	return nil
}

func (a *RandomOpeningArgs) open(map[string]any) ([]byte, error) {
	opening := make([]byte, a.Bytes)
	if _, err := rand.Read(opening); err != nil {
		return nil, err
	}
	return opening, nil
}

func (a *ClaimOpeningArgs) name() string     { return "claim" }
func (a *ClaimOpeningArgs) inputs() []string { return []string{a.Input} }

// validate accepts every claim: its value is checked when it is read.
func (a *ClaimOpeningArgs) validate() error {
	return nil
}

func (a *ClaimOpeningArgs) open(claims map[string]any) ([]byte, error) {
	value, err := inputClaim(claims, a.Input)
	if err != nil {
		return nil, err
	}
	// The value is a secret, so each error names the claim only.
	opening, err := base64url.Decode(value)
	if err != nil {
		return nil, fmt.Errorf("%w: opening input %q: %w", ErrInvalidClaimInput, a.Input, err)
	}
	if err := openingLengths.check(len(opening)); err != nil {
		return nil, fmt.Errorf("%w: opening input %q: %w", ErrInvalidClaimInput, a.Input, err)
	}
	return opening, nil
}
