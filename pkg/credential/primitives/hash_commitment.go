package primitives

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/base64url"
)

// HashCommitmentArgs fulfils the to_wallet hash_commitment entry at Path.
type HashCommitmentArgs struct {
	// Path is the claims path pointer of the to_wallet entry it fulfils.
	Path []string `yaml:"path" validate:"required,min=1,dive,required" doc_example:"[\"eu.europa.ec.eudi.nym_auth.1\", \"ssc\"]"`
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
	// Input is the claim of the source data that holds the opening.
	// Supports dot-notation claim paths and literal dotted keys.
	Input string `yaml:"input" validate:"required" doc_example:"\"nym_auth_opening\""`
}

// Apply implements Applier. The derivation pipeline skips hash_commitment,
// whose opening comes from NewOpening.
func (a *HashCommitmentArgs) Apply(map[string]any, time.Time) (map[string]any, error) {
	return nil, errors.New("hash_commitment produces its opening through NewOpening")
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

// NewOpening produces the opening from the claims of the source data.
func (a *HashCommitmentArgs) NewOpening(claims map[string]any) ([]byte, error) {
	generator, err := a.Opening.generator()
	if err != nil {
		return nil, err
	}
	return generator.open(claims)
}

// openingGenerator produces an opening from the claims of the source data.
type openingGenerator interface {
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

// Keyed returns the generator of an opening that sets hkdf or hmac alone.
func (o OpeningArgs) Keyed() (KeyedOpening, bool) {
	generator, err := o.generator()
	if err != nil {
		return nil, false
	}
	keyed, ok := generator.(KeyedOpening)
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

func (a *RandomOpeningArgs) validate() error {
	if err := openingLengths.check(a.Bytes); err != nil {
		return fmt.Errorf("random: %w", err)
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
