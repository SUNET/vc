package primitives

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/credential/seed"
)

// HashCommitmentArgs fulfils the to_wallet hash_commitment entry at Path.
type HashCommitmentArgs struct {
	// Path is the claims path pointer of the to_wallet entry it fulfils.
	Path []string `yaml:"path" validate:"required,min=1,dive,required" doc_example:"[\"eu.europa.ec.eudi.nym_auth.1\", \"ssc\"]"`
	// Opening produces the opening.
	Opening OpeningArgs `yaml:"opening" validate:"required"`
}

// OpeningArgs produces the opening of a hash commitment. Exactly one field
// is set.
type OpeningArgs struct {
	// HKDF derives the opening from a secret and claims of the source
	// data.
	HKDF *HKDFOpeningArgs `yaml:"hkdf,omitempty"`
	// Random draws a random opening.
	Random *RandomOpeningArgs `yaml:"random,omitempty"`
}

// HKDFOpeningArgs derives the opening with HKDF-SHA256 over the ordered
// input claims.
type HKDFOpeningArgs struct {
	// SecretPath is a file holding the secret, base64url, decoding to at
	// least 32 bytes.
	SecretPath string `yaml:"secret_path" validate:"required" doc_example:"\"/pki/nym_auth_seed.key\""`
	// Inputs are claims of the source data, each a non-empty string.
	// Their order is part of the derivation.
	Inputs []string `yaml:"inputs" validate:"required,min=1,max=16,dive,required" doc_example:"[\"issuing_country\", \"personal_administrative_number\"]"`
	// Bytes is the opening length.
	Bytes int `yaml:"bytes" validate:"required,min=16,max=64" doc_example:"16"`
}

// RandomOpeningArgs draws the opening from crypto/rand.
type RandomOpeningArgs struct {
	// Bytes is the opening length.
	Bytes int `yaml:"bytes" validate:"required,min=16,max=64" doc_example:"16"`
}

// Apply implements Applier. The derivation pipeline skips hash_commitment,
// whose opening comes from NewOpening.
func (a *HashCommitmentArgs) Apply(map[string]any, time.Time) (map[string]any, error) {
	return nil, errors.New("hash_commitment produces its opening through NewOpening")
}

// NewOpening produces the opening from the claims of the source data.
func (a *HashCommitmentArgs) NewOpening(ctx context.Context, claims map[string]any) ([]byte, error) {
	generator, err := a.Opening.generator()
	if err != nil {
		return nil, err
	}
	return generator.open(ctx, claims)
}

// openingGenerator produces an opening from the claims of the source data.
type openingGenerator interface {
	open(ctx context.Context, claims map[string]any) ([]byte, error)
}

// generator returns the one generator the opening sets.
func (o OpeningArgs) generator() (openingGenerator, error) {
	switch {
	case o.HKDF != nil && o.Random == nil:
		return o.HKDF, nil
	case o.Random != nil && o.HKDF == nil:
		return o.Random, nil
	default:
		return nil, errors.New("set exactly one of hkdf and random")
	}
}

// Validate checks that the opening can be produced: one generator is set,
// and an hkdf secret loads.
func (o OpeningArgs) Validate() error {
	if _, err := o.generator(); err != nil {
		return err
	}
	if o.HKDF == nil {
		return nil
	}
	if _, err := o.HKDF.Deriver(); err != nil {
		return fmt.Errorf("hkdf: %w", err)
	}
	return nil
}

// Deriver loads the secret and returns the HKDF deriver it configures.
func (a *HKDFOpeningArgs) Deriver() (*seed.Deriver, error) {
	raw, err := os.ReadFile(filepath.Clean(a.SecretPath))
	if err != nil {
		return nil, fmt.Errorf("reading the opening secret: %w", err)
	}
	secret, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(string(raw)), "="))
	if err != nil {
		return nil, fmt.Errorf("the opening secret in %s is not base64url: %w", a.SecretPath, err)
	}
	return seed.NewDeriver(secret, a.Bytes)
}

func (a *HKDFOpeningArgs) open(ctx context.Context, claims map[string]any) ([]byte, error) {
	inputs := make([]string, 0, len(a.Inputs))
	for _, path := range a.Inputs {
		val, present := lookupClaim(claims, path)
		s, ok := val.(string)
		if !present || !ok || strings.TrimSpace(s) == "" {
			// The value is a personal identifier, so the error names the
			// claim only.
			return nil, fmt.Errorf("%w: hkdf input %q must be a non-empty string", ErrInvalidClaimInput, path)
		}
		inputs = append(inputs, s)
	}
	deriver, err := a.Deriver()
	if err != nil {
		return nil, err
	}
	return deriver.Seed(ctx, inputs, "")
}

func (a *RandomOpeningArgs) open(context.Context, map[string]any) ([]byte, error) {
	opening := make([]byte, a.Bytes)
	if _, err := rand.Read(opening); err != nil {
		return nil, err
	}
	return opening, nil
}
