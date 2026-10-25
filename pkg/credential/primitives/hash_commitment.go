package primitives

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/base64url"
	"github.com/SUNET/vc/pkg/claimpath"
)

// HashCommitmentArgs fulfils the to_wallet hash_commitment entry at Path.
type HashCommitmentArgs struct {
	// Path is the claims path pointer of the to_wallet entry it fulfils.
	Path claimpath.Pointer `yaml:"path" validate:"required" doc_example:"[\"eu.europa.ec.eudi.nym_auth.1\", \"ssc\"]"`
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
	Inputs []claimpath.Pointer `yaml:"inputs" validate:"required,min=1,max=16,dive,required" doc_example:"[[\"issuing_country\"], [\"personal_administrative_number\"]]"`
	// Bytes is the opening length.
	Bytes int `yaml:"bytes" validate:"required" doc_example:"16"`
}

// RandomOpeningArgs draws the opening from crypto/rand.
type RandomOpeningArgs struct {
	// Bytes is the opening length.
	Bytes int `yaml:"bytes" validate:"required" doc_example:"16"`
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

// resolve reads the dotted hkdf inputs as claims of the source data.
func (a *HashCommitmentArgs) resolve(source claimpath.Shape) error {
	if a.Opening.HKDF == nil {
		return nil
	}
	for i := range a.Opening.HKDF.Inputs {
		if err := source.ResolveOne(&a.Opening.HKDF.Inputs[i]); err != nil {
			return fmt.Errorf("opening.hkdf.inputs[%d]: %w", i, err)
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
	open(claims map[string]any, source claimpath.Shape) ([]byte, error)
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

// An opening has 16 to 64 bytes: at least 128 bits.
const (
	minOpeningBytes = 16
	maxOpeningBytes = 64
)

// Validate checks that the opening can be produced: one generator is set,
// the length is in range, and an hkdf secret loads.
func (o OpeningArgs) Validate() error {
	if _, err := o.generator(); err != nil {
		return err
	}
	if n := o.bytes(); n < minOpeningBytes || n > maxOpeningBytes {
		return fmt.Errorf("an opening has %d to %d bytes, got %d", minOpeningBytes, maxOpeningBytes, n)
	}
	if o.HKDF == nil {
		return nil
	}
	if _, err := o.HKDF.secret(); err != nil {
		return fmt.Errorf("hkdf: %w", err)
	}
	return nil
}

// bytes is the length the set generator produces.
func (o OpeningArgs) bytes() int {
	if o.HKDF != nil {
		return o.HKDF.Bytes
	}
	return o.Random.Bytes
}

// minHKDFSecretBytes is the output length of SHA-256.
const minHKDFSecretBytes = sha256.Size

// secret reads the secret file: base64url, at least 32 bytes.
func (a *HKDFOpeningArgs) secret() ([]byte, error) {
	secret, err := base64url.ReadFile(a.SecretPath)
	if err != nil {
		return nil, fmt.Errorf("the opening secret: %w", err)
	}
	if len(secret) < minHKDFSecretBytes {
		return nil, fmt.Errorf("the opening secret in %s is shorter than %d bytes", a.SecretPath, minHKDFSecretBytes)
	}
	return secret, nil
}

func (a *HKDFOpeningArgs) open(claims map[string]any, source claimpath.Shape) ([]byte, error) {
	values := make([]string, 0, len(a.Inputs))
	for _, path := range a.Inputs {
		val, present, err := source.Get(claims, path)
		s, ok := val.(string)
		if err != nil || !present || !ok {
			// The value is a personal identifier, so the error names the
			// claim only.
			return nil, fmt.Errorf("%w: hkdf input %s must be a non-empty string", ErrInvalidClaimInput, path)
		}
		values = append(values, s)
	}
	return a.OpenValues(values)
}

// OpenValues derives the opening from the values of Inputs, in their order.
func (a *HKDFOpeningArgs) OpenValues(values []string) ([]byte, error) {
	if len(values) != len(a.Inputs) {
		return nil, fmt.Errorf("%w: hkdf takes %d input values, got %d", ErrInvalidClaimInput, len(a.Inputs), len(values))
	}
	info := hkdfField(nil, hkdfLabel)
	info = hkdfField(info, strconv.Itoa(a.Bytes))
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%w: hkdf input %s must be a non-empty string", ErrInvalidClaimInput, a.Inputs[i])
		}
		if len(value) > maxHKDFField {
			// A longer value would wrap its length prefix, and two inputs
			// would then encode alike.
			return nil, fmt.Errorf("%w: hkdf input %s is longer than %d bytes", ErrInvalidClaimInput, a.Inputs[i], maxHKDFField)
		}
		info = hkdfField(info, value)
	}
	secret, err := a.secret()
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, secret, nil, string(info), a.Bytes)
}

// hkdfLabel separates the hkdf opening from other uses of the secret.
const hkdfLabel = "vc/hash_commitment/hkdf/v1"

// maxHKDFField is the longest field a two-byte length prefix holds.
const maxHKDFField = 1<<16 - 1

// hkdfField appends field to info, prefixed with its length.
func hkdfField(info []byte, field string) []byte {
	return append(binary.BigEndian.AppendUint16(info, uint16(len(field))), field...)
}

func (a *RandomOpeningArgs) open(map[string]any, claimpath.Shape) ([]byte, error) {
	opening := make([]byte, a.Bytes)
	if _, err := rand.Read(opening); err != nil {
		return nil, err
	}
	return opening, nil
}
