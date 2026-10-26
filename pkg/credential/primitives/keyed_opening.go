package primitives

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/SUNET/vc/pkg/base64url"
)

// KeyedOpeningArgs derives the opening with the keyed function F from a
// secret and the ordered input claims.
type KeyedOpeningArgs[F keyedFunction] struct {
	// SecretPath is a file holding the secret, base64url, decoding to at
	// least 32 bytes.
	SecretPath string `yaml:"secret_path" validate:"required" doc_example:"\"/pki/nym_auth_seed.key\""`
	// Inputs are claims of the source data, each a non-empty string.
	// Their order is part of the derivation. A presentation source lists
	// each in its required_claims.
	Inputs []string `yaml:"inputs" validate:"required,min=1,max=16,dive,required" doc_example:"[\"issuing_country\", \"personal_administrative_number\"]"`
	// Bytes is the opening length.
	Bytes int `yaml:"bytes" validate:"required" doc_example:"16"`
}

// HKDFOpeningArgs derives the opening with HKDF-SHA256.
//
// The opening has 16 to 64 bytes.
type HKDFOpeningArgs = KeyedOpeningArgs[hkdfSHA256]

// HMACOpeningArgs derives the opening with HMAC-SHA256.
//
// The opening has 16 to 32 bytes: the HMAC output, truncated to at least
// half its length (RFC 2104 section 5).
type HMACOpeningArgs = KeyedOpeningArgs[hmacSHA256]

// KeyedOpening is an hkdf or hmac opening: a function of the secret and the
// values of its input claims.
type KeyedOpening interface {
	// OpenValues derives the opening from the values of the input claims,
	// in their configured order.
	OpenValues(values []string) ([]byte, error)
}

// keyedFunction is the pseudorandom function of a keyed opening.
type keyedFunction interface {
	// name is the generator's key under opening.
	name() string
	// label separates the function's openings from other uses of the
	// secret.
	label() string
	// lengths is the range of openings the function produces.
	lengths() lengthRange
	// derive returns n bytes of the function keyed with secret over
	// message.
	derive(secret, message []byte, n int) ([]byte, error)
}

// hkdfSHA256 is HKDF-SHA256 (RFC 5869) with the secret as input keying
// material, an empty salt, and the message as info.
type hkdfSHA256 struct{}

func (hkdfSHA256) name() string         { return "hkdf" }
func (hkdfSHA256) label() string        { return "vc/hash_commitment/hkdf/v1" }
func (hkdfSHA256) lengths() lengthRange { return openingLengths }

func (hkdfSHA256) derive(secret, message []byte, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, string(message), n)
}

// hmacSHA256 is HMAC-SHA256 (RFC 2104) keyed with the secret over the
// message, truncated to n bytes.
type hmacSHA256 struct{}

func (hmacSHA256) name() string  { return "hmac" }
func (hmacSHA256) label() string { return "vc/hash_commitment/hmac/v1" }

func (hmacSHA256) lengths() lengthRange {
	return lengthRange{min: openingLengths.min, max: sha256.Size}
}

func (hmacSHA256) derive(secret, message []byte, n int) ([]byte, error) {
	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(message); err != nil {
		return nil, err
	}
	return mac.Sum(nil)[:n], nil
}

func (a *KeyedOpeningArgs[F]) name() string {
	var f F
	return f.name()
}

func (a *KeyedOpeningArgs[F]) inputs() []string { return a.Inputs }

func (a *KeyedOpeningArgs[F]) validate() error {
	_, err := a.key()
	return err
}

func (a *KeyedOpeningArgs[F]) open(claims map[string]any) ([]byte, error) {
	values := make([]string, 0, len(a.Inputs))
	for _, path := range a.Inputs {
		value, err := inputClaim(claims, path)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return a.OpenValues(values)
}

// OpenValues derives the opening from the values of Inputs, in their order.
func (a *KeyedOpeningArgs[F]) OpenValues(values []string) ([]byte, error) {
	message, err := a.message(values)
	if err != nil {
		return nil, err
	}
	key, err := a.key()
	if err != nil {
		return nil, err
	}
	return key.derive(message)
}

// message encodes the label, the opening length in decimal and the input
// values, each a field.
func (a *KeyedOpeningArgs[F]) message(values []string) ([]byte, error) {
	var f F
	if len(values) != len(a.Inputs) {
		return nil, fmt.Errorf("%w: %s takes %d input values, got %d", ErrInvalidClaimInput, f.name(), len(a.Inputs), len(values))
	}
	message := appendField(nil, f.label())
	message = appendField(message, strconv.Itoa(a.Bytes))
	for i, value := range values {
		if err := checkFieldValue(value); err != nil {
			// The value is personal data, so the error names the claim
			// only.
			return nil, fmt.Errorf("%w: %s input %q %w", ErrInvalidClaimInput, f.name(), a.Inputs[i], err)
		}
		message = appendField(message, value)
	}
	return message, nil
}

// openingKey is a keyed opening's loaded secret, with a length F
// produces.
type openingKey[F keyedFunction] struct {
	secret []byte
	bytes  int
}

// minSecretBytes is the output length of SHA-256.
const minSecretBytes = sha256.Size

// key checks the length and loads the secret file: base64url, at least 32
// bytes.
func (a *KeyedOpeningArgs[F]) key() (openingKey[F], error) {
	var f F
	if err := f.lengths().check(a.Bytes); err != nil {
		return openingKey[F]{}, fmt.Errorf("%s: %w", f.name(), err)
	}
	secret, err := base64url.ReadFile(a.SecretPath)
	if err != nil {
		return openingKey[F]{}, fmt.Errorf("%s: the opening secret: %w", f.name(), err)
	}
	if len(secret) < minSecretBytes {
		return openingKey[F]{}, fmt.Errorf("%s: the opening secret in %s is shorter than %d bytes", f.name(), a.SecretPath, minSecretBytes)
	}
	return openingKey[F]{secret: secret, bytes: a.Bytes}, nil
}

func (k openingKey[F]) derive(message []byte) ([]byte, error) {
	var f F
	return f.derive(k.secret, message, k.bytes)
}

// maxField is the longest field a two-byte length prefix holds.
const maxField = 1<<16 - 1

// appendField appends field to message, prefixed with its two-byte
// big-endian length.
func appendField(message []byte, field string) []byte {
	return append(binary.BigEndian.AppendUint16(message, uint16(len(field))), field...)
}

// checkFieldValue accepts an input value that is not blank and that a
// length prefix holds.
func checkFieldValue(value string) error {
	switch {
	case strings.TrimSpace(value) == "":
		return errors.New("must be a non-empty string")
	case len(value) > maxField:
		// A longer value would wrap its length prefix, and two inputs
		// would then encode alike.
		return fmt.Errorf("is longer than %d bytes", maxField)
	}
	return nil
}
