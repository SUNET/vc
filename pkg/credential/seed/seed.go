// Package seed produces a per-subject secret and the commitment an issuer
// writes into a credential in its place.
//
// The shape is the same wherever it is used: a subject has one seed; the
// credential carries commit(seed) and never the seed. Whoever holds the
// seed can recompute anything derived from it later - which is what makes
// a pseudonym built on it remappable to a person, and is the reason the
// seed is worth as much care as a signing key.
//
// Nothing here knows about a credential type or a credential format. The
// first consumer is the EUDI nym_auth attestation, whose `ssc` element is
// SHA-256 over a 16-byte seed, but that is a configuration of this package
// and not a property of it.
package seed

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// MinSecretBytes is the shortest derivation secret this package accepts.
//
// A derivation secret is not rotatable in any useful sense - every
// commitment ever written under it is a function of it, so replacing it
// repseudonymises everyone - which makes "long enough" a decision taken
// once and never revisited. 32 bytes is the output size of the hash the
// derivation runs on; less than that would cap the entropy of every seed
// below the construction's own strength.
const MinSecretBytes = 32

// DefaultSeedBytes is the seed length a consumer gets without saying.
// nym_auth's 16 bytes; a different consumer may ask for more.
const DefaultSeedBytes = 16

// MaxSeedBytes bounds what a configuration may ask for. HKDF-SHA256 can
// expand to 255*32 bytes; anything near that in a credential claim is a
// configuration mistake rather than a use case.
const MaxSeedBytes = 64

// derivationLabel separates this use of HKDF from any other, and carries a
// version so that a change to the construction has to be a deliberate new
// label rather than a silent repseudonymisation of everyone.
const derivationLabel = "vc/seed/v1"

// ErrNoSubject is returned for an empty subject identifier.
//
// Deriving over "" would give every subject without a resolvable
// identifier the same seed, and therefore the same pseudonym - the exact
// opposite of what the identifier is for. It is an error, never a default.
var ErrNoSubject = errors.New("seed: subject identifier is empty")

// Source yields a subject's seed. One subject, one seed: the same
// identifier must give the same bytes on every call, for the life of the
// deployment, across formats and across credential configurations.
//
// The interface exists so that a stored implementation - a random value
// drawn once per subject and kept - can replace the derived one without
// anything above it changing. Deriver is the only implementation here.
type Source interface {
	Seed(ctx context.Context, subjectID, context_ string) ([]byte, error)
}

// Deriver computes a subject's seed from a secret it holds.
//
// Nothing is stored: the same inputs give the same seed forever, which is
// what makes the seed recoverable without a database. The cost is that the
// secret is permanent - see MinSecretBytes.
type Deriver struct {
	secret    *secretKey
	seedBytes int
}

// secretKey holds the derivation key behind a pointer.
//
// The indirection is not for sharing - it is so that REFLECTION prints an
// address instead of the key. fmt resolves %T and %p before it consults
// Formatter, and the bad-verb path it lands on sets its erroring flag,
// which disables String, GoString and Format outright. So %p on a Deriver
// VALUE renders the struct by reflection with no method able to intervene;
// go vet flags that as a mistake, but "vet would have caught it" is not
// the same as "the key cannot be printed". A pointer field renders as an
// address at that depth, and there is nothing to read.
type secretKey struct{ bytes []byte }

// NewDeriver returns a Deriver over secret, producing seeds of seedBytes.
// Pass 0 for DefaultSeedBytes.
func NewDeriver(secret []byte, seedBytes int) (*Deriver, error) {
	if len(secret) < MinSecretBytes {
		// Deliberately does not report the length it got: this runs at
		// startup, where the error reaches a log, and the length of a
		// secret is information about the secret.
		return nil, fmt.Errorf("seed: derivation secret is shorter than the %d-byte minimum", MinSecretBytes)
	}
	if seedBytes == 0 {
		seedBytes = DefaultSeedBytes
	}
	if seedBytes < 1 || seedBytes > MaxSeedBytes {
		return nil, fmt.Errorf("seed: seed length %d is outside 1..%d", seedBytes, MaxSeedBytes)
	}

	// Copied, so a caller that zeroes or reuses its buffer cannot change
	// what every subject's seed is afterwards.
	owned := make([]byte, len(secret))
	copy(owned, secret)

	return &Deriver{secret: &secretKey{bytes: owned}, seedBytes: seedBytes}, nil
}

// Seed derives the subject's seed.
//
// context_ separates populations that must not share seeds. It is empty in
// the ordinary case, because a subject has ONE seed: two credential types
// issued to the same person have to lead back to the same person, and they
// would not if the credential configuration were part of the derivation.
func (d *Deriver) Seed(_ context.Context, subjectID, context_ string) ([]byte, error) {
	if subjectID == "" {
		return nil, ErrNoSubject
	}

	// The secret is the HKDF key and is deliberately NOT part of info.
	// Naming a secret identifier in the context would invite rotating it,
	// and rotating it changes every seed it has ever produced.
	//
	// The seed LENGTH is in the info, which it would not have to be: HKDF
	// expand is a stream, so a 32-byte seed would otherwise begin with the
	// 16-byte seed for the same subject. Harmless - every commitment
	// changes anyway, since the digest is over a different length - but a
	// derivation whose output is a prefix of another derivation's is a
	// surprise waiting for whoever reads this next. Naming the length
	// makes the seed a function of all of its declared parameters.
	info, err := derivationInfo(strconv.Itoa(d.seedBytes), context_, subjectID)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, d.secret.bytes, nil, info, d.seedBytes)
	if err != nil {
		return nil, fmt.Errorf("seed: derivation failed: %w", err)
	}
	return key, nil
}

// SeedBytes reports the seed length this Deriver produces.
func (d *Deriver) SeedBytes() int { return d.seedBytes }

// String keeps the secret out of anything that renders a Deriver.
//
// Without it the secret reaches a log or an error the first time someone
// puts an enclosing struct through %v - a decision nobody takes
// deliberately, which is exactly why it has to be impossible rather than
// discouraged.
func (d Deriver) String() string {
	return fmt.Sprintf("seed.Deriver{secret: <redacted>, seedBytes: %d}", d.seedBytes)
}

// GoString keeps the secret out of %#v for a caller that reaches for
// GoString directly. Format below covers the verb.
func (d Deriver) GoString() string { return d.String() }

// Format redacts under EVERY verb, which String alone does not do.
//
// Value receiver, here and on String and GoString, so a COPIED Deriver
// redacts too - a pointer's method set includes value-receiver methods,
// but not the other way round, so a pointer receiver would leave
// fmt.Printf("%v", *d), and any struct holding a Deriver by value, back on
// reflection and printing the secret.
//
// String and GoString are consulted only for the string-capable verbs. A
// numeric one - %d, say, on an enclosing struct somebody logged - skips
// both and falls back to reflection, which walks into the struct and
// prints the secret as decimal bytes. That is not a hypothetical reading
// of the fmt documentation: it was the observed behaviour here before
// this existed.
//
// So the rendering is deliberately the same under every verb, including
// ones where it reads oddly (%d produces a sentence). A redaction that
// holds for the verbs someone thought of is not a redaction.
func (d Deriver) Format(f fmt.State, _ rune) {
	io.WriteString(f, d.String())
}

// derivationInfo builds the HKDF info string.
//
// Every field is length-prefixed rather than joined by a separator, so no
// two fields can be slid into one another: with a separator, a context of
// "a" and a subject of "b.c" would produce the same info as "a.b" and "c",
// and two different people would share a seed.
func derivationInfo(fields ...string) (string, error) {
	var out []byte
	for _, f := range append([]string{derivationLabel}, fields...) {
		if len(f) > maxDerivationField {
			// The prefix is what separates the fields, so a length it
			// cannot hold stops separating them. uint16(90465) is 24929,
			// and ("", "a"x65536+"b"x24929) then encodes byte for byte
			// like ("a"x65536, "b"x24929): two different subjects, one
			// seed, from the same secret.
			//
			// Refused rather than widened: the prefix width is part of
			// the derivation, so growing it would change every seed ever
			// produced. No real subject identifier is this long.
			return "", fmt.Errorf("seed: a derivation field of %d bytes exceeds the %d-byte limit, and would collide with a different one", len(f), maxDerivationField)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(f)))
		out = append(out, f...)
	}
	return string(out), nil
}

// maxDerivationField is the longest value a 2-byte length prefix can
// describe. Enforced where the prefix is written, so a caller reaching
// derivation directly - seed_recover -context, say - cannot slip past a
// check placed anywhere else.
const maxDerivationField = 1<<16 - 1

// Commit returns the commitment a credential carries in place of the seed.
//
// fn names the digest, so that a consumer specifying something other than
// SHA-256 is a configuration change rather than a code change. Only
// "sha-256" is registered, and an unknown name is an error rather than a
// fallback - a commitment written under the wrong function is one no
// verifier can ever open.
func Commit(fn string, seedValue []byte) ([]byte, error) {
	if len(seedValue) == 0 {
		return nil, errors.New("seed: cannot commit to an empty seed")
	}
	switch fn {
	case "", CommitSHA256:
		sum := sha256.Sum256(seedValue)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("seed: unknown commitment function %q", fn)
	}
}

// CommitSHA256 is the only registered commitment function.
const CommitSHA256 = "sha-256"

// CommitmentBytes reports the length a commitment under fn has, so a
// caller can check a value it did not compute - a holder-supplied
// commitment, or one arriving from a data source - without computing one.
func CommitmentBytes(fn string) (int, error) {
	switch fn {
	case "", CommitSHA256:
		return sha256.Size, nil
	default:
		return 0, fmt.Errorf("seed: unknown commitment function %q", fn)
	}
}
