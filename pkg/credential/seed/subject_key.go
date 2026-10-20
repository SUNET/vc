package seed

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// subjectKeyLabel separates a subject key from a seed derivation.
//
// Its own label, not derivationLabel, because the two are different
// functions of the same inputs and must stay distinguishable: a value
// that is a key to a record must never also be usable as derivation
// input, or a store full of keys becomes a store full of seed material.
const subjectKeyLabel = "vc/psc-subject/v1"

// SubjectKeyBytes is the width of a subject key: SHA-256, so 32.
const SubjectKeyBytes = sha256.Size

// SubjectKey is the stable, non-reversible key a per-subject record is
// stored under.
//
// Over the SAME ordered identifiers, with the SAME length-prefixed
// encoding, that Seed derives from. That is the point of it: a
// holder-supplied commitment has to be one per subject, and "the same
// subject" has to mean exactly what it means for an issuer-derived
// seed, or the two configurations of one rulebook would disagree about
// who a person is.
//
// Hashed rather than stored in the clear because the record is a list
// of who holds a nym_auth credential. The store does not need the
// identifiers to do its job, so it should not hold them.
//
// Not reversible, and not meant to be: an operator resetting a record
// supplies the identifiers again and this recomputes the key.
func SubjectKey(subjectIDs []string) ([]byte, error) {
	if len(subjectIDs) == 0 {
		return nil, ErrNoSubject
	}
	if len(subjectIDs) > maxDerivationFields {
		return nil, fmt.Errorf("seed: %d subject identifiers exceeds the limit of %d", len(subjectIDs), maxDerivationFields)
	}
	for i, id := range subjectIDs {
		// Refused rather than skipped, exactly as in Seed: skipping
		// would make ["a", ""] key the record of ["a"], so a subject
		// whose second identifier failed to resolve would be checked
		// against - and could overwrite - another subject's record.
		if id == "" {
			return nil, fmt.Errorf("%w (identifier %d of %d)", ErrNoSubject, i, len(subjectIDs))
		}
	}

	encoded, err := subjectKeyInfo(subjectIDs...)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(encoded))
	return sum[:], nil
}

// SubjectKeyHex is SubjectKey rendered the way the stores hold it.
func SubjectKeyHex(subjectIDs []string) (string, error) {
	key, err := SubjectKey(subjectIDs)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// subjectKeyInfo encodes the identifiers under subjectKeyLabel.
//
// It shares derivationInfo's body deliberately - the encoding is the
// part that must not differ - and differs only in the label, which is
// what keeps the two functions apart.
func subjectKeyInfo(fields ...string) (string, error) {
	return encodeFields(subjectKeyLabel, fields...)
}
