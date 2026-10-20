package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrPSCConflict is returned when a subject with a record already
// presents a DIFFERENT commitment, and no reset has been approved.
//
// The issuance is refused and nothing is issued. Writing the new value
// would discard a commitment the subject's other credentials already
// name; writing the credential with the RECORDED one would hand the
// holder a credential committing to a seed its wallet cannot open,
// which it would discover at presentation with nothing to explain it.
var ErrPSCConflict = errors.New("nymauth: this subject already has a different nym_auth commitment on record")

// ErrPSCNoRecord is returned when a reset is asked for a subject with
// no record. There is nothing to reset, and inventing an audit row for
// a reset that did not happen would make the trail untrue.
var ErrPSCNoRecord = errors.New("nymauth: this subject has no nym_auth commitment on record")

// PSCCommitmentBytes is the width of a nym_auth commitment: SHA-256 of
// the holder's private_seed, so 32.
const PSCCommitmentBytes = sha256.Size

// NymAuthPSCRecord is one subject's accepted holder-generated
// commitment.
//
// Between resets there is exactly one of these per subject, which is
// the rule the whole store exists to enforce.
type NymAuthPSCRecord struct {
	// SubjectKey is seed.SubjectKeyHex over the ordered subject
	// identifiers: hex, 64 characters. The identifiers themselves are
	// not stored.
	SubjectKey string `bson:"subject_key"`
	// PSC is the commitment, hex.
	PSC string `bson:"psc"`
	// Acceptance distinguishes ONE acceptance from the next, even when
	// the next records the same commitment.
	//
	// A reset audits an acceptance, and a retry completing an
	// interrupted reset must remove the acceptance it audited and no
	// other. Without it, Accept(A) - reset - Accept(A) - replay the
	// reset removes the second A, because the commitment alone cannot
	// tell two acceptances of the same value apart.
	Acceptance string `bson:"acceptance"`
	// AcceptedAt is when this value was first accepted.
	AcceptedAt time.Time `bson:"accepted_at"`
}

// NymAuthPSCReset is one audit row: an operator-approved reset.
type NymAuthPSCReset struct {
	SubjectKey string `bson:"subject_key"`
	// EvidenceRef points at the re-identification record, wherever that
	// process keeps it. It is also the idempotency key: one piece of
	// evidence resets a subject once.
	EvidenceRef string `bson:"evidence_ref"`
	// ResetOf is SHA-256 of the PREVIOUS commitment, hex - never the
	// commitment. See the migration for why. It is for the human
	// reading the trail.
	ResetOf string `bson:"reset_of"`
	// ResetAcceptance is the acceptance this reset removed, and is
	// what a compensating retry matches on. See
	// NymAuthPSCRecord.Acceptance.
	ResetAcceptance string `bson:"reset_acceptance"`
	// ApprovedBy is the operator identity from the admin session.
	ApprovedBy string    `bson:"approved_by"`
	ApprovedAt time.Time `bson:"approved_at"`
}

// NymAuthPSCStore records which holder-generated commitment a subject
// has already supplied.
//
// The nym_auth rulebook allows one per subject per issuer; enforcing
// that is what this is for. Every method takes a subject KEY, not the
// identifiers: hashing happens once, at the edge, so no implementation
// can hold the identifiers by accident.
type NymAuthPSCStore interface {
	// Accept records psc for this subject, and is the only way a
	// commitment enters the store.
	//
	// Returns nil when the value is newly recorded AND when the same
	// value is presented again - re-issuance, batch issuance and a
	// retried request all reach this legitimately. Returns
	// ErrPSCConflict when a different value is on record.
	Accept(ctx context.Context, subjectKey, psc string, now time.Time) error

	// Get returns the subject's record, or nil when there is none.
	Get(ctx context.Context, subjectKey string) (*NymAuthPSCRecord, error)

	// Reset removes the record so the next Accept starts a new one, and
	// writes the audit row.
	//
	// Idempotent per evidenceRef: a retry with the same evidence is a
	// no-op, which is what stops a replayed request from discarding a
	// record the subject has since re-established.
	//
	// ErrPSCNoRecord when there is nothing to reset and this evidence
	// has not already been used.
	Reset(ctx context.Context, subjectKey, approvedBy, evidenceRef string, now time.Time) error

	// Resets returns the audit trail for one subject, oldest first.
	Resets(ctx context.Context, subjectKey string) ([]NymAuthPSCReset, error)

	// Erase removes the record AND its audit rows.
	//
	// Together, always: an audit trail that outlives the record it
	// describes is a retained identifier with no remaining purpose.
	// Erasing does NOT invalidate pseudonyms already issued, which stay
	// derivable from the holder's own seed.
	Erase(ctx context.Context, subjectKey string) error
}

// ResetOf is the audit trail's reference to a commitment: SHA-256 of
// it, hex.
//
// A hash and not the value, so the trail shows that a reset happened
// and who approved it without keeping a working key to the subject's
// former pseudonyms.
func ResetOf(psc string) string {
	sum := sha256.Sum256([]byte(psc))
	return hex.EncodeToString(sum[:])
}

// completesAnInterruptedReset decides whether a record still present
// after an audit row was written is the one that reset removed.
//
// A pure predicate, and separate from the store, because it is the
// whole correctness of the compensating retry and it is wrong in ways
// that no amount of integration testing in one backend would surface.
// Only the non-transactional backend calls it; the SQL store writes
// both halves in one transaction and can never reach the state.
//
// It matches on the ACCEPTANCE. Matching on the commitment looks
// equivalent and is not: a subject recovering with the same wallet and
// the same seed re-presents the SAME commitment, so a replayed reset
// would delete that new record while believing it was finishing an
// interrupted one.
func completesAnInterruptedReset(auditedAcceptance string, record *NymAuthPSCRecord) bool {
	if record == nil || auditedAcceptance == "" {
		return false
	}
	return record.Acceptance == auditedAcceptance
}

// checkPSCArgs refuses arguments no caller could legitimately have.
//
// Shared by both backends so the two cannot disagree about what is
// storable, and placed here rather than at the HTTP edge because the
// store's invariant - one well-formed commitment per subject - has to
// hold for every caller, including a future one.
func checkPSCArgs(subjectKey, psc string) error {
	if err := checkHexDigest(subjectKey, "subject key"); err != nil {
		return err
	}
	return checkHexDigest(psc, "commitment")
}

func checkHexDigest(value, what string) error {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("nymauth: %s is not hex: %w", what, err)
	}
	if len(raw) != PSCCommitmentBytes {
		return fmt.Errorf("nymauth: %s is %d bytes, not %d", what, len(raw), PSCCommitmentBytes)
	}
	return nil
}
