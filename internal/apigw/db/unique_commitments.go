package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/codes"
)

// UniqueCommitments is the UniqueCommitmentStore. Its protocol is the same
// on every backend, which provides the row operations.
type UniqueCommitments struct {
	Service *Service
	backend uniqueCommitmentBackend
}

// uniqueCommitmentBackend stores the commitment and reset rows. An insert
// leaves a row already stored under the same key in place.
type uniqueCommitmentBackend interface {
	insertCommitment(ctx context.Context, row uniqueCommitmentRow) error
	// record returns the row of key, or ErrNoDocuments.
	record(ctx context.Context, key storedKey) (uniqueCommitmentRow, error)
	// keepCommitments empties, in one statement, the releasable_by of each
	// row a key of rows holds with that row's commitment. rows is not empty.
	keepCommitments(ctx context.Context, rows []uniqueCommitmentRow) error
	// releaseCommitment removes the row of key whose releasable_by is call,
	// if there is one.
	releaseCommitment(ctx context.Context, key storedKey, call string) error
	insertReset(ctx context.Context, row uniqueCommitmentResetRow) error
	// resetPrevious returns the previous commitment hash the reset with
	// evidenceRef recorded for key.
	resetPrevious(ctx context.Context, key storedKey, evidenceRef string) (string, error)
	// deleteCommitment removes the row of key that holds commitment, and
	// reports whether there was one.
	deleteCommitment(ctx context.Context, key storedKey, commitment string) (bool, error)
}

// storedKey is a UniqueCommitmentKey as the rows store it: the path
// JSON-encoded and the key hash base64url.
type storedKey struct {
	Scope   string `bson:"scope"`
	Path    string `bson:"path"`
	KeyHash string `bson:"key_hash"`
}

func storedKeyOf(key UniqueCommitmentKey) (storedKey, error) {
	path, err := json.Marshal(key.Path)
	if err != nil {
		return storedKey{}, err
	}
	return storedKey{Scope: key.Scope, Path: string(path), KeyHash: base64.RawURLEncoding.EncodeToString(key.KeyHash)}, nil
}

type uniqueCommitmentRow struct {
	Scope      string    `bson:"scope" db:"scope"`
	Path       string    `bson:"path" db:"path"`
	KeyHash    string    `bson:"key_hash" db:"key_hash"`
	Commitment string    `bson:"commitment" db:"commitment"`
	AcceptedAt time.Time `bson:"accepted_at" db:"accepted_at"`
	// ReleasableBy names the unfinished Accept call that stored the row, which
	// removes the row when it fails. It is empty once an Accept succeeded: the
	// row then stays until a reset.
	ReleasableBy string `bson:"releasable_by" db:"releasable_by"`
}

// key is the key the row is stored under.
func (r uniqueCommitmentRow) key() storedKey {
	return storedKey{Scope: r.Scope, Path: r.Path, KeyHash: r.KeyHash}
}

type uniqueCommitmentResetRow struct {
	Scope       string `bson:"scope"`
	Path        string `bson:"path"`
	KeyHash     string `bson:"key_hash"`
	EvidenceRef string `bson:"evidence_ref"`
	// PreviousSHA256 is the base64url SHA-256 of the removed commitment:
	// the row shows that a reset happened, and holds no copy of the
	// commitment.
	PreviousSHA256 string    `bson:"previous_commitment_sha256"`
	ApprovedBy     string    `bson:"approved_by"`
	ApprovedAt     time.Time `bson:"approved_at"`
}

// Accept implements UniqueCommitmentStore.
func (h *UniqueCommitments) Accept(ctx context.Context, commitments []UniqueCommitment, at time.Time) error {
	ctx, span := h.Service.tracer.Start(ctx, "db:vc:unique_commitment:accept")
	defer span.End()

	err := h.accept(ctx, commitments, at)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
	return err
}

// acceptRounds bounds the rounds of acceptRow and of keep. Each concurrent
// removal of a row takes one more.
const acceptRounds = 4

// errAcceptRounds is returned when concurrent removals of a row left every
// round undecided.
var errAcceptRounds = errors.New("the commitment on record changed during every round of the accept")

// accept stores the commitments as releasable by a random call name, and
// keeps them all once it has accepted them, so a row outlasts its accepts
// only when one of them succeeds. On a failure it removes the rows that name
// may still remove.
func (h *UniqueCommitments) accept(ctx context.Context, commitments []UniqueCommitment, at time.Time) error {
	if len(commitments) == 0 {
		return nil
	}
	call := rand.Text()
	rows := make([]uniqueCommitmentRow, 0, len(commitments))
	for _, c := range commitments {
		k, err := storedKeyOf(c.Key)
		if err != nil {
			return err
		}
		rows = append(rows, uniqueCommitmentRow{Scope: k.Scope, Path: k.Path, KeyHash: k.KeyHash,
			Commitment: base64.RawURLEncoding.EncodeToString(c.Commitment), AcceptedAt: at.UTC(), ReleasableBy: call})
	}
	for i, row := range rows {
		if err := h.acceptRow(ctx, row, i); err != nil {
			return h.refuse(ctx, rows[:i+1], call, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return h.refuse(ctx, rows, call, err)
	}
	// The keep decides the batch, so a cancelled request cannot stop it.
	if err := h.keep(context.WithoutCancel(ctx), rows); err != nil {
		return h.refuse(ctx, rows, call, err)
	}
	return nil
}

// refuse removes what a refused accept may still remove, and returns why it
// was refused. A failed removal is the error returned, so the caller cannot
// take it for a conflict.
func (h *UniqueCommitments) refuse(ctx context.Context, rows []uniqueCommitmentRow, call string, reason error) error {
	if released := h.release(ctx, rows, call); released != nil {
		return fmt.Errorf("%w, after: %v", released, reason)
	}
	return reason
}

// acceptRow stores row when its key holds no row, and accepts a row that
// holds the same commitment, whichever call stored it.
func (h *UniqueCommitments) acceptRow(ctx context.Context, row uniqueCommitmentRow, index int) error {
	for range acceptRounds {
		if err := h.backend.insertCommitment(ctx, row); err != nil {
			return err
		}
		stored, err := h.backend.record(ctx, row.key())
		switch {
		case errors.Is(err, ErrNoDocuments):
			// A reset, or the release of the call that stored the row,
			// removed it after the insert.
			continue
		case err != nil:
			return err
		case stored.Commitment != row.Commitment:
			return &UniqueCommitmentConflict{Index: index}
		}
		return nil
	}
	return errAcceptRounds
}

// keep makes the accepted rows stay, and returns once every row is kept. A
// row that a failed call's release or a reset removed before the keep is
// stored again. A different commitment in its place refuses the call, and the
// rows already kept stay until a reset.
func (h *UniqueCommitments) keep(ctx context.Context, rows []uniqueCommitmentRow) error {
	for range acceptRounds {
		if err := h.backend.keepCommitments(ctx, rows); err != nil {
			return err
		}
		kept, err := h.allKept(ctx, rows)
		if err != nil || kept {
			return err
		}
	}
	return errAcceptRounds
}

// allKept reports whether each key holds its row with an empty releasable_by.
// It stores again a row that was removed.
func (h *UniqueCommitments) allKept(ctx context.Context, rows []uniqueCommitmentRow) (bool, error) {
	kept := true
	for i, row := range rows {
		stored, err := h.backend.record(ctx, row.key())
		switch {
		case errors.Is(err, ErrNoDocuments):
			if err := h.acceptRow(ctx, row, i); err != nil {
				return false, err
			}
			kept = false
		case err != nil:
			return false, err
		case stored.Commitment != row.Commitment:
			return false, &UniqueCommitmentConflict{Index: i}
		case stored.ReleasableBy != "":
			kept = false
		}
	}
	return kept, nil
}

// release removes the rows of rows' keys that call stored and may still
// remove. It runs when ctx is cancelled as well: a cancelled request is
// refused too.
func (h *UniqueCommitments) release(ctx context.Context, rows []uniqueCommitmentRow, call string) error {
	ctx = context.WithoutCancel(ctx)
	for _, row := range rows {
		if err := h.backend.releaseCommitment(ctx, row.key(), call); err != nil {
			return fmt.Errorf("removing the commitments of a refused accept: %w", err)
		}
	}
	return nil
}

// Find implements UniqueCommitmentStore.
func (h *UniqueCommitments) Find(ctx context.Context, key UniqueCommitmentKey) (UniqueCommitmentRecord, error) {
	ctx, span := h.Service.tracer.Start(ctx, "db:vc:unique_commitment:find")
	defer span.End()

	k, err := storedKeyOf(key)
	if err != nil {
		return UniqueCommitmentRecord{}, err
	}
	row, err := h.backend.record(ctx, k)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return UniqueCommitmentRecord{}, err
	}
	return UniqueCommitmentRecord{AcceptedAt: row.AcceptedAt}, nil
}

// Reset implements UniqueCommitmentStore.
func (h *UniqueCommitments) Reset(ctx context.Context, key UniqueCommitmentKey, approval UniqueCommitmentReset) error {
	ctx, span := h.Service.tracer.Start(ctx, "db:vc:unique_commitment:reset")
	defer span.End()

	err := h.reset(ctx, key, approval)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
	return err
}

// reset records the approval before it removes the commitment, and the
// approval stays. A retry with the same evidence reference completes a reset
// interrupted between the two, and is refused once the key holds another
// commitment. When a concurrent reset removed the commitment first, reset
// returns ErrNoDocuments.
func (h *UniqueCommitments) reset(ctx context.Context, key UniqueCommitmentKey, approval UniqueCommitmentReset) error {
	k, err := storedKeyOf(key)
	if err != nil {
		return err
	}
	stored, err := h.backend.record(ctx, k)
	if err != nil {
		return err
	}
	previous, err := sha256Of(stored.Commitment)
	if err != nil {
		return err
	}
	row := uniqueCommitmentResetRow{Scope: k.Scope, Path: k.Path, KeyHash: k.KeyHash, EvidenceRef: approval.EvidenceRef,
		PreviousSHA256: previous, ApprovedBy: approval.ApprovedBy, ApprovedAt: approval.At.UTC()}
	if err := h.backend.insertReset(ctx, row); err != nil {
		return err
	}
	recorded, err := h.backend.resetPrevious(ctx, k, approval.EvidenceRef)
	if err != nil {
		return err
	}
	if recorded != previous {
		return ErrResetEvidenceUsed
	}
	removed, err := h.backend.deleteCommitment(ctx, k, stored.Commitment)
	if err != nil {
		return err
	}
	if !removed {
		return ErrNoDocuments
	}
	return nil
}

// sha256Of is the base64url SHA-256 of the commitment a stored base64url
// value holds.
func sha256Of(stored string) (string, error) {
	commitment, err := base64.RawURLEncoding.DecodeString(stored)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(commitment)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
