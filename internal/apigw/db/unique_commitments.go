package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	// commitment returns the stored commitment of key, or ErrNoDocuments.
	commitment(ctx context.Context, key storedKey) (string, error)
	insertReset(ctx context.Context, row uniqueCommitmentResetRow) error
	// resetPrevious returns the previous commitment hash the reset with
	// evidenceRef recorded for key.
	resetPrevious(ctx context.Context, key storedKey, evidenceRef string) (string, error)
	// deleteCommitment removes the row of key that holds commitment.
	deleteCommitment(ctx context.Context, key storedKey, commitment string) error
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
	Scope      string    `bson:"scope"`
	Path       string    `bson:"path"`
	KeyHash    string    `bson:"key_hash"`
	Commitment string    `bson:"commitment"`
	AcceptedAt time.Time `bson:"accepted_at"`
}

type uniqueCommitmentResetRow struct {
	Scope       string `bson:"scope"`
	Path        string `bson:"path"`
	KeyHash     string `bson:"key_hash"`
	EvidenceRef string `bson:"evidence_ref"`
	// PreviousSHA256 is the base64url SHA-256 of the removed commitment:
	// the row shows that a reset happened, and holds no key to the earlier
	// pseudonyms.
	PreviousSHA256 string    `bson:"previous_commitment_sha256"`
	ApprovedBy     string    `bson:"approved_by"`
	ApprovedAt     time.Time `bson:"approved_at"`
}

// Accept implements UniqueCommitmentStore.
func (h *UniqueCommitments) Accept(ctx context.Context, key UniqueCommitmentKey, commitment []byte, at time.Time) ([]byte, error) {
	ctx, span := h.Service.tracer.Start(ctx, "db:vc:unique_commitment:accept")
	defer span.End()

	stored, err := h.accept(ctx, key, commitment, at)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
	return stored, err
}

func (h *UniqueCommitments) accept(ctx context.Context, key UniqueCommitmentKey, commitment []byte, at time.Time) ([]byte, error) {
	k, err := storedKeyOf(key)
	if err != nil {
		return nil, err
	}
	row := uniqueCommitmentRow{Scope: k.Scope, Path: k.Path, KeyHash: k.KeyHash,
		Commitment: base64.RawURLEncoding.EncodeToString(commitment), AcceptedAt: at.UTC()}
	if err := h.backend.insertCommitment(ctx, row); err != nil {
		return nil, err
	}
	stored, err := h.backend.commitment(ctx, k)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(stored)
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

// reset records the approval before it removes the commitment. A retry
// with the same evidence reference completes a reset interrupted between
// the two, and is refused once the key holds another commitment.
func (h *UniqueCommitments) reset(ctx context.Context, key UniqueCommitmentKey, approval UniqueCommitmentReset) error {
	k, err := storedKeyOf(key)
	if err != nil {
		return err
	}
	stored, err := h.backend.commitment(ctx, k)
	if err != nil {
		return err
	}
	previous, err := sha256Of(stored)
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
	return h.backend.deleteCommitment(ctx, k, stored)
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
