package db

import (
	"context"
	"database/sql"
	"errors"

	"github.com/SUNET/vc/pkg/sqlstore"

	"github.com/jmoiron/sqlx"
)

// sqlUniqueCommitments is the SQL backend of UniqueCommitments.
type sqlUniqueCommitments struct {
	db      *sqlx.DB
	dialect sqlstore.Dialect
}

// NewSQLUniqueCommitmentColl creates the SQL-backed UniqueCommitments.
func NewSQLUniqueCommitmentColl(service *Service, db *sqlx.DB, dialect sqlstore.Dialect) *UniqueCommitments {
	return &UniqueCommitments{Service: service, backend: &sqlUniqueCommitments{db: db, dialect: dialect}}
}

func (s *sqlUniqueCommitments) insertCommitment(ctx context.Context, row uniqueCommitmentRow) error {
	query := s.dialect.Rebind(`INSERT INTO unique_commitments (scope, path, key_hash, commitment, accepted_at, releasable_by) VALUES (?, ?, ?, ?, ?, ?) ` +
		s.dialect.UpsertClause([]string{"scope", "path", "key_hash"}, nil))
	_, err := s.db.ExecContext(ctx, query, row.Scope, row.Path, row.KeyHash, row.Commitment, row.AcceptedAt, row.ReleasableBy)
	return err
}

func (s *sqlUniqueCommitments) record(ctx context.Context, key storedKey) (uniqueCommitmentRow, error) {
	var row uniqueCommitmentRow
	query := s.dialect.Rebind(`SELECT scope, path, key_hash, commitment, accepted_at, releasable_by FROM unique_commitments WHERE scope = ? AND path = ? AND key_hash = ?`)
	if err := s.db.GetContext(ctx, &row, query, key.Scope, key.Path, key.KeyHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return row, ErrNoDocuments
		}
		return row, err
	}
	return row, nil
}

func (s *sqlUniqueCommitments) keepCommitment(ctx context.Context, key storedKey, commitment string) error {
	query := s.dialect.Rebind(`UPDATE unique_commitments SET releasable_by = '' WHERE scope = ? AND path = ? AND key_hash = ? AND commitment = ?`)
	_, err := s.db.ExecContext(ctx, query, key.Scope, key.Path, key.KeyHash, commitment)
	return err
}

func (s *sqlUniqueCommitments) takeOverCommitment(ctx context.Context, key storedKey, commitment, call string) error {
	query := s.dialect.Rebind(`UPDATE unique_commitments SET releasable_by = ? WHERE scope = ? AND path = ? AND key_hash = ? AND commitment = ? AND releasable_by <> ''`)
	_, err := s.db.ExecContext(ctx, query, call, key.Scope, key.Path, key.KeyHash, commitment)
	return err
}

func (s *sqlUniqueCommitments) releaseCommitment(ctx context.Context, key storedKey, call string) error {
	query := s.dialect.Rebind(`DELETE FROM unique_commitments WHERE scope = ? AND path = ? AND key_hash = ? AND releasable_by = ?`)
	_, err := s.db.ExecContext(ctx, query, key.Scope, key.Path, key.KeyHash, call)
	return err
}

func (s *sqlUniqueCommitments) insertReset(ctx context.Context, row uniqueCommitmentResetRow) error {
	query := s.dialect.Rebind(`INSERT INTO unique_commitment_resets (scope, path, key_hash, evidence_ref, previous_commitment_sha256, approved_by, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?) ` +
		s.dialect.UpsertClause([]string{"scope", "path", "key_hash", "evidence_ref"}, nil))
	_, err := s.db.ExecContext(ctx, query, row.Scope, row.Path, row.KeyHash, row.EvidenceRef, row.PreviousSHA256, row.ApprovedBy, row.ApprovedAt)
	return err
}

func (s *sqlUniqueCommitments) resetPrevious(ctx context.Context, key storedKey, evidenceRef string) (string, error) {
	var previous string
	query := s.dialect.Rebind(`SELECT previous_commitment_sha256 FROM unique_commitment_resets WHERE scope = ? AND path = ? AND key_hash = ? AND evidence_ref = ?`)
	err := s.db.GetContext(ctx, &previous, query, key.Scope, key.Path, key.KeyHash, evidenceRef)
	return previous, err
}

func (s *sqlUniqueCommitments) deleteCommitment(ctx context.Context, key storedKey, commitment string) (bool, error) {
	query := s.dialect.Rebind(`DELETE FROM unique_commitments WHERE scope = ? AND path = ? AND key_hash = ? AND commitment = ?`)
	n, err := affectedRows(s.db.ExecContext(ctx, query, key.Scope, key.Path, key.KeyHash, commitment))
	return n > 0, err
}

// affectedRows returns the rows a statement changed.
func affectedRows(result sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
