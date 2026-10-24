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
	query := s.dialect.Rebind(`INSERT INTO unique_commitments (scope, path, key_hash, commitment, accepted_at) VALUES (?, ?, ?, ?, ?) ` +
		s.dialect.UpsertClause([]string{"scope", "path", "key_hash"}, nil))
	_, err := s.db.ExecContext(ctx, query, row.Scope, row.Path, row.KeyHash, row.Commitment, row.AcceptedAt)
	return err
}

func (s *sqlUniqueCommitments) record(ctx context.Context, key storedKey) (uniqueCommitmentRow, error) {
	var row uniqueCommitmentRow
	query := s.dialect.Rebind(`SELECT scope, path, key_hash, commitment, accepted_at FROM unique_commitments WHERE scope = ? AND path = ? AND key_hash = ?`)
	if err := s.db.GetContext(ctx, &row, query, key.Scope, key.Path, key.KeyHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return row, ErrNoDocuments
		}
		return row, err
	}
	return row, nil
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

func (s *sqlUniqueCommitments) deleteCommitment(ctx context.Context, key storedKey, commitment string) error {
	query := s.dialect.Rebind(`DELETE FROM unique_commitments WHERE scope = ? AND path = ? AND key_hash = ? AND commitment = ?`)
	_, err := s.db.ExecContext(ctx, query, key.Scope, key.Path, key.KeyHash, commitment)
	return err
}
