package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/sqlstore"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/codes"
)

// SQLNymAuthPSCColl is the SQL-backed NymAuthPSCStore.
type SQLNymAuthPSCColl struct {
	Service *Service
	db      *sqlx.DB
	dialect sqlstore.Dialect
}

// NewSQLNymAuthPSCColl creates a SQL-backed NymAuthPSCStore.
func NewSQLNymAuthPSCColl(service *Service, db *sqlx.DB, dialect sqlstore.Dialect) *SQLNymAuthPSCColl {
	return &SQLNymAuthPSCColl{Service: service, db: db, dialect: dialect}
}

type nymAuthPSCRow struct {
	SubjectKey string    `db:"subject_key"`
	PSC        string    `db:"psc"`
	AcceptedAt time.Time `db:"accepted_at"`
}

type nymAuthPSCResetRow struct {
	SubjectKey  string    `db:"subject_key"`
	EvidenceRef string    `db:"evidence_ref"`
	ResetOf     string    `db:"reset_of"`
	ApprovedBy  string    `db:"approved_by"`
	ApprovedAt  time.Time `db:"approved_at"`
}

// Accept inserts the commitment if the subject has none, then reads
// back what is actually stored and compares.
//
// Insert-if-absent and then read, rather than read and then insert,
// because two requests for one subject can race: the primary key means
// exactly one insert wins, and the read tells the loser whether it lost
// to its own value (fine - a retry or a batch) or to a different one (a
// conflict). Checking first and inserting second would let both see an
// empty table and both believe they had recorded theirs.
func (c *SQLNymAuthPSCColl) Accept(ctx context.Context, subjectKey, psc string, now time.Time) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:nymauth_psc:accept")
	defer span.End()

	if err := checkPSCArgs(subjectKey, psc); err != nil {
		return err
	}

	query := c.dialect.Rebind(`INSERT INTO nymauth_psc (subject_key, psc, accepted_at)
		VALUES (?, ?, ?) ` + c.dialect.UpsertClause([]string{"subject_key"}, nil))
	if _, err := c.db.ExecContext(ctx, query, subjectKey, psc, now.UTC()); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	stored, err := c.Get(ctx, subjectKey)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if stored == nil {
		// The insert reported no error and the row is not there, which
		// is not a state this schema can reach. Refuse rather than
		// report success: a caller told "recorded" would go on to issue.
		return errors.New("nymauth: the commitment was neither stored nor rejected")
	}
	if stored.PSC != psc {
		return ErrPSCConflict
	}
	return nil
}

// Get returns the subject's record, or nil.
func (c *SQLNymAuthPSCColl) Get(ctx context.Context, subjectKey string) (*NymAuthPSCRecord, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:nymauth_psc:get")
	defer span.End()

	var row nymAuthPSCRow
	query := c.dialect.Rebind(`SELECT subject_key, psc, accepted_at FROM nymauth_psc WHERE subject_key = ?`)
	if err := c.db.GetContext(ctx, &row, query, subjectKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return &NymAuthPSCRecord{SubjectKey: row.SubjectKey, PSC: row.PSC, AcceptedAt: row.AcceptedAt}, nil
}

// Reset writes the audit row and removes the record, in one
// transaction.
//
// One transaction because the two halves are one act: a trail row with
// the record still present would say a reset happened that did not, and
// a removed record with no trail row would be a reset nobody approved.
func (c *SQLNymAuthPSCColl) Reset(ctx context.Context, subjectKey, approvedBy, evidenceRef string, now time.Time) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:nymauth_psc:reset")
	defer span.End()

	if err := checkHexDigest(subjectKey, "subject key"); err != nil {
		return err
	}
	if approvedBy == "" || evidenceRef == "" {
		return errors.New("nymauth: a reset needs an approving operator and an evidence reference")
	}

	tx, err := c.db.BeginTxx(ctx, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Already used? Then this is a retry of a reset that happened, and
	// the answer is the same as the first time. Checked BEFORE the
	// record, because by now the subject may legitimately have
	// re-established one - and discarding that would be the replay this
	// guard exists to stop.
	var seen int
	query := c.dialect.Rebind(`SELECT COUNT(*) FROM nymauth_psc_resets WHERE subject_key = ? AND evidence_ref = ?`)
	if err := tx.GetContext(ctx, &seen, query, subjectKey, evidenceRef); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if seen > 0 {
		return nil
	}

	// FOR UPDATE: the row is read, audited and deleted across three
	// statements, and READ COMMITTED - the default in both backends -
	// gives each statement a fresh snapshot. Without the lock, two
	// resets can both read commitment A; the first commits, the wallet
	// legitimately records commitment B, and the second then deletes B
	// while its audit row says it reset A. A destroyed record and an
	// untrue trail, from an operator action that is supposed to be the
	// careful one.
	var row nymAuthPSCRow
	query = c.dialect.Rebind(`SELECT subject_key, psc, accepted_at FROM nymauth_psc WHERE subject_key = ? FOR UPDATE`)
	if err := tx.GetContext(ctx, &row, query, subjectKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPSCNoRecord
		}
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	query = c.dialect.Rebind(`INSERT INTO nymauth_psc_resets
		(subject_key, evidence_ref, reset_of, approved_by, approved_at) VALUES (?, ?, ?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, query, subjectKey, evidenceRef, ResetOf(row.PSC), approvedBy, now.UTC()); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// Conditional on the value that was audited, so that even if the
	// lock above were ever lost this cannot delete a commitment the
	// trail does not describe. Belt and braces on purpose: the whole
	// store exists to keep one invariant, and the cheapest place to
	// keep it is in the predicate.
	query = c.dialect.Rebind(`DELETE FROM nymauth_psc WHERE subject_key = ? AND psc = ?`)
	result, err := tx.ExecContext(ctx, query, subjectKey, row.PSC)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if affected == 0 {
		// The commitment changed under us. Roll back rather than
		// commit an audit row for a reset that did not remove what it
		// names.
		return fmt.Errorf("nymauth: the commitment changed while the reset was in progress; nothing was reset")
	}
	return tx.Commit()
}

// Resets returns the subject's audit trail, oldest first.
func (c *SQLNymAuthPSCColl) Resets(ctx context.Context, subjectKey string) ([]NymAuthPSCReset, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:nymauth_psc:resets")
	defer span.End()

	var rows []nymAuthPSCResetRow
	query := c.dialect.Rebind(`SELECT subject_key, evidence_ref, reset_of, approved_by, approved_at
		FROM nymauth_psc_resets WHERE subject_key = ? ORDER BY approved_at ASC, evidence_ref ASC`)
	if err := c.db.SelectContext(ctx, &rows, query, subjectKey); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	out := make([]NymAuthPSCReset, 0, len(rows))
	for _, r := range rows {
		out = append(out, NymAuthPSCReset{
			SubjectKey:  r.SubjectKey,
			EvidenceRef: r.EvidenceRef,
			ResetOf:     r.ResetOf,
			ApprovedBy:  r.ApprovedBy,
			ApprovedAt:  r.ApprovedAt,
		})
	}
	return out, nil
}

// Erase removes the record and its audit rows together.
func (c *SQLNymAuthPSCColl) Erase(ctx context.Context, subjectKey string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:nymauth_psc:erase")
	defer span.End()

	tx, err := c.db.BeginTxx(ctx, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// The RECORD first, and under the same lock a reset takes, so a
	// reset cannot be mid-flight while this runs. Deleting the trail
	// first left a window in which a concurrent reset inserted its row
	// afterwards and erasure returned success with that row retained -
	// a retained identifier for a subject who asked to be forgotten.
	var row nymAuthPSCRow
	query := c.dialect.Rebind(`SELECT subject_key, psc, accepted_at FROM nymauth_psc WHERE subject_key = ? FOR UPDATE`)
	if err := tx.GetContext(ctx, &row, query, subjectKey); err != nil && !errors.Is(err, sql.ErrNoRows) {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	for _, stmt := range []string{
		`DELETE FROM nymauth_psc WHERE subject_key = ?`,
		`DELETE FROM nymauth_psc_resets WHERE subject_key = ?`,
	} {
		if _, err := tx.ExecContext(ctx, c.dialect.Rebind(stmt), subjectKey); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return err
		}
	}
	return tx.Commit()
}
