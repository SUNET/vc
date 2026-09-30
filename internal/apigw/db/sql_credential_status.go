package db

import (
	"context"
	"time"

	"github.com/SUNET/vc/pkg/sqlstore"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/codes"
)

// SQLCredentialStatusColl is the SQL-backed CredentialStatusStore.
type SQLCredentialStatusColl struct {
	Service *Service
	db      *sqlx.DB
	dialect sqlstore.Dialect
}

// NewSQLCredentialStatusColl creates a SQL-backed CredentialStatusStore.
func NewSQLCredentialStatusColl(service *Service, db *sqlx.DB, dialect sqlstore.Dialect) *SQLCredentialStatusColl {
	return &SQLCredentialStatusColl{Service: service, db: db, dialect: dialect}
}

type credentialStatusRow struct {
	StatusListURI   string    `db:"status_list_uri"`
	Index           int64     `db:"idx"`
	Identifier      string    `db:"identifier"`
	Section         int64     `db:"section"`
	Backend         string    `db:"backend"`
	AuthenticSource string    `db:"authentic_source"`
	Scope           string    `db:"scope"`
	IssuedAt        time.Time `db:"issued_at"`
}

// Save records one allocated status-list entry, upserting on
// (status_list_uri, idx, backend) - what identifies an entry. See the
// 000010 migration for why the key is neither (section, idx) nor
// (status_list_uri, idx).
func (c *SQLCredentialStatusColl) Save(ctx context.Context, entry *CredentialStatusEntry) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:credential_status:save")
	defer span.End()

	if entry.IssuedAt.IsZero() {
		entry.IssuedAt = time.Now().UTC()
	}

	updateCols := []string{"identifier", "section", "authentic_source", "scope", "issued_at"}
	query := c.dialect.Rebind(`INSERT INTO credential_status_entries
		(status_list_uri, idx, identifier, section, backend, authentic_source, scope, issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ` +
		c.dialect.UpsertClause([]string{"status_list_uri", "idx", "backend"}, updateCols))

	if _, err := c.db.ExecContext(ctx, query,
		entry.StatusListURI, entry.Index, entry.Identifier,
		entry.Section, entry.Backend, entry.AuthenticSource, entry.Scope, entry.IssuedAt,
	); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// SearchByIdentifier returns every status entry recorded for a subject.
func (c *SQLCredentialStatusColl) SearchByIdentifier(ctx context.Context, identifier string) ([]*CredentialStatusEntry, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:credential_status:search")
	defer span.End()

	query := c.dialect.Rebind(`SELECT status_list_uri, idx, identifier, section, backend, authentic_source, scope, issued_at
		FROM credential_status_entries WHERE identifier = ?`)

	rows := []credentialStatusRow{}
	if err := c.db.SelectContext(ctx, &rows, query, identifier); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	entries := make([]*CredentialStatusEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, &CredentialStatusEntry{
			StatusListURI:   r.StatusListURI,
			Index:           r.Index,
			Identifier:      r.Identifier,
			Section:         r.Section,
			Backend:         r.Backend,
			AuthenticSource: r.AuthenticSource,
			Scope:           r.Scope,
			IssuedAt:        r.IssuedAt,
		})
	}
	return entries, nil
}
