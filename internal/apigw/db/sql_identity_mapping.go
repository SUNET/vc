package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/codes"
)

// SQLIdentityMappingsColl is a SQL-backed implementation of IdentityMappingStore.
type SQLIdentityMappingsColl struct {
	Service *Service
	db      *sqlx.DB
	dialect sqlstore.Dialect
}

// NewSQLIdentityMappingsColl creates a SQL-backed IdentityMappingStore.
func NewSQLIdentityMappingsColl(service *Service, db *sqlx.DB, dialect sqlstore.Dialect) *SQLIdentityMappingsColl {
	return &SQLIdentityMappingsColl{Service: service, db: db, dialect: dialect}
}

type identityMappingRow struct {
	AuthenticSource         string                           `db:"authentic_source"`
	AuthenticSourcePersonID string                           `db:"authentic_source_person_id"`
	Attributes              sqlstore.JSON[map[string]string] `db:"attributes"`
	CreatedAt               time.Time                        `db:"created_at"`
}

func (row identityMappingRow) toModel() *model.IdentityMapping {
	return &model.IdentityMapping{
		AuthenticSource:         row.AuthenticSource,
		AuthenticSourcePersonID: row.AuthenticSourcePersonID,
		Attributes:              row.Attributes.V,
		CreatedAt:               row.CreatedAt,
	}
}

// Count returns the (possibly approximate) number of identity mappings.
func (c *SQLIdentityMappingsColl) Count(ctx context.Context) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:identities:count")
	defer span.End()

	var count int64
	if err := c.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM identity_mappings"); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}
	return count, nil
}

// CreateMapping creates a new identity mapping.
func (c *SQLIdentityMappingsColl) CreateMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:identities:createMapping")
	defer span.End()

	mapping.CreatedAt = time.Now().UTC()

	query := c.dialect.Rebind(`INSERT INTO identity_mappings
		(authentic_source, authentic_source_person_id, attributes, created_at) VALUES (?, ?, ?, ?)`)
	_, err := c.db.ExecContext(ctx, query,
		mapping.AuthenticSource, mapping.AuthenticSourcePersonID,
		sqlstore.JSON[map[string]string]{V: mapping.Attributes}, mapping.CreatedAt,
	)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// CreateMappings creates multiple identity mappings in a single statement.
func (c *SQLIdentityMappingsColl) CreateMappings(ctx context.Context, mappings []*model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:identities:createMappings")
	defer span.End()

	if len(mappings) == 0 {
		return nil
	}

	now := time.Now().UTC()
	placeholders := make([]string, 0, len(mappings))
	args := make([]any, 0, len(mappings)*4)
	for _, m := range mappings {
		m.CreatedAt = now
		placeholders = append(placeholders, "(?, ?, ?, ?)")
		args = append(args, m.AuthenticSource, m.AuthenticSourcePersonID,
			sqlstore.JSON[map[string]string]{V: m.Attributes}, m.CreatedAt)
	}

	query := c.dialect.Rebind(fmt.Sprintf(
		`INSERT INTO identity_mappings (authentic_source, authentic_source_person_id, attributes, created_at) VALUES %s`,
		strings.Join(placeholders, ", "),
	))
	if _, err := c.db.ExecContext(ctx, query, args...); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// EnsureMapping creates an identity mapping only if it does not already exist.
// If a record with the same (authentic_source, authentic_source_person_id) already exists, it is left unchanged.
func (c *SQLIdentityMappingsColl) EnsureMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:identities:ensureMapping")
	defer span.End()

	query := c.dialect.Rebind(fmt.Sprintf(
		`INSERT INTO identity_mappings (authentic_source, authentic_source_person_id, attributes, created_at)
		VALUES (?, ?, ?, ?) %s`,
		c.dialect.UpsertClause([]string{"authentic_source", "authentic_source_person_id"}, nil),
	))
	_, err := c.db.ExecContext(ctx, query,
		mapping.AuthenticSource, mapping.AuthenticSourcePersonID,
		sqlstore.JSON[map[string]string]{V: mapping.Attributes}, time.Now().UTC(),
	)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// ResolveMapping resolves identity attributes to an authentic_source_person_id.
func (c *SQLIdentityMappingsColl) ResolveMapping(ctx context.Context, query *ResolveMappingQuery) (string, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:identities:resolveMapping")
	defer span.End()

	if query.AuthenticSource == "" && len(query.Attributes) == 0 {
		span.SetStatus(codes.Error, helpers.ErrNoIdentityFound.Error())
		return "", helpers.ErrNoIdentityFound
	}

	conditions := []string{}
	args := []any{}
	if query.AuthenticSource != "" {
		conditions = append(conditions, "authentic_source = ?")
		args = append(args, query.AuthenticSource)
	}
	if len(query.Attributes) > 0 {
		conditions = append(conditions, c.dialect.JSONContains("attributes"))
		args = append(args, sqlstore.JSON[map[string]string]{V: query.Attributes})
	}

	sqlQuery := c.dialect.Rebind(fmt.Sprintf(
		`SELECT authentic_source_person_id FROM identity_mappings WHERE %s LIMIT 1`,
		strings.Join(conditions, " AND "),
	))

	var personID string
	if err := c.db.GetContext(ctx, &personID, sqlQuery, args...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			span.SetStatus(codes.Error, helpers.ErrNoIdentityFound.Error())
			return "", helpers.ErrNoIdentityFound
		}
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	return personID, nil
}

// UpdateMapping updates the attributes of an existing identity mapping.
func (c *SQLIdentityMappingsColl) UpdateMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:identities:updateMapping")
	defer span.End()

	query := c.dialect.Rebind(`UPDATE identity_mappings SET attributes = ?
		WHERE authentic_source = ? AND authentic_source_person_id = ?`)
	result, err := c.db.ExecContext(ctx, query,
		sqlstore.JSON[map[string]string]{V: mapping.Attributes},
		mapping.AuthenticSource, mapping.AuthenticSourcePersonID,
	)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if n == 0 {
		return helpers.ErrNoIdentityFound
	}
	return nil
}

// DeleteMapping deletes an identity mapping.
func (c *SQLIdentityMappingsColl) DeleteMapping(ctx context.Context, query *DeleteMappingQuery) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:identities:deleteMapping")
	defer span.End()

	sqlQuery := c.dialect.Rebind(`DELETE FROM identity_mappings
		WHERE authentic_source = ? AND authentic_source_person_id = ?`)
	result, err := c.db.ExecContext(ctx, sqlQuery, query.AuthenticSource, query.AuthenticSourcePersonID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if n == 0 {
		return helpers.ErrNoIdentityFound
	}
	return nil
}

// escapeLike escapes LIKE/ILIKE wildcard characters in a user-supplied search term.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// SearchMappings returns identity mappings matching a text search or filters, with a limit.
func (c *SQLIdentityMappingsColl) SearchMappings(ctx context.Context, query *SearchMappingsQuery) ([]*model.IdentityMapping, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:identities:searchMappings")
	defer span.End()

	conditions := []string{}
	args := []any{}

	if query.AuthenticSource != "" {
		if len(query.AllowedAuthenticSources) > 0 && !slices.Contains(query.AllowedAuthenticSources, query.AuthenticSource) {
			return []*model.IdentityMapping{}, nil
		}
		conditions = append(conditions, "authentic_source = ?")
		args = append(args, query.AuthenticSource)
	} else if len(query.AllowedAuthenticSources) > 0 {
		placeholders := make([]string, len(query.AllowedAuthenticSources))
		for i, src := range query.AllowedAuthenticSources {
			placeholders[i] = "?"
			args = append(args, src)
		}
		conditions = append(conditions, fmt.Sprintf("authentic_source IN (%s)", strings.Join(placeholders, ", ")))
	}

	if query.Search != "" {
		term := "%" + escapeLike(query.Search) + "%"
		searchCols := []string{
			"authentic_source_person_id",
			"authentic_source",
			c.dialect.JSONTextExtract("attributes", "family_name"),
			c.dialect.JSONTextExtract("attributes", "given_name"),
			c.dialect.JSONTextExtract("attributes", "birth_date"),
		}
		orClauses := make([]string, len(searchCols))
		for i, col := range searchCols {
			orClauses[i] = c.dialect.CaseInsensitiveLike(col)
			args = append(args, term)
		}
		conditions = append(conditions, "("+strings.Join(orClauses, " OR ")+")")
	}

	limit := int64(50)
	if query.Limit > 0 && query.Limit <= 200 {
		limit = query.Limit
	}

	whereClause := "1=1"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " AND ")
	}
	sqlQuery := c.dialect.Rebind(fmt.Sprintf(
		`SELECT authentic_source, authentic_source_person_id, attributes, created_at
		 FROM identity_mappings WHERE %s ORDER BY created_at DESC LIMIT ?`,
		whereClause,
	))
	args = append(args, limit)

	var rows []identityMappingRow
	if err := c.db.SelectContext(ctx, &rows, sqlQuery, args...); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	res := make([]*model.IdentityMapping, len(rows))
	for i, row := range rows {
		res[i] = row.toModel()
	}
	return res, nil
}
