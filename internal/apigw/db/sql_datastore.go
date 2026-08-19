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

// SQLDatastoreColl is a SQL-backed implementation of DatastoreStore.
type SQLDatastoreColl struct {
	Service *Service
	db      *sqlx.DB
	dialect sqlstore.Dialect
}

// NewSQLDatastoreColl creates a SQL-backed DatastoreStore.
func NewSQLDatastoreColl(service *Service, db *sqlx.DB, dialect sqlstore.Dialect) *SQLDatastoreColl {
	return &SQLDatastoreColl{Service: service, db: db, dialect: dialect}
}

// sqlxExtQuerier is satisfied by both *sqlx.DB and *sqlx.Tx, so helper
// methods below work identically inside or outside a transaction.
type sqlxExtQuerier interface {
	SelectContext(ctx context.Context, dest any, query string, args ...any) error
	GetContext(ctx context.Context, dest any, query string, args ...any) error
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type datastoreRow struct {
	AuthenticSource        string                        `db:"authentic_source"`
	Scope                  string                        `db:"scope"`
	DocumentID             string                        `db:"document_id"`
	DocumentDataValidation sql.NullString                `db:"document_data_validation"`
	DocumentData           sqlstore.JSON[map[string]any] `db:"document_data"`
	ValidNotAfter          sql.NullTime                  `db:"valid_not_after"`
	CreatedAt              time.Time                     `db:"created_at"`
}

func (row datastoreRow) toMeta() *model.MetaData {
	meta := &model.MetaData{
		AuthenticSource:           row.AuthenticSource,
		Scope:                     row.Scope,
		DocumentID:                row.DocumentID,
		DocumentDataValidationRef: row.DocumentDataValidation.String,
		CreatedAt:                 row.CreatedAt,
	}
	if row.ValidNotAfter.Valid {
		t := row.ValidNotAfter.Time
		meta.ValidNotAfter = &t
	}
	return meta
}

type datastoreMetaRow struct {
	AuthenticSource        string         `db:"authentic_source"`
	Scope                  string         `db:"scope"`
	DocumentID             string         `db:"document_id"`
	DocumentDataValidation sql.NullString `db:"document_data_validation"`
	ValidNotAfter          sql.NullTime   `db:"valid_not_after"`
	CreatedAt              time.Time      `db:"created_at"`
}

func (row datastoreMetaRow) toMeta() *model.MetaData {
	meta := &model.MetaData{
		AuthenticSource:           row.AuthenticSource,
		Scope:                     row.Scope,
		DocumentID:                row.DocumentID,
		DocumentDataValidationRef: row.DocumentDataValidation.String,
		CreatedAt:                 row.CreatedAt,
	}
	if row.ValidNotAfter.Valid {
		t := row.ValidNotAfter.Time
		meta.ValidNotAfter = &t
	}
	return meta
}

// Count returns the (possibly approximate) number of documents in the datastore.
func (c *SQLDatastoreColl) Count(ctx context.Context) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:count")
	defer span.End()

	var count int64
	if err := c.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM datastore"); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}
	return count, nil
}

func (c *SQLDatastoreColl) insertDocument(ctx context.Context, q sqlxExtQuerier, doc *model.CompleteDocument) error {
	query := c.dialect.Rebind(`INSERT INTO datastore
		(authentic_source, scope, document_id, document_data_validation, document_data, valid_not_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)

	var validNotAfter sql.NullTime
	if doc.Meta.ValidNotAfter != nil {
		validNotAfter = sql.NullTime{Time: *doc.Meta.ValidNotAfter, Valid: true}
	}

	_, err := q.ExecContext(ctx, query,
		doc.Meta.AuthenticSource, doc.Meta.Scope, doc.Meta.DocumentID,
		doc.Meta.DocumentDataValidationRef, sqlstore.JSON[map[string]any]{V: doc.DocumentData},
		validNotAfter, doc.Meta.CreatedAt,
	)
	return err
}

// identityMappingRowsValues builds the "(?, ?, ?, ?), (?, ?, ?, ?), ..."
// placeholder list and matching args for a multi-row insert into
// datastore_identity_mapping, one row per id in identityMappingIDs.
func identityMappingRowsValues(authenticSource, scope, documentID string, identityMappingIDs []string) (string, []any) {
	placeholders := make([]string, 0, len(identityMappingIDs))
	args := make([]any, 0, len(identityMappingIDs)*4)
	for _, id := range identityMappingIDs {
		placeholders = append(placeholders, "(?, ?, ?, ?)")
		args = append(args, authenticSource, scope, documentID, id)
	}
	return strings.Join(placeholders, ", "), args
}

func (c *SQLDatastoreColl) insertIdentityMappings(ctx context.Context, q sqlxExtQuerier, meta *model.MetaData, identityMappingIDs []string) error {
	if len(identityMappingIDs) == 0 {
		return nil
	}
	values, args := identityMappingRowsValues(meta.AuthenticSource, meta.Scope, meta.DocumentID, identityMappingIDs)
	query := c.dialect.Rebind(fmt.Sprintf(
		`INSERT INTO datastore_identity_mapping (authentic_source, scope, document_id, identity_mapping_id) VALUES %s`,
		values,
	))
	_, err := q.ExecContext(ctx, query, args...)
	return err
}

// Save saves one document to the generic collection.
func (c *SQLDatastoreColl) Save(ctx context.Context, doc *model.CompleteDocument) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:save")
	defer span.End()

	if err := helpers.Check(ctx, c.Service.cfg, doc, c.Service.log); err != nil {
		return err
	}
	doc.Meta.CreatedAt = time.Now().UTC()

	tx, err := c.db.BeginTxx(ctx, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := c.insertDocument(ctx, tx, doc); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if err := c.insertIdentityMappings(ctx, tx, doc.Meta, doc.IdentityMappingIDs); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if err := tx.Commit(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// SaveMany saves multiple documents to the generic collection.
func (c *SQLDatastoreColl) SaveMany(ctx context.Context, docs []*model.CompleteDocument) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:saveMany")
	defer span.End()

	now := time.Now().UTC()
	for _, doc := range docs {
		if err := helpers.Check(ctx, c.Service.cfg, doc, c.Service.log); err != nil {
			return err
		}
		doc.Meta.CreatedAt = now
	}

	tx, err := c.db.BeginTxx(ctx, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, doc := range docs {
		if err := c.insertDocument(ctx, tx, doc); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		if err := c.insertIdentityMappings(ctx, tx, doc.Meta, doc.IdentityMappingIDs); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

func (c *SQLDatastoreColl) documentExists(ctx context.Context, q sqlxExtQuerier, authenticSource, scope, documentID string) (bool, error) {
	query := c.dialect.Rebind(`SELECT 1 FROM datastore WHERE authentic_source = ? AND scope = ? AND document_id = ?`)
	var exists int
	err := q.GetContext(ctx, &exists, query, authenticSource, scope, documentID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// AddIdentity adds document identity.
func (c *SQLDatastoreColl) AddIdentity(ctx context.Context, query *AddIdentityQuery) error {
	ok, err := c.documentExists(ctx, c.db, query.AuthenticSource, query.Scope, query.DocumentID)
	if err != nil {
		return err
	}
	if !ok {
		return helpers.ErrNoDocumentFound
	}
	if len(query.IdentityMappingIDs) == 0 {
		return nil
	}

	// Single multi-row upsert (insert-if-absent per id, matching Mongo's
	// $addToSet semantics): one round-trip and one atomic statement, rather
	// than one INSERT per id, which was both N round-trips and non-atomic
	// (a failure partway through would leave a subset of ids inserted).
	values, args := identityMappingRowsValues(query.AuthenticSource, query.Scope, query.DocumentID, query.IdentityMappingIDs)
	q := c.dialect.Rebind(fmt.Sprintf(
		`INSERT INTO datastore_identity_mapping (authentic_source, scope, document_id, identity_mapping_id) VALUES %s %s`,
		values,
		c.dialect.UpsertClause([]string{"authentic_source", "scope", "document_id", "identity_mapping_id"}, nil),
	))
	_, err = c.db.ExecContext(ctx, q, args...)
	return err
}

// DeleteIdentity deletes identity in document.
func (c *SQLDatastoreColl) DeleteIdentity(ctx context.Context, query *DeleteIdentityQuery) error {
	ok, err := c.documentExists(ctx, c.db, query.AuthenticSource, query.Scope, query.DocumentID)
	if err != nil {
		return err
	}
	if !ok {
		return helpers.ErrNoDocumentFound
	}

	sqlQuery := c.dialect.Rebind(`DELETE FROM datastore_identity_mapping
		WHERE authentic_source = ? AND scope = ? AND document_id = ? AND identity_mapping_id = ?`)
	_, err = c.db.ExecContext(ctx, sqlQuery, query.AuthenticSource, query.Scope, query.DocumentID, query.AuthenticSourcePersonID)
	return err
}

// Delete deletes a document. Mirrors Mongo's Delete: silently succeeds even
// if nothing matched.
func (c *SQLDatastoreColl) Delete(ctx context.Context, doc *model.MetaData) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:delete")
	defer span.End()

	query := c.dialect.Rebind(`DELETE FROM datastore WHERE authentic_source = ? AND scope = ? AND document_id = ?`)
	if _, err := c.db.ExecContext(ctx, query, doc.AuthenticSource, doc.Scope, doc.DocumentID); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Get returns the matching document, or an error if none exists.
func (c *SQLDatastoreColl) Get(ctx context.Context, meta *model.MetaData) (*model.Document, error) {
	query := c.dialect.Rebind(`SELECT authentic_source, scope, document_id, document_data_validation, document_data, valid_not_after, created_at
		FROM datastore WHERE authentic_source = ? AND scope = ? AND document_id = ?`)

	var row datastoreRow
	if err := c.db.GetContext(ctx, &row, query, meta.AuthenticSource, meta.Scope, meta.DocumentID); err != nil {
		return nil, err
	}

	return &model.Document{Meta: row.toMeta(), DocumentData: row.DocumentData.V}, nil
}

// fetchIdentityMappingIDs returns all identity_mapping_id values for a given document key, sorted.
func (c *SQLDatastoreColl) fetchIdentityMappingIDs(ctx context.Context, q sqlxExtQuerier, authenticSource, scope, documentID string) ([]string, error) {
	query := c.dialect.Rebind(`SELECT identity_mapping_id FROM datastore_identity_mapping
		WHERE authentic_source = ? AND scope = ? AND document_id = ? ORDER BY identity_mapping_id`)
	var ids []string
	if err := q.SelectContext(ctx, &ids, query, authenticSource, scope, documentID); err != nil {
		return nil, err
	}
	return ids, nil
}

func (c *SQLDatastoreColl) toCompleteDocument(ctx context.Context, row datastoreRow) (*model.CompleteDocument, error) {
	ids, err := c.fetchIdentityMappingIDs(ctx, c.db, row.AuthenticSource, row.Scope, row.DocumentID)
	if err != nil {
		return nil, err
	}
	return &model.CompleteDocument{
		Meta:               row.toMeta(),
		IdentityMappingIDs: ids,
		DocumentData:       row.DocumentData.V,
	}, nil
}

// documentKey identifies one datastore row by its natural key.
type documentKey struct {
	AuthenticSource string
	Scope           string
	DocumentID      string
}

// fetchIdentityMappingIDsBatch returns every row's identity_mapping_ids in a
// single query, keyed by documentKey - used instead of calling
// fetchIdentityMappingIDs once per row (an N+1 query pattern) when a caller
// already has a whole result set of rows to resolve at once.
func (c *SQLDatastoreColl) fetchIdentityMappingIDsBatch(ctx context.Context, q sqlxExtQuerier, rows []datastoreRow) (map[documentKey][]string, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(rows))
	args := make([]any, 0, len(rows)*3)
	for i, row := range rows {
		placeholders[i] = "(?, ?, ?)"
		args = append(args, row.AuthenticSource, row.Scope, row.DocumentID)
	}
	query := c.dialect.Rebind(fmt.Sprintf(
		`SELECT authentic_source, scope, document_id, identity_mapping_id FROM datastore_identity_mapping
		WHERE (authentic_source, scope, document_id) IN (%s) ORDER BY document_id, identity_mapping_id`,
		strings.Join(placeholders, ", "),
	))
	var mappingRows []struct {
		AuthenticSource   string `db:"authentic_source"`
		Scope             string `db:"scope"`
		DocumentID        string `db:"document_id"`
		IdentityMappingID string `db:"identity_mapping_id"`
	}
	if err := q.SelectContext(ctx, &mappingRows, query, args...); err != nil {
		return nil, err
	}
	result := make(map[documentKey][]string, len(rows))
	for _, r := range mappingRows {
		key := documentKey{AuthenticSource: r.AuthenticSource, Scope: r.Scope, DocumentID: r.DocumentID}
		result[key] = append(result[key], r.IdentityMappingID)
	}
	return result, nil
}

// toCompleteDocumentsBatch is toCompleteDocument for a whole result set at
// once: one batched identity-mapping query instead of one per row.
func (c *SQLDatastoreColl) toCompleteDocumentsBatch(ctx context.Context, rows []datastoreRow) ([]*model.CompleteDocument, error) {
	idsByKey, err := c.fetchIdentityMappingIDsBatch(ctx, c.db, rows)
	if err != nil {
		return nil, err
	}
	docs := make([]*model.CompleteDocument, len(rows))
	for i, row := range rows {
		key := documentKey{AuthenticSource: row.AuthenticSource, Scope: row.Scope, DocumentID: row.DocumentID}
		docs[i] = &model.CompleteDocument{
			Meta:               row.toMeta(),
			IdentityMappingIDs: idsByKey[key],
			DocumentData:       row.DocumentData.V,
		}
	}
	return docs, nil
}

// GetByIdentity returns matching documents for a scope where any of the
// document's identity mappings match the provided identifier.
func (c *SQLDatastoreColl) GetByIdentity(ctx context.Context, scope, identityMappingID string) (map[string]*model.CompleteDocument, error) {
	query := c.dialect.Rebind(`SELECT d.authentic_source, d.scope, d.document_id, d.document_data_validation, d.document_data, d.valid_not_after, d.created_at
		FROM datastore d
		JOIN datastore_identity_mapping m
			ON d.authentic_source = m.authentic_source AND d.scope = m.scope AND d.document_id = m.document_id
		WHERE d.scope = ? AND m.identity_mapping_id = ?`)

	var rows []datastoreRow
	if err := c.db.SelectContext(ctx, &rows, query, scope, identityMappingID); err != nil {
		return nil, err
	}

	completeDocs, err := c.toCompleteDocumentsBatch(ctx, rows)
	if err != nil {
		return nil, err
	}
	docs := make(map[string]*model.CompleteDocument, len(completeDocs))
	for _, doc := range completeDocs {
		docs[doc.Meta.AuthenticSource] = doc
	}
	return docs, nil
}

// List returns matching document metadata, filtered by identity mapping and
// optionally authentic_source/scope.
func (c *SQLDatastoreColl) List(ctx context.Context, query *ListQuery) ([]*model.DocumentList, error) {
	if err := helpers.Check(ctx, c.Service.cfg, query, c.Service.log); err != nil {
		return nil, err
	}

	conditions := []string{"m.identity_mapping_id = ?"}
	args := []any{query.IdentityMappingID}
	if query.AuthenticSource != "" {
		conditions = append(conditions, "d.authentic_source = ?")
		args = append(args, query.AuthenticSource)
	}
	if query.Scope != "" {
		conditions = append(conditions, "d.scope = ?")
		args = append(args, query.Scope)
	}

	sqlQuery := c.dialect.Rebind(fmt.Sprintf(
		`SELECT d.authentic_source, d.scope, d.document_id, d.document_data_validation, d.valid_not_after, d.created_at
		 FROM datastore d
		 JOIN datastore_identity_mapping m
			ON d.authentic_source = m.authentic_source AND d.scope = m.scope AND d.document_id = m.document_id
		 WHERE %s`,
		strings.Join(conditions, " AND "),
	))

	var rows []datastoreMetaRow
	if err := c.db.SelectContext(ctx, &rows, sqlQuery, args...); err != nil {
		return nil, err
	}

	res := make([]*model.DocumentList, len(rows))
	for i, row := range rows {
		res[i] = &model.DocumentList{Meta: row.toMeta()}
	}
	return res, nil
}

// Replace replaces one document, including its full set of identity
// mappings, matching by natural key. Mirrors Mongo's ReplaceOne: silently
// does nothing if no document matches.
func (c *SQLDatastoreColl) Replace(ctx context.Context, doc *model.CompleteDocument) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:replace")
	defer span.End()

	tx, err := c.db.BeginTxx(ctx, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	ok, err := c.documentExists(ctx, tx, doc.Meta.AuthenticSource, doc.Meta.Scope, doc.Meta.DocumentID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if !ok {
		return nil
	}

	var validNotAfter sql.NullTime
	if doc.Meta.ValidNotAfter != nil {
		validNotAfter = sql.NullTime{Time: *doc.Meta.ValidNotAfter, Valid: true}
	}
	updateQuery := c.dialect.Rebind(`UPDATE datastore SET document_data_validation = ?, document_data = ?, valid_not_after = ?, created_at = ?
		WHERE authentic_source = ? AND scope = ? AND document_id = ?`)
	if _, err := tx.ExecContext(ctx, updateQuery,
		doc.Meta.DocumentDataValidationRef, sqlstore.JSON[map[string]any]{V: doc.DocumentData}, validNotAfter, doc.Meta.CreatedAt,
		doc.Meta.AuthenticSource, doc.Meta.Scope, doc.Meta.DocumentID,
	); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	deleteQuery := c.dialect.Rebind(`DELETE FROM datastore_identity_mapping WHERE authentic_source = ? AND scope = ? AND document_id = ?`)
	if _, err := tx.ExecContext(ctx, deleteQuery, doc.Meta.AuthenticSource, doc.Meta.Scope, doc.Meta.DocumentID); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if err := c.insertIdentityMappings(ctx, tx, doc.Meta, doc.IdentityMappingIDs); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if err := tx.Commit(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	c.Service.log.Info("updated document", "document_id", doc.Meta.DocumentID)
	return nil
}

// GetByKey retrieves a document by its natural key (authentic_source, scope, document_id).
func (c *SQLDatastoreColl) GetByKey(ctx context.Context, authenticSource, scope, documentID string) (*model.CompleteDocument, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:getDocumentByKey")
	defer span.End()

	query := c.dialect.Rebind(`SELECT authentic_source, scope, document_id, document_data_validation, document_data, valid_not_after, created_at
		FROM datastore WHERE authentic_source = ? AND scope = ? AND document_id = ?`)

	var row datastoreRow
	if err := c.db.GetContext(ctx, &row, query, authenticSource, scope, documentID); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return c.toCompleteDocument(ctx, row)
}

// DeleteByKey deletes a document by its natural key (authentic_source, scope, document_id).
func (c *SQLDatastoreColl) DeleteByKey(ctx context.Context, authenticSource, scope, documentID string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:deleteDocumentByKey")
	defer span.End()

	query := c.dialect.Rebind(`DELETE FROM datastore WHERE authentic_source = ? AND scope = ? AND document_id = ?`)
	result, err := c.db.ExecContext(ctx, query, authenticSource, scope, documentID)
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
		return helpers.ErrNoDocumentFound
	}
	return nil
}

// Search returns documents matching a text search or filters, with a limit.
// The document_data.* text search is a known perf tradeoff vs Mongo's
// regex-across-BSON: neither Postgres nor MariaDB can cheaply full-text
// index arbitrary, unschema'd JSON keys without knowing them in advance.
func (c *SQLDatastoreColl) Search(ctx context.Context, query *SearchDocumentsQuery) ([]*model.CompleteDocument, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:searchDocuments")
	defer span.End()

	conditions := []string{}
	args := []any{}

	if query.AuthenticSource != "" {
		if len(query.AllowedAuthenticSources) > 0 && !slices.Contains(query.AllowedAuthenticSources, query.AuthenticSource) {
			return []*model.CompleteDocument{}, nil
		}
		conditions = append(conditions, "d.authentic_source = ?")
		args = append(args, query.AuthenticSource)
	} else if len(query.AllowedAuthenticSources) > 0 {
		placeholders := make([]string, len(query.AllowedAuthenticSources))
		for i, src := range query.AllowedAuthenticSources {
			placeholders[i] = "?"
			args = append(args, src)
		}
		conditions = append(conditions, fmt.Sprintf("d.authentic_source IN (%s)", strings.Join(placeholders, ", ")))
	}

	if query.Scope != "" {
		if len(query.AllowedScopes) > 0 && !slices.Contains(query.AllowedScopes, query.Scope) {
			return []*model.CompleteDocument{}, nil
		}
		conditions = append(conditions, "d.scope = ?")
		args = append(args, query.Scope)
	} else if len(query.AllowedScopes) > 0 {
		placeholders := make([]string, len(query.AllowedScopes))
		for i, scope := range query.AllowedScopes {
			placeholders[i] = "?"
			args = append(args, scope)
		}
		conditions = append(conditions, fmt.Sprintf("d.scope IN (%s)", strings.Join(placeholders, ", ")))
	}

	if query.Search != "" {
		term := "%" + escapeLike(query.Search) + "%"
		searchCols := []string{
			"d.document_id",
			"d.authentic_source",
			"d.scope",
			c.dialect.JSONTextExtract("d.document_data", "family_name"),
			c.dialect.JSONTextExtract("d.document_data", "given_name"),
			c.dialect.JSONTextExtract("d.document_data", "email"),
			c.dialect.JSONTextExtract("d.document_data", "birthdate"),
		}
		orClauses := make([]string, 0, len(searchCols)+1)
		for _, col := range searchCols {
			orClauses = append(orClauses, c.dialect.CaseInsensitiveLike(col))
			args = append(args, term)
		}
		orClauses = append(orClauses, `EXISTS (
			SELECT 1 FROM datastore_identity_mapping m
			WHERE m.authentic_source = d.authentic_source AND m.scope = d.scope AND m.document_id = d.document_id
			AND `+c.dialect.CaseInsensitiveLike("m.identity_mapping_id")+`
		)`)
		args = append(args, term)
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
		`SELECT d.authentic_source, d.scope, d.document_id, d.document_data_validation, d.document_data, d.valid_not_after, d.created_at
		 FROM datastore d WHERE %s ORDER BY d.created_at DESC LIMIT ?`,
		whereClause,
	))
	args = append(args, limit)

	var rows []datastoreRow
	if err := c.db.SelectContext(ctx, &rows, sqlQuery, args...); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	res, err := c.toCompleteDocumentsBatch(ctx, rows)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return res, nil
}

// ListAuthenticSources returns all unique authentic_source values in the datastore.
func (c *SQLDatastoreColl) ListAuthenticSources(ctx context.Context) ([]string, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:datastore:listAuthenticSources")
	defer span.End()

	var results []string
	query := "SELECT DISTINCT authentic_source FROM datastore ORDER BY authentic_source"
	if err := c.db.SelectContext(ctx, &results, query); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return results, nil
}
