// Package sqlstore provides the shared SQL plumbing (dialect differences,
// connection setup, schema migrations) used by every service's relational
// storage implementation. Repository code lives in each service's own db
// package (next to its Mongo sibling), not here — this package only holds
// what's genuinely shared: the small set of behaviors that differ between
// Postgres and MariaDB, and connecting/migrating a database handle.
package sqlstore

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

// Dialect captures the handful of things that genuinely differ between the
// two supported relational backends. Every repository method is written
// once, using a Dialect to produce backend-correct SQL text, so Postgres
// and MariaDB share one code path instead of two.
type Dialect interface {
	// Name identifies the dialect: "postgres" or "mariadb".
	Name() string
	// DriverName is the database/sql driver name to pass to sql.Open/sqlx.Open.
	DriverName() string
	// Rebind rewrites a query written with "?" placeholders into this
	// dialect's native placeholder style: a no-op for MariaDB, $1/$2/...
	// for Postgres.
	Rebind(query string) string
	// JSONColumnType is the column type used for JSON-valued columns:
	// "JSONB" for Postgres, "JSON" for MariaDB. The actual column types
	// live in the migration files; this is informational, for tests and
	// tooling that want to assert a dialect-appropriate schema.
	JSONColumnType() string
	// UpsertClause returns the dialect-native SQL fragment to append to an
	// "INSERT INTO table (...) VALUES (...)" statement to make it an
	// upsert-by-natural-key. conflictCols are the natural-key columns that
	// define the conflict target; updateCols are the columns to overwrite
	// when a conflict occurs. If updateCols is empty, the upsert becomes a
	// no-op-on-conflict insert (insert-if-absent).
	UpsertClause(conflictCols, updateCols []string) string
	// JSONContains returns a boolean SQL expression testing whether the JSON
	// value in column contains all the keys/values of the JSON document
	// bound to the next "?" placeholder (combine with Rebind as usual).
	JSONContains(column string) string
	// JSONTextExtract returns a SQL expression extracting the text value at
	// the given top-level key of a JSON column.
	JSONTextExtract(column, key string) string
	// CaseInsensitiveLike returns a boolean SQL expression doing a
	// case-insensitive substring match of column against the next "?"
	// placeholder. On MariaDB this relies on the column's collation being
	// case-insensitive (the default for this schema's text columns); it is
	// not otherwise enforced at the SQL level the way Postgres's ILIKE is.
	CaseInsensitiveLike(column string) string
}

// PostgresDialect is the Dialect implementation for PostgreSQL.
var PostgresDialect Dialect = postgresDialect{}

// MariaDBDialect is the Dialect implementation for MariaDB/MySQL.
var MariaDBDialect Dialect = mariaDBDialect{}

// ForName returns the Dialect for the given backend name ("postgres" or
// "mariadb"), as used by Common.SQL.Backend.
func ForName(name string) (Dialect, error) {
	switch name {
	case "postgres":
		return PostgresDialect, nil
	case "mariadb":
		return MariaDBDialect, nil
	default:
		return nil, fmt.Errorf("sqlstore: unknown dialect %q", name)
	}
}

type postgresDialect struct{}

func (postgresDialect) Name() string               { return "postgres" }
func (postgresDialect) DriverName() string         { return "pgx" }
func (postgresDialect) Rebind(query string) string { return sqlx.Rebind(sqlx.DOLLAR, query) }
func (postgresDialect) JSONColumnType() string     { return "JSONB" }

func (postgresDialect) UpsertClause(conflictCols, updateCols []string) string {
	if len(conflictCols) == 0 {
		panic("sqlstore: UpsertClause requires at least one conflict column")
	}
	if len(updateCols) == 0 {
		return fmt.Sprintf("ON CONFLICT (%s) DO NOTHING", strings.Join(conflictCols, ", "))
	}
	sets := make([]string, len(updateCols))
	for i, c := range updateCols {
		sets[i] = fmt.Sprintf("%s = EXCLUDED.%s", c, c)
	}
	return fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET %s", strings.Join(conflictCols, ", "), strings.Join(sets, ", "))
}

func (postgresDialect) JSONContains(column string) string {
	return column + " @> ?::jsonb"
}

func (postgresDialect) JSONTextExtract(column, key string) string {
	return fmt.Sprintf("%s->>'%s'", column, escapeSQLStringLiteral(key))
}

// escapeSQLStringLiteral escapes a value for safe embedding inside a
// standard-conforming ('...') SQL string literal by doubling embedded
// single quotes. Postgres's default standard_conforming_strings setting
// means backslash has no special meaning in a plain '...' literal, so only
// the quote character itself needs escaping. Every JSONTextExtract caller
// today passes a hardcoded key (never user input), but this guards against
// both malformed SQL for keys with unusual characters and, if a future
// caller ever passes an untrusted key, SQL injection via an embedded quote.
func escapeSQLStringLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func (postgresDialect) CaseInsensitiveLike(column string) string {
	return column + " ILIKE ?"
}

type mariaDBDialect struct{}

func (mariaDBDialect) Name() string               { return "mariadb" }
func (mariaDBDialect) DriverName() string         { return "mysql" }
func (mariaDBDialect) Rebind(query string) string { return sqlx.Rebind(sqlx.QUESTION, query) }
func (mariaDBDialect) JSONColumnType() string     { return "JSON" }

func (mariaDBDialect) UpsertClause(conflictCols, updateCols []string) string {
	if len(conflictCols) == 0 {
		panic("sqlstore: UpsertClause requires at least one conflict column")
	}
	if len(updateCols) == 0 {
		// MariaDB has no "DO NOTHING" upsert clause; updating a conflict
		// column to itself is a harmless no-op write that still avoids a
		// duplicate-key error.
		return fmt.Sprintf("ON DUPLICATE KEY UPDATE %s = %s", conflictCols[0], conflictCols[0])
	}
	sets := make([]string, len(updateCols))
	for i, c := range updateCols {
		sets[i] = fmt.Sprintf("%s = VALUES(%s)", c, c)
	}
	return fmt.Sprintf("ON DUPLICATE KEY UPDATE %s", strings.Join(sets, ", "))
}

func (mariaDBDialect) JSONContains(column string) string {
	return fmt.Sprintf("JSON_CONTAINS(%s, ?)", column)
}

func (mariaDBDialect) JSONTextExtract(column, key string) string {
	// MariaDB does not support MySQL's "->>" shorthand operator; use the
	// portable JSON_UNQUOTE(JSON_EXTRACT(...)) form instead. The key is
	// always double-quoted within the JSON path ($."key") -- valid whether
	// or not the key actually needs quoting -- and escaped, guarding
	// against both malformed SQL for irregular keys and, if a future caller
	// ever passes an untrusted key, injection via an embedded quote.
	return fmt.Sprintf("JSON_UNQUOTE(JSON_EXTRACT(%s, '$.%s'))", column, escapeMariaDBJSONPathKey(key))
}

// escapeMariaDBJSONPathKey escapes key for safe embedding as a double-quoted
// JSON path segment ($."key") inside a SQL string literal. Uses Go's own
// JSON string escaping (json.Marshal on a string never fails) for the
// path-quoting layer -- the JSON path grammar's quoted-key escaping rules
// are the same as JSON string escaping -- then escapes the result again for
// the surrounding SQL string literal: unlike Postgres, MariaDB's default
// sql_mode treats backslash as an escape character in string literals, so
// both backslash and the quote character need escaping here.
func escapeMariaDBJSONPathKey(key string) string {
	jsonQuoted, _ := json.Marshal(key) // e.g. `"foo\"bar"`, already double-quoted
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(string(jsonQuoted))
}

func (mariaDBDialect) CaseInsensitiveLike(column string) string {
	return column + " LIKE ?"
}
