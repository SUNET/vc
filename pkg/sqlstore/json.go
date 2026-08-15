package sqlstore

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSON is a generic sql.Scanner/driver.Valuer wrapper for marshaling a Go
// value to/from a JSON/JSONB column. Neither database/sql nor sqlx do this
// automatically for struct fields, so repository row structs use this to
// mark which fields need JSON (de)serialization, e.g.:
//
//	type row struct {
//	    UUID       string                       `db:"uuid"`
//	    Parameters JSON[SomeParametersType]      `db:"params"`
//	}
type JSON[T any] struct {
	V T
}

// Value implements driver.Valuer.
func (j JSON[T]) Value() (driver.Value, error) {
	b, err := json.Marshal(j.V)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: marshal JSON column: %w", err)
	}
	return b, nil
}

// Scan implements sql.Scanner.
func (j *JSON[T]) Scan(src any) error {
	if src == nil {
		return nil
	}
	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("sqlstore: cannot scan %T into JSON column", src)
	}
	return json.Unmarshal(b, &j.V)
}
