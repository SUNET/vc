// Package plainbson decodes stored documents whose any-typed values consumers
// walk as plain Go data. The driver's default gives those values bson.D and
// bson.A, which a map[string]any or []any type assertion does not match.
package plainbson

import (
	"bytes"
	"reflect"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var registry = newRegistry()

func newRegistry() *bson.Registry {
	r := bson.NewRegistry()
	// The driver reads the root document as Type(0) and maps it separately.
	r.RegisterTypeMapEntry(bson.Type(0), reflect.TypeOf(map[string]any{}))
	r.RegisterTypeMapEntry(bson.TypeEmbeddedDocument, reflect.TypeOf(map[string]any{}))
	r.RegisterTypeMapEntry(bson.TypeArray, reflect.TypeOf([]any{}))
	return r
}

// Unmarshal decodes the BSON document data into val. A document held by an
// any value decodes to map[string]any and an array to []any, at every depth
// from the root.
func Unmarshal(data []byte, val any) error {
	decoder := bson.NewDecoder(bson.NewDocumentReader(bytes.NewReader(data)))
	decoder.SetRegistry(registry)
	return decoder.Decode(val)
}
