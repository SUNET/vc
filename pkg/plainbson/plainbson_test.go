package plainbson

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// The root document decoded into an any is plain, as its nested values are.
func TestUnmarshal_RootAnyIsAPlainMap(t *testing.T) {
	data, err := bson.Marshal(bson.D{
		{Key: "object", Value: bson.D{{Key: "k", Value: "v"}}},
		{Key: "list", Value: bson.A{bson.D{{Key: "k", Value: "v"}}, "a"}},
	})
	require.NoError(t, err)

	var value any
	require.NoError(t, Unmarshal(data, &value))

	assert.Equal(t, map[string]any{
		"object": map[string]any{"k": "v"},
		"list":   []any{map[string]any{"k": "v"}, "a"},
	}, value)
}
