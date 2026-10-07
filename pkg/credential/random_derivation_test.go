package credential_test

import (
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/helpers"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// The random primitive has to behave like the others inside a pipeline: its
// output accumulates, later entries can read it, and the caller's claims are
// not mutated.
func TestApplyDerivations_Random(t *testing.T) {
	claims := map[string]any{"given_name": "  Ada  "}

	derived, err := credential.ApplyDerivations([]primitives.Derivation{
		{Random: &primitives.RandomArgs{Output: "document_id"}},
		{Trim: &primitives.TrimArgs{Input: "given_name"}},
		// Reads what the first entry produced, which is the property that
		// makes a generated value usable by the rest of the pipeline.
		{Uppercase: &primitives.UppercaseArgs{Input: "document_id", Output: "document_id_upper"}},
	}, claims, now)
	require.NoError(t, err)

	id, ok := derived["document_id"].(string)
	require.True(t, ok, "document_id is %T", derived["document_id"])
	_, err = uuid.Parse(id)
	require.NoError(t, err, "document_id is not a uuid: %q", id)

	assert.Equal(t, "Ada", derived["given_name"])
	assert.Equal(t, strings.ToUpper(id), derived["document_id_upper"])

	assert.Equal(t, "  Ada  ", claims["given_name"], "the caller's claims must not be mutated")
	assert.NotContains(t, claims, "document_id")
}

// A claim the source data supplied survives: this primitive fills gaps.
func TestApplyDerivations_RandomDoesNotReplaceSourceData(t *testing.T) {
	derived, err := credential.ApplyDerivations([]primitives.Derivation{
		{Random: &primitives.RandomArgs{Output: "document_id"}},
	}, map[string]any{"document_id": "ABC-123"}, now)
	require.NoError(t, err)

	assert.NotContains(t, derived, "document_id")
}

// Config validation: `random:` is a derivation entry like any other, so the
// exactly-one-primitive rule covers it in both directions.
func TestRandomDerivationPassesConfigValidation(t *testing.T) {
	validate, err := helpers.NewValidator()
	require.NoError(t, err)

	t.Run("on its own", func(t *testing.T) {
		assert.NoError(t, validate.Struct(&primitives.Derivation{
			Random: &primitives.RandomArgs{Output: "document_id"},
		}))
	})

	t.Run("without an output", func(t *testing.T) {
		assert.Error(t, validate.Struct(&primitives.Derivation{
			Random: &primitives.RandomArgs{},
		}))
	})

	t.Run("with an unknown format", func(t *testing.T) {
		assert.Error(t, validate.Struct(&primitives.Derivation{
			Random: &primitives.RandomArgs{Output: "id", Format: "dice"},
		}))
	})

	t.Run("with a byte count outside the range", func(t *testing.T) {
		for _, n := range []int{1, 7, 65, 1024} {
			assert.Error(t, validate.Struct(&primitives.Derivation{
				Random: &primitives.RandomArgs{Output: "id", Format: "hex", Bytes: n},
			}), "bytes=%d", n)
		}
	})

	t.Run("alongside another primitive", func(t *testing.T) {
		assert.Error(t, validate.Struct(&primitives.Derivation{
			Random: &primitives.RandomArgs{Output: "id"},
			Trim:   &primitives.TrimArgs{Input: "name"},
		}))
	})
}
