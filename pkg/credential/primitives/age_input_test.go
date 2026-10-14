package primitives

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A birthdate that is empty, malformed or in the future is the HOLDER's
// data, not a server fault - and the caller answering the wallet needs to
// be able to tell the two apart, because one of them is worth retrying
// and the other never is.
func TestAgeOverThresholds_InvalidInputIsMarkedAsSuch(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	for name, birthdate := range map[string]string{
		"empty":                 "",
		"malformed":             "not-a-date",
		"wrong order of fields": "14-10-1990",
		"in the future":         "2030-01-01",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := AgeOverThresholds(birthdate, now, []int{18})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidClaimInput,
				"the caller has to be able to tell this from a server fault")
		})
	}
}

// And a usable birthdate is not marked, so the classification cannot
// swallow a real failure.
func TestAgeOverThresholds_ValidInputIsNotMarked(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	got, err := AgeOverThresholds("1990-10-14", now, []int{18, 65})
	require.NoError(t, err)
	assert.True(t, got["age_over_18"])
	assert.False(t, got["age_over_65"])
	assert.False(t, errors.Is(err, ErrInvalidClaimInput))
}
