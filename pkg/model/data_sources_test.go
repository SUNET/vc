package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssertionScope_ResolveDefaults(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	t.Run("no expiry_duration returns Defaults verbatim", func(t *testing.T) {
		scope := AssertionScope{
			Defaults: map[string]any{
				"issuing_authority": "SUNET",
				"date_of_expiry":    "2030-01-01",
			},
		}
		got, err := scope.ResolveDefaults(now)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{
			"issuing_authority": "SUNET",
			"date_of_expiry":    "2030-01-01",
		}, got)
	})

	t.Run("expiry_duration computes date_of_expiry from now", func(t *testing.T) {
		scope := AssertionScope{
			Defaults:       map[string]any{"issuing_authority": "SUNET"},
			ExpiryDuration: "8760h",
		}
		got, err := scope.ResolveDefaults(now)
		require.NoError(t, err)
		assert.Equal(t, "SUNET", got["issuing_authority"])
		assert.Equal(t, "2027-09-17", got["date_of_expiry"])
	})

	t.Run("expiry_duration overrides static date_of_expiry", func(t *testing.T) {
		scope := AssertionScope{
			Defaults: map[string]any{
				"date_of_expiry": "2020-01-01",
			},
			ExpiryDuration: "8760h",
		}
		got, err := scope.ResolveDefaults(now)
		require.NoError(t, err)
		assert.Equal(t, "2027-09-17", got["date_of_expiry"])
	})

	t.Run("invalid expiry_duration returns error", func(t *testing.T) {
		scope := AssertionScope{ExpiryDuration: "not-a-duration"}
		_, err := scope.ResolveDefaults(now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid expiry_duration")
	})

	t.Run("Defaults is not mutated", func(t *testing.T) {
		scope := AssertionScope{
			Defaults:       map[string]any{"date_of_expiry": "2020-01-01"},
			ExpiryDuration: "8760h",
		}
		_, err := scope.ResolveDefaults(now)
		require.NoError(t, err)
		assert.Equal(t, "2020-01-01", scope.Defaults["date_of_expiry"])
	})
}
