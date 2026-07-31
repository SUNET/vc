package tokenstatuslist

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractStatusReference(t *testing.T) {
	t.Run("valid status claim", func(t *testing.T) {
		claims := map[string]any{
			"iss": "https://issuer.example.com",
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": "https://issuer.example.com/statuslists/0",
					"idx": float64(42),
				},
			},
		}

		ref, err := ExtractStatusReference(claims)
		require.NoError(t, err)
		require.NotNil(t, ref)
		assert.Equal(t, "https://issuer.example.com/statuslists/0", ref.URI)
		assert.Equal(t, int64(42), ref.Index)
	})

	t.Run("no status claim", func(t *testing.T) {
		claims := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "user1",
		}

		ref, err := ExtractStatusReference(claims)
		assert.NoError(t, err)
		assert.Nil(t, ref, "no status claim should return nil")
	})

	t.Run("status claim without status_list", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"other_field": "value",
			},
		}

		ref, err := ExtractStatusReference(claims)
		assert.NoError(t, err)
		assert.Nil(t, ref)
	})

	t.Run("status_list missing uri", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"idx": float64(10),
				},
			},
		}

		ref, err := ExtractStatusReference(claims)
		assert.NoError(t, err)
		assert.Nil(t, ref)
	})

	t.Run("status_list missing idx", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": "https://example.com/statuslists/0",
				},
			},
		}

		ref, err := ExtractStatusReference(claims)
		assert.NoError(t, err)
		assert.Nil(t, ref)
	})

	t.Run("idx as int64", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": "https://example.com/statuslists/1",
					"idx": int64(99),
				},
			},
		}

		ref, err := ExtractStatusReference(claims)
		require.NoError(t, err)
		require.NotNil(t, ref)
		assert.Equal(t, int64(99), ref.Index)
	})

	t.Run("idx as int", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": "https://example.com/statuslists/2",
					"idx": 7,
				},
			},
		}

		ref, err := ExtractStatusReference(claims)
		require.NoError(t, err)
		require.NotNil(t, ref)
		assert.Equal(t, int64(7), ref.Index)
	})
}

func TestMapStatusCode(t *testing.T) {
	assert.Equal(t, CredentialStatusValid, MapStatusCode(StatusValid))
	assert.Equal(t, CredentialStatusInvalid, MapStatusCode(StatusInvalid))
	assert.Equal(t, CredentialStatusSuspended, MapStatusCode(StatusSuspended))
	assert.Equal(t, CredentialStatusUnknown, MapStatusCode(255))
}

func TestCredentialStatus_String(t *testing.T) {
	assert.Equal(t, "valid", CredentialStatusValid.String())
	assert.Equal(t, "invalid", CredentialStatusInvalid.String())
	assert.Equal(t, "suspended", CredentialStatusSuspended.String())
	assert.Equal(t, "unknown", CredentialStatusUnknown.String())
}
