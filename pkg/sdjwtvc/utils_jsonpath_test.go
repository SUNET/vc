package sdjwtvc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractClaimsByJSONPath(t *testing.T) {
	t.Run("simple_extraction", func(t *testing.T) {
		documentData := map[string]any{
			"given_name":  "John",
			"family_name": "Doe",
			"birth_date":  "1990-01-01",
		}

		jsonPathMap := map[string]string{
			"given_name_field":  "$.given_name",
			"family_name_field": "$.family_name",
		}

		result, err := ExtractClaimsByJSONPath(documentData, jsonPathMap)
		require.NoError(t, err)
		assert.Equal(t, "John", result["given_name_field"])
		assert.Equal(t, "Doe", result["family_name_field"])
	})

	t.Run("nested_extraction", func(t *testing.T) {
		documentData := map[string]any{
			"name": map[string]any{
				"given":  "John",
				"family": "Doe",
			},
			"birth_date": "1990-01-01",
		}

		jsonPathMap := map[string]string{
			"given_name":  "$.name.given",
			"family_name": "$.name.family",
			"birth_date":  "$.birth_date",
		}

		result, err := ExtractClaimsByJSONPath(documentData, jsonPathMap)
		require.NoError(t, err)
		assert.Equal(t, "John", result["given_name"])
		assert.Equal(t, "Doe", result["family_name"])
		assert.Equal(t, "1990-01-01", result["birth_date"])
	})

	t.Run("missing_path", func(t *testing.T) {
		documentData := map[string]any{
			"given_name": "John",
		}

		jsonPathMap := map[string]string{
			"nonexistent": "$.does_not_exist",
			"existing":    "$.given_name",
		}

		result, err := ExtractClaimsByJSONPath(documentData, jsonPathMap)
		// Missing paths are silently skipped — only matched paths are returned
		require.NoError(t, err)
		assert.Equal(t, "John", result["existing"])
		assert.NotContains(t, result, "nonexistent")
	})

	t.Run("empty_document", func(t *testing.T) {
		documentData := map[string]any{}

		jsonPathMap := map[string]string{
			"some_field": "$.field",
		}

		result, err := ExtractClaimsByJSONPath(documentData, jsonPathMap)
		// No paths match in empty document — returns empty result, no error
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("empty_json_path_map", func(t *testing.T) {
		documentData := map[string]any{
			"given_name": "John",
		}

		jsonPathMap := map[string]string{}

		result, err := ExtractClaimsByJSONPath(documentData, jsonPathMap)
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}
