package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bulk handlers read every entry, so a null entry never reaches them.
func TestBulkRequestsRefuseNullEntries(t *testing.T) {
	validate, err := helpers.NewValidator()
	require.NoError(t, err)

	for member, request := range map[string]any{
		"documents": &DatastoreBulkUploadRequest{},
		"mappings":  &IdentityMappingBulkCreateRequest{},
	} {
		t.Run(member, func(t *testing.T) {
			require.NoError(t, json.Unmarshal([]byte(`{"`+member+`":{"x":null}}`), request))

			var refused validator.ValidationErrors
			require.ErrorAs(t, validate.Struct(request), &refused)
			assert.Equal(t, "required", refused[0].Tag())
		})
	}
}
