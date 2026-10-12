package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func iaCfg(enable, require bool) *model.Cfg {
	return &model.Cfg{APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
		InteractiveAuthorization: model.InteractiveAuthorization{
			Enable:                          &enable,
			RequireInteractiveAuthorization: &require,
		},
	}}}
}

// A server cannot require a mechanism it does not offer. The metadata
// generator drops the parameter rather than emit an unusable document, so
// without this check an operator who set it would be silently corrected
// instead of told.
func TestCheckInteractiveAuthorization(t *testing.T) {
	t.Run("require without enable is refused", func(t *testing.T) {
		err := checkInteractiveAuthorization(iaCfg(false, true), "apigw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "require_interactive_authorization")
		assert.Contains(t, err.Error(), "enable is false")
	})

	t.Run("require with enable is accepted", func(t *testing.T) {
		assert.NoError(t, checkInteractiveAuthorization(iaCfg(true, true), "apigw"))
	})

	t.Run("neither set is accepted", func(t *testing.T) {
		assert.NoError(t, checkInteractiveAuthorization(iaCfg(false, false), "apigw"))
	})

	t.Run("enable alone is accepted", func(t *testing.T) {
		assert.NoError(t, checkInteractiveAuthorization(iaCfg(true, false), "apigw"))
	})

	t.Run("other services are unaffected", func(t *testing.T) {
		// Only apigw serves the Authorization Server metadata; the field
		// is nil on every other service's config by then.
		assert.NoError(t, checkInteractiveAuthorization(iaCfg(false, true), "verifier"))
		assert.NoError(t, checkInteractiveAuthorization(&model.Cfg{}, "apigw"))
	})
}
