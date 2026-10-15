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
// struct refuses the pair as well, but that refusal arrives at serving
// time with no operator watching; this one arrives at startup.
func TestCheckInteractiveAuthorization(t *testing.T) {
	t.Run("require without enable is refused", func(t *testing.T) {
		err := checkInteractiveAuthorization(iaCfg(false, true), "apigw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "require_interactive_authorization")
		assert.Contains(t, err.Error(), "enable is false")
	})

	for _, tt := range []struct {
		name    string
		enable  bool
		require bool
	}{
		{name: "require with enable", enable: true, require: true},
		{name: "neither", enable: false, require: false},
		{name: "enable alone", enable: true, require: false},
	} {
		t.Run(tt.name+" is accepted", func(t *testing.T) {
			assert.NoError(t, checkInteractiveAuthorization(iaCfg(tt.enable, tt.require), "apigw"))
		})
	}

	t.Run("other services are unaffected", func(t *testing.T) {
		// Only apigw serves the Authorization Server metadata; the whole
		// APIGW block is nil on every other service's config by then.
		assert.NoError(t, checkInteractiveAuthorization(iaCfg(false, true), "verifier"))
		assert.NoError(t, checkInteractiveAuthorization(&model.Cfg{}, "apigw"))
	})
}
