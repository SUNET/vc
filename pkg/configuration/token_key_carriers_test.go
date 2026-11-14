package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// The loader deliberately does not UnmarshalStrict (shipped_configs_test.go),
// so a key the model does not declare is accepted and silently dropped - the
// configuration looks applied and is not. These run the loader's two steps,
// yaml.Unmarshal then defaults.Set, over the real model so the yaml tag is
// proven to be the one an operator writes.
func TestTokenKeyCarriersAreReadFromTheConfig(t *testing.T) {
	raw := []byte(`
registry:
  token_status_lists:
    token_key_carriers: ["x5c"]
`)

	cfg := &model.Cfg{}
	require.NoError(t, yaml.Unmarshal(raw, cfg))
	require.NoError(t, defaults.Set(cfg))

	assert.Equal(t, []string{"x5c"}, cfg.Registry.TokenStatusLists.TokenKeyCarriers,
		"a configured carrier list must reach the model, not be dropped as an unknown key")
}

func TestTokenKeyCarriersDefaultToBoth(t *testing.T) {
	raw := []byte(`
registry:
  token_status_lists:
    section_size: 1000
`)

	cfg := &model.Cfg{}
	require.NoError(t, yaml.Unmarshal(raw, cfg))
	require.NoError(t, defaults.Set(cfg))

	assert.Equal(t, []string{"x5c", "jwk"}, cfg.Registry.TokenStatusLists.TokenKeyCarriers,
		"saying nothing must ask for every carrier the deployment can produce")
}
