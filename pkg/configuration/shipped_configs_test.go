package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// shippedConfigs are the configuration files this repository ships: the
// reference config, the two examples people copy, and the two Fly
// deployments.
var shippedConfigs = []string{
	"config.yaml",
	"config.oidc.example.yaml",
	"config.saml.example.yaml",
	"fly/dev/config.yaml",
	"fly/demo/config.yaml",
}

// Every key in a shipped config must exist in the model.
//
// The loader is a plain yaml.Unmarshal, so an unknown key is silently
// ignored and a field that has been removed can sit in these files
// indefinitely - telling operators who copy them that a setting exists when
// nothing reads it. apigw.registry_public_url outlived its field that way
// (SUNET/vc#765).
//
// UnmarshalStrict rejects two things: a key with no field in the model, and
// a mapping key repeated within one block. Both are real defects in a file
// this repository ships, and the failure message names the key either way -
// worth knowing which you are looking at, since the remedies differ.
//
// What it does NOT catch is a key that HAS a field nothing reads. That
// decodes perfectly cleanly - SUNET/vc#756 was that, not this - and needs a
// different check entirely.
//
// UnmarshalStrict is what the runtime deliberately does NOT do - loading
// must stay tolerant of a key from a newer or older release - so the strict
// pass belongs here, where it costs an operator nothing and catches the
// drift before it ships.
func TestShippedConfigsCarryNoUnknownKeys(t *testing.T) {
	root := repoRoot(t)

	// Before the loop, because a loop cannot prove it ran: emptying
	// shippedConfigs would otherwise make this test and the one below pass
	// while checking nothing at all.
	require.Len(t, shippedConfigs, 5, "the list of shipped configs has changed - update it deliberately")

	for _, name := range shippedConfigs {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, name))
			require.NoError(t, err)

			var cfg model.Cfg
			assert.NoError(t, yaml.UnmarshalStrict(raw, &cfg),
				"%s carries a key the config model does not define - remove it, or reintroduce the field", name)
		})
	}
}

// ... and every file named is really there, so the strict pass above
// cannot quietly skip one that has been renamed or moved.
func TestShippedConfigsAreAllPresent(t *testing.T) {
	root := repoRoot(t)

	require.NotEmpty(t, shippedConfigs)

	for _, name := range shippedConfigs {
		_, err := os.Stat(filepath.Join(root, name))
		assert.NoError(t, err, "%s is listed here but not in the repository", name)
	}
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "walked past the filesystem root without finding go.mod")
		dir = parent
	}
	t.Fatal("no go.mod within ten levels")
	return ""
}

// ... and a duplicate key is caught too, which is the guard's other half.
func TestShippedConfigsRejectADuplicateKey(t *testing.T) {
	var cfg model.Cfg

	assert.Error(t, yaml.UnmarshalStrict([]byte("common:\n  production: true\n  production: false\n"), &cfg),
		"a repeated mapping key must be refused, not silently last-one-wins")
}
