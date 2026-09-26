package webvendor

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestOverlay(t *testing.T) {
	base := fstest.MapFS{
		"own.js":    {Data: []byte("service asset")},
		"dc-api.js": {Data: []byte("service override")},
	}
	o := Overlay(base)

	t.Run("serves the service's own assets", func(t *testing.T) {
		b, err := fs.ReadFile(o, "own.js")
		require.NoError(t, err)
		require.Equal(t, "service asset", string(b))
	})

	t.Run("falls back to the vendored bundle", func(t *testing.T) {
		b, err := fs.ReadFile(o, "dc-api-full.js")
		require.NoError(t, err)
		require.Contains(t, string(b), "@sirosfoundation/dc-api v0.7.0")
	})

	// Both services reference /static/dc-api.js; the overlay is what makes
	// that resolve to the single shared copy rather than a per-service one.
	t.Run("vendored bundle is reachable under its served name", func(t *testing.T) {
		b, err := fs.ReadFile(Overlay(fstest.MapFS{}), "dc-api.js")
		require.NoError(t, err)
		require.Contains(t, string(b), "@sirosfoundation/dc-api v0.7.0")
	})

	t.Run("the service wins a name collision", func(t *testing.T) {
		b, err := fs.ReadFile(o, "dc-api.js")
		require.NoError(t, err)
		require.Equal(t, "service override", string(b))
	})

	t.Run("a name in neither is still not found", func(t *testing.T) {
		_, err := fs.ReadFile(o, "nope.js")
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}
