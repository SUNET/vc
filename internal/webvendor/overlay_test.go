package webvendor

import (
	"errors"
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

// A one-sided ReadDir failure is only "absent" when it IS absent.
//
// Treating permission or I/O errors as absence returns a listing short of
// files Open will still serve, and a caller building an index from it gets
// a quietly incomplete one - the same shape as the bug ReadDir exists to
// fix. Open falls back only on ErrNotExist, and this matches it.
func TestOverlayReadDirPropagatesRealErrors(t *testing.T) {
	boom := errors.New("disk is unhappy")

	t.Run("base error is reported", func(t *testing.T) {
		_, err := Overlay(errFS{err: boom}).(fs.ReadDirFS).ReadDir(".")
		require.ErrorIs(t, err, boom)
	})

	t.Run("vendor error is reported", func(t *testing.T) {
		o := overlayFS{base: fstest.MapFS{"a.js": &fstest.MapFile{}}, vendor: errFS{err: boom}}
		_, err := o.ReadDir(".")
		require.ErrorIs(t, err, boom)
	})

	t.Run("a genuinely missing directory on one side still merges", func(t *testing.T) {
		o := overlayFS{
			base:   fstest.MapFS{"only/base.js": &fstest.MapFile{}},
			vendor: fstest.MapFS{"other/vendor.js": &fstest.MapFile{}},
		}
		entries, err := o.ReadDir("only")
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, "base.js", entries[0].Name())
	})

	t.Run("missing on both sides is still an error", func(t *testing.T) {
		o := overlayFS{base: fstest.MapFS{}, vendor: fstest.MapFS{}}
		_, err := o.ReadDir("nowhere")
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}

// errFS fails every operation with a non-ErrNotExist error.
type errFS struct{ err error }

func (e errFS) Open(string) (fs.File, error)          { return nil, e.err }
func (e errFS) ReadDir(string) ([]fs.DirEntry, error) { return nil, e.err }
