package httpserver

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/SUNET/vc/internal/apigw/staticembed"
	"github.com/SUNET/vc/internal/webvendor"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// staticEngine mounts the static tree exactly as Service.Default does, so
// these assert on the real pairing of middleware and file server rather
// than on the middleware alone. The 304 is produced by net/http reading
// back the ETag the middleware set; a test that only checked the header
// would not notice that stopping working.
func staticEngine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	assets := webvendor.Overlay(staticembed.FS)
	etags, err := webvendor.StaticETags(assets)
	require.NoError(t, err)

	engine := gin.New()
	engine.Use(staticCacheHeaders("/static/", etags))
	engine.StaticFS("/static", http.FS(assets))
	return engine
}

func get(t *testing.T, engine *gin.Engine, path, ifNoneMatch string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// embed.FS reports a zero modification time, so the file server emits no
// Last-Modified. Without an ETag there is no validator at all, and the only
// thing governing staleness is the freshness lifetime - which is how a
// 24-hour one let a deployed consent page run new HTML against cached old
// JavaScript.
func TestStaticAssetsCarryAValidator(t *testing.T) {
	engine := staticEngine(t)

	res := get(t, engine, "/static/consent.js", "")
	require.Equal(t, http.StatusOK, res.Code)

	etag := res.Header().Get("ETag")
	require.NotEmpty(t, etag, "a static asset with no validator cannot be revalidated at all")
	require.Equal(t, `"`, string(etag[0]), "a strong ETag is quoted")
	require.Equal(t, "public, no-cache", res.Header().Get("Cache-Control"),
		"no-cache keeps the copy and requires a conditional request; it is not no-store")
}

// The point of the validator: an unchanged file costs a 304 with no body,
// so revalidating on every load does not undo the bandwidth saving the
// long freshness lifetime was there for.
func TestUnchangedAssetRevalidatesTo304(t *testing.T) {
	engine := staticEngine(t)

	first := get(t, engine, "/static/consent.js", "")
	require.Equal(t, http.StatusOK, first.Code)
	require.NotEmpty(t, first.Body.Bytes())

	second := get(t, engine, "/static/consent.js", first.Header().Get("ETag"))
	require.Equal(t, http.StatusNotModified, second.Code)
	require.Empty(t, second.Body.Bytes(), "a 304 must not carry the body it just saved")
}

// ...and a stale validator gets the new file, which is the half that was
// broken: a browser holding the previous deploy's copy must be given this
// one rather than told its own is still good.
func TestChangedAssetIsServedAgain(t *testing.T) {
	engine := staticEngine(t)

	res := get(t, engine, "/static/consent.js", `"0000000000000000000000000000beef"`)
	require.Equal(t, http.StatusOK, res.Code)
	require.NotEmpty(t, res.Body.Bytes())
}

// Different content, different tag. A single shared validator would make
// every asset look unchanged whenever any one of them was.
func TestETagsAreContentDerived(t *testing.T) {
	engine := staticEngine(t)

	js := get(t, engine, "/static/consent.js", "").Header().Get("ETag")
	css := get(t, engine, "/static/styles.css", "").Header().Get("ETag")

	require.NotEmpty(t, js)
	require.NotEmpty(t, css)
	require.NotEqual(t, js, css)
}

// A path the embedded set does not have is left alone rather than given a
// fabricated validator.
func TestUnknownPathGetsNoValidator(t *testing.T) {
	engine := staticEngine(t)

	res := get(t, engine, "/static/not-a-real-asset.js", "")
	require.Equal(t, http.StatusNotFound, res.Code)
	require.Empty(t, res.Header().Get("ETag"))
}

// A vendored asset must get the same treatment as a service's own.
//
// webvendor.Overlay serves these, but walking the overlay used to find
// only the base filesystem - fs.ReadDir fell back to opening the
// directory, Open(".") returned the base's root, and the vendored entries
// were not in that listing. They were served and absent from the index, so
// they got no validator and no Cache-Control at all: still stale, and now
// silently so.
func TestVendoredAssetsAreTaggedToo(t *testing.T) {
	engine := staticEngine(t)

	for _, name := range []string{"dc-api.js", "dc-api-full.js"} {
		t.Run(name, func(t *testing.T) {
			res := get(t, engine, "/static/"+name, "")
			require.Equal(t, http.StatusOK, res.Code, "the overlay serves this file")

			etag := res.Header().Get("ETag")
			require.NotEmpty(t, etag, "a served file with no validator cannot be revalidated")
			require.Equal(t, "public, no-cache", res.Header().Get("Cache-Control"))

			notModified := get(t, engine, "/static/"+name, etag)
			require.Equal(t, http.StatusNotModified, notModified.Code)
		})
	}
}

// The overlay's own contract, asserted directly: a merged listing, base
// winning a name conflict, sorted.
func TestOverlayReadDirMergesBothFilesystems(t *testing.T) {
	entries, err := webvendor.Overlay(staticembed.FS).(fs.ReadDirFS).ReadDir(".")
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}

	require.Contains(t, names, "consent.js", "a file only the base has")
	require.Contains(t, names, "dc-api.js", "a file only the vendor has")
	require.True(t, sort.StringsAreSorted(names), "fs.ReadDir is specified to return entries sorted by filename")

	seen := map[string]int{}
	for _, n := range names {
		seen[n]++
	}
	for n, count := range seen {
		require.Equal(t, 1, count, "%s appears twice in the merged listing", n)
	}
}
