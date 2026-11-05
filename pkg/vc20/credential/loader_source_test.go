package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An operator's own copy of a context is used INSTEAD of dereferencing the
// URL, and the document is cached under the URL the credential names - the
// one the processor will ask for again. Caching it under the file path
// would leave the canonical URL unresolved and fetched after all.
func TestContextSourceFileIsUsedInsteadOfFetching(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "individual-id.jsonld")
	require.NoError(t, os.WriteFile(path, []byte(`{"@context":{"IndividualID":"https://example.org/IndividualID"}}`), 0o600))

	// A URL that cannot be resolved, so a fetch would be unmistakable.
	const url = "https://ctx.invalid/individual-id/v1/context"
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	doc, err := loader.LoadDocument(url)
	require.NoError(t, err, "the configured copy must be used, not the unreachable URL")
	assert.Equal(t, url, doc.DocumentURL,
		"the document is the one the credential names; relative references inside it resolve against that")
	assert.Equal(t, "https://example.org/IndividualID", termIRI(t, loader, url, "IndividualID"))
}

// A source applies to pinning as well, so "lazy" is not the only policy it
// works under.
func TestContextSourceFileIsPinnable(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "ctx.jsonld")
	require.NoError(t, os.WriteFile(path, []byte(`{"@context":{"A":"https://example.org/A"}}`), 0o600))

	const url = "https://ctx.invalid/pinnable.jsonld"
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	require.NoError(t, loader.PinRemoteContext(url))
	assert.True(t, pinned(t, loader, url))
}

// A file that is not a context document fails where it is configured, not
// at the first credential that needs it.
func TestContextSourceFileMustBeJSON(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.jsonld")
	require.NoError(t, os.WriteFile(path, []byte("not json at all"), 0o600))

	const url = "https://ctx.invalid/broken.jsonld"
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	_, err := loader.LoadDocument(url)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not valid JSON")
	assert.Contains(t, err.Error(), url, "the failure has to name the context, not only the path")
}

// A file larger than the cap is refused, for the same reason a response is:
// one context document must not be able to exhaust memory.
func TestContextSourceFileIsSizeCapped(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.jsonld")
	// Valid JSON, and one byte over the cap.
	padding := strings.Repeat("a", maxContextBytes)
	require.NoError(t, os.WriteFile(path, []byte(`{"@context":{"A":"`+padding+`"}}`), 0o600))

	const url = "https://ctx.invalid/huge.jsonld"
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	_, err := loader.LoadDocument(url)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "larger than")
}

// A mirror is an ordinary fetch, so the scheme and address policy apply to
// it unchanged - and a failure names the CANONICAL context, because that is
// the one the operator configured and the one a credential carries.
func TestContextSourceMirrorFailureNamesTheCanonicalContext(t *testing.T) {
	loader := NewCachingDocumentLoader()
	const url = "https://ctx.example.org/mirrored.jsonld"
	loader.SetContextSources(map[string]ContextSource{
		url: {URL: "https://mirror.invalid/mirrored.jsonld"},
	})

	_, err := loader.LoadDocument(url)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "from its configured mirror")
	assert.Contains(t, err.Error(), url)
}

// A source entry naming neither a file nor a URL is refused rather than
// silently falling through to a fetch, which would make a misconfigured
// source look like a working one.
func TestContextSourceWithNeitherFileNorURLIsRefused(t *testing.T) {
	loader := NewCachingDocumentLoader()
	const url = "https://ctx.example.org/empty-source.jsonld"
	loader.SetContextSources(map[string]ContextSource{url: {}})

	_, err := loader.LoadDocument(url)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "neither file nor url")
}

// Contexts with no source configured are unaffected.
func TestContextWithoutASourceIsUntouched(t *testing.T) {
	loader := NewCachingDocumentLoader()
	const url = "https://ctx.example.org/plain.jsonld"
	seedWithTTL(t, loader, url, `{"@context":{"A":"https://example.org/A"}}`)
	loader.SetContextSources(map[string]ContextSource{
		"https://ctx.example.org/other.jsonld": {File: "/nonexistent"},
	})

	doc, err := loader.LoadDocument(url)
	require.NoError(t, err)
	assert.Equal(t, url, doc.DocumentURL)
}

// LoadDocument answers from the cache before it consults a source, so
// installing sources has to drop what is cached for those URLs. The W3C
// base contexts are preloaded at construction with NO expiry, so without
// this an operator's configured copy of one was ignored for the life of the
// process, with nothing to say the setting had not taken.
func TestSetContextSourcesEvictsCachedCopies(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()

	const url = "https://ctx.example.org/cached-first.jsonld"
	seedWithTTL(t, loader, url, `{"@context":{"Term":"https://example.org/stale"}}`)

	path := filepath.Join(dir, "fresh.jsonld")
	require.NoError(t, os.WriteFile(path, []byte(`{"@context":{"Term":"https://example.org/fresh"}}`), 0o600))
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	doc, err := loader.LoadDocument(url)
	require.NoError(t, err)
	assert.Equal(t, url, doc.DocumentURL)
	assert.Equal(t, "https://example.org/fresh", termIRI(t, loader, url, "Term"),
		"the configured copy must win over what was already cached")
}

// Including a preloaded context, which is pinned with no expiry and would
// otherwise never be reconsidered.
func TestSetContextSourcesOverridesAPreloadedContext(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()

	// ContextV2 is preloaded by NewCachingDocumentLoader.
	require.NotNil(t, loader.cache.Get(ContextV2), "precondition: the base context is preloaded")

	path := filepath.Join(dir, "v2.jsonld")
	require.NoError(t, os.WriteFile(path, []byte(`{"@context":{"Marker":"https://example.org/operator-copy"}}`), 0o600))
	loader.SetContextSources(map[string]ContextSource{ContextV2: {File: path}})

	_, err := loader.LoadDocument(ContextV2)
	require.NoError(t, err)
	assert.Equal(t, "https://example.org/operator-copy", termIRI(t, loader, ContextV2, "Marker"))
}

// json-gold mutates what the loader gives it. Handling "@import" it merges
// the importing context's members into the IMPORTED document's own map,
// including the "@import" key itself - so the cached document becomes a
// context declaring a nested import, which the next expansion refuses with
// "must not include @import entry".
//
// A context using @import therefore worked exactly once per process and
// failed every time after. Nothing expanded twice before the startup
// policy began re-checking scopes, which is how it stayed hidden.
func TestExpandingTwiceDoesNotCorruptAnImportedContext(t *testing.T) {
	loader := GetGlobalLoader()
	const importer = "https://ctx.invalid/importer.jsonld"
	const imported = "https://ctx.invalid/imported.jsonld"

	loader.AddContext(imported, `{"@context":{"@version":1.1,"Extra":"https://example.org/Extra"}}`)
	loader.AddContext(importer, `{"@context":{"@version":1.1,"@import":"`+imported+`","Diploma":"https://example.org/Diploma"}}`)

	first, err := ExpandTypes([]string{importer}, []string{"Diploma"})
	require.NoError(t, err, "the first expansion has always worked")
	require.Contains(t, first, "https://example.org/Diploma")

	second, err := ExpandTypes([]string{importer}, []string{"Diploma"})
	require.NoError(t, err, "the second expansion must not see an @import the first one wrote into the cache")
	assert.Equal(t, first, second)

	// And the cached document is still what was loaded.
	doc, err := loader.LoadDocument(imported)
	require.NoError(t, err)
	ctx, ok := doc.Document.(map[string]any)["@context"].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, ctx, "@import",
		"the imported context must not have acquired its importer's @import key")
	assert.NotContains(t, ctx, "Diploma",
		"nor the importer's own terms")
}

// The copy has to be deep: a shallow one shares the nested maps that
// json-gold actually writes into.
func TestLoadDocumentReturnsAnIndependentCopy(t *testing.T) {
	loader := NewCachingDocumentLoader()
	const url = "https://ctx.invalid/independent.jsonld"
	loader.AddContext(url, `{"@context":{"Term":"https://example.org/Term","nested":{"Inner":"https://example.org/Inner"}}}`)

	first, err := loader.LoadDocument(url)
	require.NoError(t, err)

	// Mutate the handed-out document the way the processor does.
	ctx := first.Document.(map[string]any)["@context"].(map[string]any)
	ctx["@import"] = "https://ctx.invalid/injected.jsonld"
	ctx["nested"].(map[string]any)["Inner"] = "https://example.org/Clobbered"

	second, err := loader.LoadDocument(url)
	require.NoError(t, err)
	freshCtx := second.Document.(map[string]any)["@context"].(map[string]any)
	assert.NotContains(t, freshCtx, "@import", "a caller's write must not reach the cache")
	assert.Equal(t, "https://example.org/Inner", freshCtx["nested"].(map[string]any)["Inner"],
		"a shallow copy would share this nested map")
}
