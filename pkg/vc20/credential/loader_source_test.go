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
