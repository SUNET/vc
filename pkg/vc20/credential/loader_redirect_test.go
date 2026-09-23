package credential

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsInternalAddr pins which addresses a context fetch may not reach.
func TestIsInternalAddr(t *testing.T) {
	for _, internal := range []string{
		"127.0.0.1", "::1", // loopback
		"10.1.2.3", "192.168.0.1", "172.16.0.1", // private
		"169.254.169.254",                          // link-local, the cloud metadata endpoint
		"0.0.0.0",                                  // unspecified
		"100.64.0.1",                               // RFC 6598 carrier-grade NAT, which IsPrivate misses
		"198.18.0.1",                               // RFC 2544 benchmarking
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // TEST-NET
		"240.0.0.1",       // reserved
		"224.0.0.1",       // multicast
		"::ffff:10.0.0.1", // IPv4-mapped private address
		"2001:db8::1",     // IPv6 documentation
	} {
		assert.True(t, isInternalAddr(net.ParseIP(internal)), "%s must be refused", internal)
	}
	assert.True(t, isInternalAddr(nil), "an unparsable address is not something to connect to")

	for _, public := range []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		assert.False(t, isInternalAddr(net.ParseIP(public)), "%s is reachable and allowed", public)
	}
}

// TestContextClientRefusesInternalDial pins the layer the check lives at.
//
// Checking the URL before the request covers only the paths this package
// controls. json-gold follows redirects itself, and a Link header with
// rel=alternate makes it call its OWN loader recursively, never re-entering
// CachingDocumentLoader. A dial hook sees all of them, because they all end up
// opening a socket through this client.
func TestContextClientRefusesInternalDial(t *testing.T) {
	var hit bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = w.Write([]byte(`{"@context":{}}`))
	}))
	defer internal.Close()

	resp, err := contextHTTPClient().Get(internal.URL)
	if err == nil {
		defer resp.Body.Close()
	}
	require.Error(t, err, "a context on an internal address must not be connected to")
	assert.Contains(t, err.Error(), "internal address")
	assert.False(t, hit, "and it must never be contacted")
}

// TestLoadDocumentRefusesNonHTTP pins the scheme.
//
// json-gold's loader opens a non-HTTP URL as a LOCAL FILE, and at verification
// the context list comes from the wallet - so file:///etc/passwd would be read
// and parsed as a context.
func TestLoadDocumentRefusesNonHTTP(t *testing.T) {
	loader := NewCachingDocumentLoader()

	for _, bad := range []string{
		"file:///etc/passwd",
		"file:///proc/self/environ",
		"ftp://example.org/ctx.jsonld",
		"/etc/passwd",
		"relative/context.jsonld",
	} {
		t.Run(bad, func(t *testing.T) {
			_, err := loader.LoadDocument(bad)
			require.Error(t, err, "%q must not be opened", bad)
			assert.Contains(t, err.Error(), "only http and https")
		})
	}
}

// TestLoadDocumentServesPreloadedContexts: preloaded contexts come from the
// cache above both checks, which is why the W3C base contexts keep working.
func TestLoadDocumentServesPreloadedContexts(t *testing.T) {
	loader := NewCachingDocumentLoader()
	doc, err := loader.LoadDocument(ContextV2)
	require.NoError(t, err)
	assert.NotNil(t, doc)
}

// TestFetchContextIgnoresLinkAlternate pins the path that made file:// legal
// again after the scheme check.
//
// json-gold resolves a Link: rel=alternate header by calling its OWN loader,
// so an http context could name a file:// alternate and have it read. This
// loader fetches the URL it was given and nothing else.
func TestFetchContextIgnoresLinkAlternate(t *testing.T) {
	served := `{"@context":{"Foo":"https://example.org/ns#Foo"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", `<file:///etc/passwd>; rel="alternate"; type="application/ld+json"`)
		_, _ = w.Write([]byte(served))
	}))
	defer srv.Close()

	loader := NewCachingDocumentLoader()
	// The dial hook refuses loopback, so point the fetch at the server through
	// a client without that policy to isolate what this test is about: that
	// the Link header is not followed.
	loader.client = srv.Client()

	doc, err := loader.LoadDocument(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, doc)

	ctx, ok := doc.Document.(map[string]any)
	require.True(t, ok, "the document served at the URL is what comes back")
	assert.Contains(t, ctx, "@context")
	assert.Empty(t, doc.ContextURL, "no alternate target is recorded or followed")
}

// TestFetchContextRejectsOversizedBody: a context is capped, so a hostile or
// broken endpoint cannot stream indefinitely into memory.
func TestFetchContextRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"@context":{"x":"` + strings.Repeat("a", maxContextBytes) + `"}}`))
	}))
	defer srv.Close()

	loader := NewCachingDocumentLoader()
	loader.client = srv.Client()

	_, err := loader.LoadDocument(srv.URL)
	require.Error(t, err, "a context larger than the cap must not be accepted whole")
}

// TestFetchContextHonoursContextLink pins the difference between the two Link
// relations.
//
// rel="http://www.w3.org/ns/json-ld#context" is how a context served as plain
// JSON names itself (JSON-LD 1.1 6.1), and json-gold resolves ContextURL
// through the DocumentLoader it was given - this one - so it re-enters the
// scheme and dial checks. rel=alternate was resolved by json-gold calling its
// OWN loader, which is how file:// became reachable, so that one stays
// unhonoured.
func TestFetchContextHonoursContextLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", `<https://example.org/real-context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"`)
		w.Header().Add("Link", `<file:///etc/passwd>; rel="alternate"; type="application/ld+json"`)
		_, _ = w.Write([]byte(`{"name":"not a context"}`))
	}))
	defer srv.Close()

	loader := NewCachingDocumentLoader()
	loader.client = srv.Client()

	doc, err := loader.LoadDocument(srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "https://example.org/real-context.jsonld", doc.ContextURL,
		"the context link is recorded, and will be fetched back through this loader")
	assert.NotContains(t, doc.ContextURL, "file://", "the alternate link is still ignored")
}

// TestFetchContextIgnoresContextLinkOnLDJSON: a response already served as
// application/ld+json IS the context, so no indirection applies.
func TestFetchContextIgnoresContextLinkOnLDJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		w.Header().Set("Link", `<https://example.org/other.jsonld>; rel="http://www.w3.org/ns/json-ld#context"`)
		_, _ = w.Write([]byte(`{"@context":{"Foo":"https://example.org/ns#Foo"}}`))
	}))
	defer srv.Close()

	loader := NewCachingDocumentLoader()
	loader.client = srv.Client()

	doc, err := loader.LoadDocument(srv.URL)
	require.NoError(t, err)
	assert.Empty(t, doc.ContextURL)
}
