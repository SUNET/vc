package credential

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsInternalAddr pins which addresses a context fetch may not reach.
func TestIsInternalAddr(t *testing.T) {
	for _, internal := range []string{
		"127.0.0.1", "::1", // loopback
		"10.1.2.3", "192.168.0.1", "172.16.0.1", // private
		"169.254.169.254", // link-local, the cloud metadata endpoint
		"0.0.0.0",         // unspecified
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
