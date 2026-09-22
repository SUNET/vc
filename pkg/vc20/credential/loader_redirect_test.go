package credential

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContextLoaderRefusesInternalRedirects pins the second hop.
//
// The issuer allowlists which context URLs it may dereference. If the fetch
// follows a redirect anywhere, an allowlisted endpoint can answer 302 and send
// it somewhere that was never allowed - which is how an allowlist checked only
// on the first hop gets bypassed. httptest listens on loopback, which stands
// in for the internal address such a bypass aims at.
func TestContextLoaderRefusesInternalRedirects(t *testing.T) {
	var internalHit bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHit = true
		_, _ = w.Write([]byte(`{"@context":{}}`))
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redirector.Close()

	resp, err := contextHTTPClient().Get(redirector.URL)
	if err == nil {
		defer resp.Body.Close()
	}
	require.Error(t, err, "a redirect to an internal address must not be followed")
	assert.Contains(t, err.Error(), "internal address")
	assert.False(t, internalHit, "the redirect target must never be contacted")
}

// TestContextLoaderFetchesDirectly: a context served without a redirect still
// loads, so the policy blocks the bypass and not the feature. Public
// redirects are deliberately still followed - w3id.org exists to redirect, and
// the Data Integrity contexts resolve through it.
func TestContextLoaderFetchesDirectly(t *testing.T) {
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		_, _ = w.Write([]byte(`{"@context":{"Foo":"https://example.org/ns#Foo"}}`))
	}))
	defer direct.Close()

	resp, err := contextHTTPClient().Get(direct.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
