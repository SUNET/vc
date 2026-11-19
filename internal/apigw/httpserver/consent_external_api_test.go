package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	authproviders "github.com/SUNET/vc/internal/apigw/auth_providers"
	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	datasources "github.com/SUNET/vc/internal/apigw/data_sources"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSIS is an Edu-API provider that counts the person lookups it receives.
type fakeSIS struct {
	srv        *httptest.Server
	personHits atomic.Int32
	failPerson bool
}

func newFakeSIS(t *testing.T) *fakeSIS {
	t.Helper()
	f := &fakeSIS{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	})
	mux.HandleFunc("/base/persons/p-lisa", func(w http.ResponseWriter, _ *http.Request) {
		f.personHits.Add(1)
		if f.failPerson {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"sourcedId":"p-lisa","recordLanguage":"en","recordStatus":"active"}`))
	})
	mux.HandleFunc("/base/enrollments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// noDocsAPI reports no cached documents, as before any fetch has stored one.
type noDocsAPI struct{ unimplementedApiv1 }

func (noDocsAPI) HasVCIDocuments(context.Context, string) bool { return false }

const consentSessionID = "vci-session-1"

// consentExternalAPIEnv drives the consent endpoint for an external_api scope
// served by the fake SIS (or by no remote at all). Its OIDC provider is not
// enabled, so a request that gets past the external_api step reaches the
// provider check and fails there: no real login is needed, and what the tests
// observe is whether SIS was queried and the documents stored first.
func consentExternalAPIEnv(t *testing.T, sis *fakeSIS, withRemote bool, identifier string) (*httptest.ResponseRecorder, apigwcache.Cache[map[string]*model.CompleteDocument]) {
	t.Helper()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	remotes := map[string]model.Remote{}
	if withRemote {
		remotes["sis"] = model.Remote{
			Type:         model.RemoteTypeEduAPI,
			BaseURL:      sis.srv.URL + "/base",
			TokenURL:     sis.srv.URL + "/oauth2/token",
			ClientID:     "vc",
			ClientSecret: "secret",
			Timeout:      5 * time.Second,
		}
	}
	docs := apigwcache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute)
	dataSources, err := datasources.New(t.Context(), remotes, model.ExternalAPIConfig{
		Scopes: map[string]model.ExternalAPIScope{"sis_enrollment": {Remote: "sis", AuthProvider: model.AuthProviderOIDC}},
	}, docs, log)
	require.NoError(t, err)

	s, engine, rg := newSessionTestEngine(t, noDocsAPI{})
	s.dataSources = dataSources
	s.authProviders = &authproviders.Service{}
	s.cacheService = &apigwcache.Service{AuthContext: apigwcache.NewTestMemoryStore(10 * time.Minute)}

	require.NoError(t, s.cacheService.AuthContext.Save(t.Context(), &apigwcache.AuthorizationContext{
		SessionID:               consentSessionID,
		DataSource:              string(model.DataSourceExternalAPI),
		RemoteName:              "sis",
		AuthenticSourcePersonID: identifier,
	}))

	rg.Use(seedSession(map[string]any{
		"auth_provider": model.AuthProviderOIDC,
		"data_source":   string(model.DataSourceExternalAPI),
		"scope":         "sis_enrollment",
		"session_id":    consentSessionID,
	}))
	s.httpHelpers.Server.RegEndpoint(t.Context(), rg, http.MethodGet,
		"authorization/consent", http.StatusNotModified, s.endpointOAuthAuthorizationConsent)

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authorization/consent", nil))
	return w, docs
}

// Before the login there is no identifier, so nothing is looked up. The request
// used to fail on that ("identifier not found in auth context for external API
// flow") before it could start the login.
func TestConsentExternalAPI_NoIdentifierQueriesNothing(t *testing.T) {
	sis := newFakeSIS(t)

	_, docs := consentExternalAPIEnv(t, sis, true, "")

	assert.Zero(t, sis.personHits.Load())
	_, stored := docs.Get(t.Context(), consentSessionID)
	assert.False(t, stored)
}

// After the callback the identifier is known, and the external API is queried
// before the auth provider is consulted.
func TestConsentExternalAPI_FetchesOnceIdentifierKnown(t *testing.T) {
	sis := newFakeSIS(t)

	_, docs := consentExternalAPIEnv(t, sis, true, "p-lisa")

	assert.EqualValues(t, 1, sis.personHits.Load())
	stored, ok := docs.Get(t.Context(), consentSessionID)
	require.True(t, ok, "the fetched document must be cached under the VCI session")
	assert.Len(t, stored, 1)
}

func TestConsentExternalAPI_NoRemoteEnabledFails(t *testing.T) {
	sis := newFakeSIS(t)

	w, docs := consentExternalAPIEnv(t, sis, false, "p-lisa")

	assert.Zero(t, sis.personHits.Load())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	_, stored := docs.Get(t.Context(), consentSessionID)
	assert.False(t, stored)
}

func TestConsentExternalAPI_FetchErrorFailsTheRequest(t *testing.T) {
	sis := newFakeSIS(t)
	sis.failPerson = true

	w, docs := consentExternalAPIEnv(t, sis, true, "p-lisa")

	assert.EqualValues(t, 1, sis.personHits.Load())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	_, stored := docs.Get(t.Context(), consentSessionID)
	assert.False(t, stored)
}
