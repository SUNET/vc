package apiv1

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	datasources "github.com/SUNET/vc/internal/apigw/data_sources"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func externalAPIAuthClient(t *testing.T, sisStatus int, withRemote bool) *Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	})
	mux.HandleFunc("/base/persons/p-lisa", func(w http.ResponseWriter, _ *http.Request) {
		if sisStatus != http.StatusOK {
			http.Error(w, "nope", sisStatus)
			return
		}
		_, _ = w.Write([]byte(`{"sourcedId":"p-lisa","recordLanguage":"en","recordStatus":"active"}`))
	})
	mux.HandleFunc("/base/enrollments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	log := logger.NewSimple("test")
	docs := apigwcache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute)

	remotes := map[string]model.Remote{}
	if withRemote {
		remotes["sis"] = model.Remote{
			Type:         model.RemoteTypeEduAPI,
			BaseURL:      srv.URL + "/base",
			TokenURL:     srv.URL + "/oauth2/token",
			ClientID:     "vc",
			ClientSecret: "secret",
			Timeout:      5 * time.Second,
		}
	}
	svc, err := datasources.New(t.Context(), remotes, model.ExternalAPIConfig{
		Scopes: map[string]model.ExternalAPIScope{"sis_enrollment": {Remote: "sis", AuthProvider: model.AuthProviderOpenID4VP}},
	}, docs, log)
	require.NoError(t, err)

	return &Client{
		log:          log,
		dataSources:  svc,
		cacheService: &apigwcache.Service{Document: docs},
	}
}

func TestFetchExternalAPIDocuments(t *testing.T) {
	authCtx := &cache.AuthorizationContext{SessionID: "sess-1", RemoteName: "sis"}

	t.Run("a known person is fetched and cached for the session", func(t *testing.T) {
		c := externalAPIAuthClient(t, http.StatusOK, true)

		docs, err := c.fetchExternalAPIDocuments(t.Context(), authCtx, "sis_enrollment", "p-lisa")
		require.NoError(t, err)
		assert.Len(t, docs, 1)

		cached, ok := c.cacheService.Document.Get(t.Context(), "sess-1")
		require.True(t, ok)
		assert.Equal(t, docs, cached)
	})

	t.Run("an unknown person is the wallet's problem", func(t *testing.T) {
		c := externalAPIAuthClient(t, http.StatusNotFound, true)

		_, err := c.fetchExternalAPIDocuments(t.Context(), authCtx, "sis_enrollment", "p-lisa")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrIssuanceAuthServerFault)

		_, cached := c.cacheService.Document.Get(t.Context(), "sess-1")
		assert.False(t, cached)
	})

	t.Run("a failing remote is ours", func(t *testing.T) {
		c := externalAPIAuthClient(t, http.StatusInternalServerError, true)

		_, err := c.fetchExternalAPIDocuments(t.Context(), authCtx, "sis_enrollment", "p-lisa")
		require.ErrorIs(t, err, ErrIssuanceAuthServerFault)
	})

	t.Run("no enabled remote is ours", func(t *testing.T) {
		c := externalAPIAuthClient(t, http.StatusOK, false)

		_, err := c.fetchExternalAPIDocuments(t.Context(), authCtx, "sis_enrollment", "p-lisa")
		require.ErrorIs(t, err, ErrIssuanceAuthServerFault)
	})
}
