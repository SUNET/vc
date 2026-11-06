package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/metric"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
)

// listFixtureStore answers List from fixed documents. The store contract test
// proves the same filter on Mongo, Postgres and MariaDB.
type listFixtureStore struct {
	db.DatastoreStore
	documents []*model.MetaData
}

func (s *listFixtureStore) List(_ context.Context, query *db.ListQuery) ([]*model.DocumentList, error) {
	matches := func(value, selected string, allowed []string) bool {
		if selected != "" && value != selected {
			return false
		}
		return len(allowed) == 0 || slices.Contains(allowed, value)
	}
	listed := []*model.DocumentList{}
	for _, meta := range s.documents {
		if matches(meta.AuthenticSource, query.AuthenticSource, query.AllowedAuthenticSources) &&
			matches(meta.Scope, query.Scope, query.AllowedScopes) {
			listed = append(listed, &model.DocumentList{Meta: meta})
		}
	}
	return listed, nil
}

// TestDatastoreListRestrictedToAllowedSources sends list requests through the
// production middleware chain, endpoint and apiv1 handler. An identity holds
// one document in source A and one in source B; alice may read only source A.
func TestDatastoreListRestrictedToAllowedSources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := t.Context()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	stores := &db.Service{DatastoreColl: &listFixtureStore{documents: []*model.MetaData{
		{AuthenticSource: "A", Scope: "pid", DocumentID: "doc-of-A"},
		{AuthenticSource: "B", Scope: "pid", DocumentID: "doc-of-B"},
	}}}
	client, err := apiv1.New(ctx, stores, nil, nil, tracer, &metric.Meter{Meter: noop.NewMeterProvider().Meter("test")}, cfg, log)
	require.NoError(t, err)

	httpHelpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	priv, pubSet := generateKeyPair(t)
	rawKeys, err := json.Marshal(pubSet)
	require.NoError(t, err)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(rawKeys)
		assert.NoError(t, err)
	}))
	t.Cleanup(jwks.Close)
	keyCache := newJWKSCache()
	keyCache.Set(ctx, jwks.URL, rawKeys)

	apiAuth := model.APIAuth{
		Rules: []string{
			`(vc (service apigw)(method *)(path *)(subject alice)(authentic_source A)(scope pid))`,
			`(vc (service apigw)(method *)(path *)(subject bob)(authentic_source *)(scope *))`,
		},
		JWKS: model.APIAuthJWKS{Enable: true, JWKSURL: jwks.URL, Issuer: "https://test-issuer", Audience: "test-audience"},
	}
	spocpEngine, err := httphelpers.BuildSPOCPEngine(apiAuth)
	require.NoError(t, err)
	tokenAuth, err := httpHelpers.Middleware.APIAuth(ctx, "apigw", apiAuth, keyCache)
	require.NoError(t, err)

	s := &Service{cfg: cfg, log: log.New("httpserver"), apiv1: client, tracer: tracer, httpHelpers: httpHelpers, spocpEngine: spocpEngine}

	sessionStore := cookie.NewStore([]byte("12345678901234567890123456789012"), []byte("1234567890123456"))
	sessionStore.Options(sessions.Options{Path: "/", MaxAge: 900, HttpOnly: true})

	engine := gin.New()
	engine.GET("/test-login", sessions.Sessions("admin_session", sessionStore), func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(adminSessionKey, true)
		session.Set("admin_subject", c.Query("subject"))
		session.Set("csrf_token", "csrf")
		assert.NoError(t, session.Save())
	})
	api := engine.Group("/api/v1")
	api.Use(sessions.Sessions("admin_session", sessionStore))
	api.Use(httpHelpers.Middleware.CSRFProtection(adminSessionKey))
	api.Use(httpHelpers.Middleware.SessionOrAPIAuth(adminSessionKey, tokenAuth, spocpEngine, "apigw"))
	httpHelpers.Server.RegEndpoint(ctx, api, http.MethodPost, "/datastore/list", http.StatusOK, s.endpointDatastoreList)

	sessionAs := func(subject string) func(*http.Request) {
		login := httptest.NewRecorder()
		engine.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/test-login?subject="+subject, nil))
		return func(req *http.Request) {
			req.Header.Set("X-CSRF-Token", "csrf")
			for _, sessionCookie := range login.Result().Cookies() {
				req.AddCookie(sessionCookie)
			}
		}
	}
	tokenOf := func(subject string) func(*http.Request) {
		token := signTestJWT(t, priv, subject, "https://test-issuer", "test-audience")
		return func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+token) }
	}

	for _, row := range []struct {
		name       string
		authorize  func(*http.Request)
		body       string
		header     map[string]string
		wantStatus int
		wantDocs   []string
	}{
		{
			name:       "session limited to A, no selector",
			authorize:  sessionAs("alice"),
			body:       `{"identity_mapping_id":"person"}`,
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A"},
		},
		{
			name:       "session limited to A, allowed list B in a header",
			authorize:  sessionAs("alice"),
			body:       `{"identity_mapping_id":"person"}`,
			header:     map[string]string{"AllowedAuthenticSources": "B"},
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A"},
		},
		{
			name:       "session with a wildcard rule, no selector",
			authorize:  sessionAs("bob"),
			body:       `{"identity_mapping_id":"person"}`,
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A", "doc-of-B"},
		},
		{
			name:       "token limited to A, no selector",
			authorize:  tokenOf("alice"),
			body:       `{"identity_mapping_id":"person"}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "token limited to A, selector A",
			authorize:  tokenOf("alice"),
			body:       `{"identity_mapping_id":"person","authentic_source":"A","scope":"pid"}`,
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A"},
		},
		{
			name:       "token with a wildcard rule, no selector",
			authorize:  tokenOf("bob"),
			body:       `{"identity_mapping_id":"person"}`,
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A", "doc-of-B"},
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/datastore/list", strings.NewReader(row.body))
			req.Header.Set("Content-Type", "application/json")
			for name, value := range row.header {
				req.Header.Set(name, value)
			}
			row.authorize(req)

			reply := httptest.NewRecorder()
			engine.ServeHTTP(reply, req)
			require.Equal(t, row.wantStatus, reply.Code, reply.Body.String())
			if row.wantStatus != http.StatusOK {
				return
			}

			var listed apiv1.DatastoreListReply
			require.NoError(t, json.Unmarshal(reply.Body.Bytes(), &listed))
			received := make([]string, 0, len(listed.Data))
			for _, doc := range listed.Data {
				received = append(received, doc.Meta.DocumentID)
			}
			assert.ElementsMatch(t, row.wantDocs, received, "documents received")
		})
	}
}

// TestAllowedListsUnreachableFromBinders offers the allowed lists through every
// channel Binding.Request reads, on every request type that holds them.
func TestAllowedListsUnreachableFromBinders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := t.Context()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)
	httpHelpers, err := httphelpers.New(ctx, tracer, &model.Cfg{Common: &model.Common{}}, log)
	require.NoError(t, err)

	offered := url.Values{"AllowedAuthenticSources": {"B"}, "AllowedScopes": {"pid"}}
	channels := map[string]func() *http.Request{
		"header": func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			for name, values := range offered {
				req.Header.Set(name, values[0])
			}
			return req
		},
		"query": func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/?"+offered.Encode(), nil)
		},
		"form": func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(offered.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req
		},
		"json": func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"AllowedAuthenticSources":["B"],"allowedScopes":["pid"],"-":["B"]}`))
			req.Header.Set("Content-Type", "application/json")
			return req
		},
	}

	for channel, newRequest := range channels {
		t.Run(channel, func(t *testing.T) {
			bind := func(request any) {
				c, _ := gin.CreateTestContext(httptest.NewRecorder())
				c.Request = newRequest()
				// A failed validation of an unrelated required field leaves
				// the request bound, which is what this test inspects.
				err := httpHelpers.Binding.Request(ctx, c, request)
				t.Log("binding result:", err)
			}

			list := &apiv1.DatastoreListRequest{}
			bind(list)
			assert.Nil(t, list.AllowedAuthenticSources)
			assert.Nil(t, list.AllowedScopes)

			search := &apiv1.DatastoreSearchRequest{}
			bind(search)
			assert.Nil(t, search.AllowedAuthenticSources)
			assert.Nil(t, search.AllowedScopes)

			mappingSearch := &apiv1.IdentityMappingSearchRequest{}
			bind(mappingSearch)
			assert.Nil(t, mappingSearch.AllowedAuthenticSources)
		})
	}
}
