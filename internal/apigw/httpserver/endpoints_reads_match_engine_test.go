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

// readFixtureStore answers List and Search from fixed documents.
type readFixtureStore struct {
	db.DatastoreStore
	documents []*model.MetaData
}

func selectedBy(selected, stored string) bool {
	return selected == "" || selected == stored
}

func (s *readFixtureStore) List(_ context.Context, query *db.ListQuery) ([]*model.DocumentList, error) {
	listed := []*model.DocumentList{}
	for _, meta := range s.documents {
		if selectedBy(query.AuthenticSource, meta.AuthenticSource) && selectedBy(query.Scope, meta.Scope) &&
			listQueryAccepts(query, meta.AuthenticSource, meta.Scope) {
			listed = append(listed, &model.DocumentList{Meta: meta})
		}
	}
	return listed, nil
}

func (s *readFixtureStore) Search(_ context.Context, query *db.SearchDocumentsQuery) ([]*model.CompleteDocument, error) {
	found := []*model.CompleteDocument{}
	for _, meta := range s.documents {
		if selectedBy(query.AuthenticSource, meta.AuthenticSource) && selectedBy(query.Scope, meta.Scope) &&
			searchQueryAccepts(query, meta.AuthenticSource, meta.Scope) {
			found = append(found, &model.CompleteDocument{Meta: meta})
		}
	}
	return found, nil
}

// readChain is the production middleware chain, endpoints and apiv1 handlers
// over a fixture store.
type readChain struct {
	engine    *gin.Engine
	spocp     *httphelpers.SafeEngine
	sessionAs func(subject string) func(*http.Request)
	tokenOf   func(subject string) func(*http.Request)
}

// newReadChain builds the chain from rules. Without tokens the deployment has no
// Bearer mode, so a request with no session passes as an open one.
func newReadChain(t *testing.T, documents []*model.MetaData, rules []string, tokens bool) *readChain {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctx := t.Context()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	stores := &db.Service{
		DatastoreColl:        &readFixtureStore{documents: documents},
		IdentityMappingsColl: &mappingFixtureStore{documents: documents},
	}
	client, err := apiv1.New(ctx, stores, nil, nil, tracer, &metric.Meter{Meter: noop.NewMeterProvider().Meter("test")}, cfg, log)
	require.NoError(t, err)
	httpHelpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	apiAuth := model.APIAuth{Rules: rules}
	priv, pubSet := generateKeyPair(t)
	keyCache := newJWKSCache()
	if tokens {
		rawKeys, err := json.Marshal(pubSet)
		require.NoError(t, err)
		jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write(rawKeys)
			assert.NoError(t, err)
		}))
		t.Cleanup(jwks.Close)
		keyCache.Set(ctx, jwks.URL, rawKeys)
		apiAuth.JWKS = model.APIAuthJWKS{Enable: true, JWKSURL: jwks.URL, Issuer: "https://test-issuer", Audience: "test-audience"}
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
	httpHelpers.Server.RegEndpoint(ctx, api, http.MethodGet, "/datastore/search", http.StatusOK, s.endpointDatastoreSearch)
	httpHelpers.Server.RegEndpoint(ctx, api, http.MethodGet, "/identity/mapping/search", http.StatusOK, s.endpointIdentityMappingSearch)

	return &readChain{
		engine: engine,
		spocp:  spocpEngine,
		sessionAs: func(subject string) func(*http.Request) {
			login := httptest.NewRecorder()
			engine.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/test-login?subject="+url.QueryEscape(subject), nil))
			return func(req *http.Request) {
				req.Header.Set("X-CSRF-Token", "csrf")
				for _, sessionCookie := range login.Result().Cookies() {
					req.AddCookie(sessionCookie)
				}
			}
		},
		tokenOf: func(subject string) func(*http.Request) {
			token := signTestJWT(t, priv, subject, "https://test-issuer", "test-audience")
			return func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+token) }
		},
	}
}

// readRoute is one of the routes that answer a request naming no selector.
type readRoute struct {
	name, method, path string
	request            func(source, scope string) *http.Request
	received           func(t *testing.T, body []byte) []string
}

func readRoutes() []readRoute {
	return []readRoute{
		{
			name: "list", method: http.MethodPost, path: "/api/v1/datastore/list",
			request: func(source, scope string) *http.Request {
				body, err := json.Marshal(map[string]string{"identity_mapping_id": "person", "authentic_source": source, "scope": scope})
				if err != nil {
					panic(err)
				}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/datastore/list", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			received: func(t *testing.T, body []byte) []string {
				var reply apiv1.DatastoreListReply
				require.NoError(t, json.Unmarshal(body, &reply))
				ids := make([]string, 0, len(reply.Data))
				for _, doc := range reply.Data {
					ids = append(ids, doc.Meta.DocumentID)
				}
				return ids
			},
		},
		{
			name: "search", method: http.MethodGet, path: "/api/v1/datastore/search",
			request: func(source, scope string) *http.Request {
				query := url.Values{}
				if source != "" {
					query.Set("authentic_source", source)
				}
				if scope != "" {
					query.Set("scope", scope)
				}
				return httptest.NewRequest(http.MethodGet, "/api/v1/datastore/search?"+query.Encode(), nil)
			},
			received: func(t *testing.T, body []byte) []string {
				var reply apiv1.DatastoreSearchReply
				require.NoError(t, json.Unmarshal(body, &reply))
				ids := make([]string, 0, len(reply.Data))
				for _, doc := range reply.Data {
					ids = append(ids, doc.Meta.DocumentID)
				}
				return ids
			},
		},
	}
}

func readFixtureDocuments() []*model.MetaData {
	documents := []*model.MetaData{}
	for _, pair := range [][2]string{
		{"A", "pid"}, {"A", "ehic"}, {"B", "pid"}, {"B", "ehic"}, {"C", "pid"}, {"a", "pid"},
		{"eu-1", "pid"}, {"eu-2", "ehic"}, {"x-eu", "pid"}, {"*", "pid"}, {"A", "identity_mapping"},
	} {
		documents = append(documents, &model.MetaData{AuthenticSource: pair[0], Scope: pair[1], DocumentID: pair[0] + "/" + pair[1]})
	}
	return documents
}

// readRule is a rule whose every position is written out by a row.
func readRule(service, method, path, subject, source, scope string) string {
	return "(vc (service " + service + ")(method " + method + ")(path " + path + ")(subject " + subject + ")(authentic_source " + source + ")(scope " + scope + "))"
}

func aliceRule(source, scope string) string {
	return readRule("apigw", "*", "*", "alice", source, scope)
}

// TestReadsMatchTheEngine holds the guarantee of the read routes: the documents
// a request receives are the ones the engine allows for their own source and
// scope, for each form of rule the parser accepts.
//
// A row marked leftOut holds a form outside the store filter. A request naming no
// selector then receives a subset holding at least the row's atLeast documents.
// Every row sends each fixture document's own pair as a named selector, which
// must reach that document exactly when the engine allows it.
func TestReadsMatchTheEngine(t *testing.T) {
	documents := readFixtureDocuments()

	for _, row := range []struct {
		name  string
		rules []string
		// refused: the routes on which a session naming no selector has no matching rule.
		refused []string
		leftOut bool
		atLeast []string
	}{
		{name: "no rule", rules: []string{readRule("apigw", "*", "*", "bob", "*", "*")}, refused: []string{"list", "search"}},
		{name: "rule of another service", rules: []string{readRule("issuer", "*", "*", "alice", "*", "*")}, refused: []string{"list", "search"}},
		{name: "rule of another method", rules: []string{readRule("apigw", "DELETE", "*", "alice", "*", "*")}, refused: []string{"list", "search"}},
		{name: "rule of another path", rules: []string{readRule("apigw", "*", "/api/v1/credential", "alice", "*", "*")}, refused: []string{"list", "search"}},
		{name: "rule of another path form", rules: []string{readRule("apigw", "*", "/other/*", "alice", "*", "*")}, refused: []string{"list", "search"}},
		{name: "rule on the list path", rules: []string{readRule("apigw", "POST", "/api/v1/datastore/list", "alice", "A", "pid")}, refused: []string{"search"}},
		{name: "rule on the search method", rules: []string{readRule("apigw", "GET", "*", "alice", "A", "pid")}, refused: []string{"list"}},
		{name: "one pair", rules: []string{aliceRule("A", "pid")}},
		{name: "two disjoint pairs", rules: []string{aliceRule("A", "pid"), aliceRule("B", "ehic")}},
		{name: "set of sources", rules: []string{aliceRule("(* set A B)", "pid")}},
		{name: "set of scopes", rules: []string{aliceRule("A", "(* set pid ehic)")}},
		{name: "sets in both positions", rules: []string{aliceRule("(* set A C)", "(* set pid ehic)")}},
		{name: "nested set", rules: []string{aliceRule("(* set (* set A) C)", "pid")}},
		{name: "set holding a literal star", rules: []string{aliceRule("(* set * B)", "pid")}},
		{name: "set holding a literal trailing star", rules: []string{aliceRule("(* set eu* B)", "pid")}},
		{name: "set holding a wildcard", rules: []string{aliceRule("(* set (*) B)", "pid")}},
		{name: "wildcard source, atom scope", rules: []string{aliceRule("*", "ehic")}},
		{name: "atom source, wildcard scope", rules: []string{aliceRule("A", "*")}},
		{name: "wildcard written (*)", rules: []string{aliceRule("(*)", "(*)")}},
		{name: "wildcard rule, path *", rules: []string{aliceRule("*", "*")}},
		{name: "wildcard rule, path /api/v1/*", rules: []string{readRule("apigw", "*", "/api/v1/*", "alice", "*", "*")}},
		{name: "wildcard rule, wildcard subject", rules: []string{readRule("apigw", "*", "/api/v1/*", "*", "*", "*")}},
		{name: "pair, subject prefix", rules: []string{readRule("apigw", "*", "*", "ali*", "A", "pid")}},
		{name: "pair, subject suffix", rules: []string{readRule("apigw", "*", "*", "(* suffix ice)", "A", "pid")}},
		{name: "pair, subject set", rules: []string{readRule("apigw", "*", "*", "(* set bob alice)", "A", "pid")}},
		{name: "wildcard scope plus a pair", rules: []string{aliceRule("A", "*"), aliceRule("B", "pid")}},
		{name: "nested list source matches nothing", rules: []string{aliceRule("(foo bar)", "*")}, refused: []string{"list", "search"}},
		{name: "prefix source", rules: []string{aliceRule("eu*", "pid")}, leftOut: true},
		{name: "prefix source, star form", rules: []string{aliceRule("(* prefix eu)", "*")}, leftOut: true},
		{name: "suffix source", rules: []string{aliceRule("(* suffix eu)", "pid")}, leftOut: true},
		{name: "prefix scope", rules: []string{aliceRule("A", "pi*")}, leftOut: true},
		{name: "wildcard source, suffix scope", rules: []string{aliceRule("*", "(* suffix id)")}, leftOut: true},
		{name: "set holding an atom and a prefix", rules: []string{aliceRule("(* set A (* prefix eu))", "pid")}, leftOut: true, atLeast: []string{"A/pid"}},
		{name: "prefix rule beside a pair", rules: []string{aliceRule("eu*", "pid"), aliceRule("B", "ehic")}, leftOut: true, atLeast: []string{"B/ehic"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			chain := newReadChain(t, documents, row.rules, true)
			alice := map[string]func(*http.Request){"session": chain.sessionAs("alice"), "token": chain.tokenOf("alice")}
			for _, route := range readRoutes() {
				allowedWithin := func(source, scope string) []string {
					allowed := []string{}
					for _, doc := range documents {
						if selectedBy(source, doc.AuthenticSource) && selectedBy(scope, doc.Scope) &&
							chain.spocp.QueryElement(httphelpers.BuildSPOCPQuery("apigw", route.method, route.path, "alice", doc.AuthenticSource, doc.Scope)) {
							allowed = append(allowed, doc.DocumentID)
						}
					}
					return allowed
				}
				for _, authName := range []string{"session", "token"} {
					send := func(source, scope string) (int, []string, string) {
						req := route.request(source, scope)
						alice[authName](req)
						reply := httptest.NewRecorder()
						chain.engine.ServeHTTP(reply, req)
						if reply.Code != http.StatusOK {
							return reply.Code, nil, reply.Body.String()
						}
						return reply.Code, route.received(t, reply.Body.Bytes()), ""
					}

					t.Run(route.name+"/"+authName+"/no selector", func(t *testing.T) {
						allowed := allowedWithin("", "")
						status, received, body := send("", "")
						switch {
						case authName == "token":
							assert.Subset(t, allowed, received, "documents received")
							if status == http.StatusOK {
								assert.ElementsMatch(t, allowed, received, "documents received")
							} else {
								assert.Equal(t, http.StatusForbidden, status, body)
							}
						case slices.Contains(row.refused, route.name):
							assert.Equal(t, http.StatusForbidden, status, "documents received: %v", received)
							assert.Contains(t, body, "insufficient permissions")
						case row.leftOut:
							require.Equal(t, http.StatusOK, status, body)
							assert.Subset(t, allowed, received, "documents received")
							assert.Subset(t, received, row.atLeast, "documents received")
						default:
							require.Equal(t, http.StatusOK, status, body)
							assert.ElementsMatch(t, allowed, received, "documents received")
						}
					})

					t.Run(route.name+"/"+authName+"/named selectors", func(t *testing.T) {
						for _, doc := range documents {
							status, received, body := send(doc.AuthenticSource, doc.Scope)
							want := allowedWithin(doc.AuthenticSource, doc.Scope)
							if len(want) > 0 {
								assert.Equal(t, http.StatusOK, status, "%s: %s", doc.DocumentID, body)
								assert.ElementsMatch(t, want, received, "%s: documents received", doc.DocumentID)
							} else {
								assert.Equal(t, http.StatusForbidden, status, "%s: documents received: %v", doc.DocumentID, received)
							}
							for _, selection := range [][2]string{{doc.AuthenticSource, ""}, {"", doc.Scope}} {
								status, received, body := send(selection[0], selection[1])
								if status == http.StatusOK {
									assert.ElementsMatch(t, allowedWithin(selection[0], selection[1]), received, "%v: documents received", selection)
								} else {
									assert.Equal(t, http.StatusForbidden, status, "%v: %s", selection, body)
								}
							}
						}
					})
				}
			}
		})
	}
}

// TestReadsWithoutRules holds that a deployment with no rules keeps every read:
// a session of any subject, the anonymous one included, and a request on an open
// or a token path.
func TestReadsWithoutRules(t *testing.T) {
	documents := readFixtureDocuments()
	all := make([]string, 0, len(documents))
	for _, doc := range documents {
		all = append(all, doc.DocumentID)
	}

	open := newReadChain(t, documents, nil, false)
	guarded := newReadChain(t, documents, nil, true)
	for _, row := range []struct {
		name      string
		chain     *readChain
		authorize func(*http.Request)
	}{
		{"anonymous session", open, open.sessionAs(anonymousAdminSubject)},
		{"named session", open, open.sessionAs("alice")},
		{"open path", open, func(*http.Request) {}},
		{"anonymous session beside tokens", guarded, guarded.sessionAs(anonymousAdminSubject)},
		{"token", guarded, guarded.tokenOf("alice")},
	} {
		for _, route := range readRoutes() {
			t.Run(row.name+"/"+route.name, func(t *testing.T) {
				req := route.request("", "")
				row.authorize(req)
				reply := httptest.NewRecorder()
				row.chain.engine.ServeHTTP(reply, req)
				require.Equal(t, http.StatusOK, reply.Code, reply.Body.String())
				assert.ElementsMatch(t, all, route.received(t, reply.Body.Bytes()))
			})
		}
	}
}
