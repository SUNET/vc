package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	bindingSubject = "alice@sunet.se"
	sourceA        = "A"
	sourceB        = "B"
	scopeA         = "pid"
)

// bindingSelector is a selector value a handler received.
type bindingSelector struct{ source, scope string }

// allowed is the policy of newBindingHarness, stated independently of the
// engine. An empty value selects nothing.
func (s bindingSelector) allowed() bool {
	return (s.source == "" || s.source == sourceA) && (s.scope == "" || s.scope == scopeA)
}

// bindingAPI records the selector values that reach the business layer. Each
// method reads its own request type, so the record is independent of how the
// request was bound or authorized.
type bindingAPI struct {
	unimplementedApiv1
	received []bindingSelector
	reached  bool
}

func (a *bindingAPI) saw(source, scope string) {
	a.reached = true
	a.received = append(a.received, bindingSelector{source, scope})
}

func (a *bindingAPI) DatastoreUpload(_ context.Context, r *vcclient.UploadRequest) (*apiv1.DatastoreUploadReply, error) {
	a.saw(r.Meta.AuthenticSource, r.Meta.Scope)
	return &apiv1.DatastoreUploadReply{}, nil
}

func (a *bindingAPI) DatastoreReplace(_ context.Context, r *vcclient.UploadRequest) error {
	a.saw(r.Meta.AuthenticSource, r.Meta.Scope)
	return nil
}

func (a *bindingAPI) DatastoreBulkUpload(_ context.Context, r *apiv1.DatastoreBulkUploadRequest) (*apiv1.DatastoreBulkUploadReply, error) {
	for _, d := range r.Documents {
		a.saw(d.Meta.AuthenticSource, d.Meta.Scope)
	}
	return &apiv1.DatastoreBulkUploadReply{}, nil
}

func (a *bindingAPI) DatastoreGetByKey(_ context.Context, r *apiv1.DatastoreGetByKeyRequest) (*apiv1.DatastoreGetByKeyReply, error) {
	a.saw(r.AuthenticSource, r.Scope)
	return &apiv1.DatastoreGetByKeyReply{}, nil
}

func (a *bindingAPI) DatastoreDeleteByKey(_ context.Context, r *apiv1.DatastoreDeleteByKeyRequest) error {
	a.saw(r.AuthenticSource, r.Scope)
	return nil
}

func (a *bindingAPI) DatastoreResolve(_ context.Context, r *apiv1.DatastoreResolveRequest) (*apiv1.DatastoreResolveReply, error) {
	a.saw(r.AuthenticSource, r.Scope)
	return &apiv1.DatastoreResolveReply{}, nil
}

func (a *bindingAPI) DatastoreList(_ context.Context, r *apiv1.DatastoreListRequest) (*apiv1.DatastoreListReply, error) {
	a.saw(r.AuthenticSource, r.Scope)
	return &apiv1.DatastoreListReply{}, nil
}

func (a *bindingAPI) DatastoreAddIdentity(_ context.Context, r *apiv1.DatastoreAddIdentityRequest) error {
	a.saw(r.AuthenticSource, r.Scope)
	return nil
}

func (a *bindingAPI) DatastoreDeleteIdentity(_ context.Context, r *apiv1.DatastoreDeleteIdentityRequest) error {
	a.saw(r.AuthenticSource, r.Scope)
	return nil
}

func (a *bindingAPI) DatastoreSearch(_ context.Context, r *apiv1.DatastoreSearchRequest) (*apiv1.DatastoreSearchReply, error) {
	a.saw(r.AuthenticSource, r.Scope)
	return &apiv1.DatastoreSearchReply{}, nil
}

func (a *bindingAPI) DatastorePreAuthOffer(_ context.Context, r *apiv1.DatastorePreAuthOfferRequest) (*apiv1.DatastorePreAuthOfferReply, error) {
	a.saw(r.AuthenticSource, r.Scope)
	return &apiv1.DatastorePreAuthOfferReply{}, nil
}

func (a *bindingAPI) PrepareIssuance(_ context.Context, r *apiv1.PrepareIssuanceRequest) (*apiv1.PrepareIssuanceReply, error) {
	a.saw(r.AuthenticSource, r.Scope)
	return &apiv1.PrepareIssuanceReply{}, nil
}

func (a *bindingAPI) IdentityMappingCreate(_ context.Context, r *apiv1.IdentityMappingCreateRequest) (*apiv1.IdentityMappingCreateReply, error) {
	a.saw(r.AuthenticSource, "")
	return &apiv1.IdentityMappingCreateReply{}, nil
}

func (a *bindingAPI) IdentityMappingBulkCreate(_ context.Context, r *apiv1.IdentityMappingBulkCreateRequest) (*apiv1.IdentityMappingBulkCreateReply, error) {
	for _, m := range r.Mappings {
		a.saw(m.AuthenticSource, "")
	}
	return &apiv1.IdentityMappingBulkCreateReply{}, nil
}

func (a *bindingAPI) IdentityMappingResolve(_ context.Context, r *apiv1.IdentityMappingResolveRequest) (*apiv1.IdentityMappingResolveReply, error) {
	a.saw(r.AuthenticSource, "")
	return &apiv1.IdentityMappingResolveReply{}, nil
}

func (a *bindingAPI) IdentityMappingUpdate(_ context.Context, r *apiv1.IdentityMappingUpdateRequest) error {
	a.saw(r.AuthenticSource, "")
	return nil
}

func (a *bindingAPI) IdentityMappingDelete(_ context.Context, r *apiv1.IdentityMappingDeleteRequest) error {
	a.saw(r.AuthenticSource, "")
	return nil
}

func (a *bindingAPI) IdentityMappingSearch(_ context.Context, r *apiv1.IdentityMappingSearchRequest) (*apiv1.IdentityMappingSearchReply, error) {
	a.saw(r.AuthenticSource, "")
	return &apiv1.IdentityMappingSearchReply{}, nil
}

// selectorShape says where a route's request type holds its selector.
type selectorShape int

const (
	shapeTop selectorShape = iota
	shapeMeta
	shapeDocuments
	shapeMappings
)

type bindingEndpoint = func(context.Context, *gin.Context) (any, error)

// bindingRoute is one route of service.go behind SessionOrAPIAuth.
type bindingRoute struct {
	method, path string
	shape        selectorShape
	// filtered: the handler passes the request's reach to its query.
	filtered bool
	// jsonRest holds the other required members in JSON. goRest holds them under
	// the names gin form binding reads for this request type.
	jsonRest, goRest string
	endpoint         func(*Service) bindingEndpoint
}

func (r bindingRoute) name() string { return r.method + " " + r.path }

const (
	bindingUploadRest   = `"identity_mapping_ids":["x"],"document_data":{"k":"v"}`
	bindingUploadGoRest = `IdentityMappingIDs=x&DocumentData=%7B%22k%22%3A%22v%22%7D`
	bindingAttrs        = `"attributes":{"k":"v"}`
	bindingAttrsGo      = `Attributes=%7B%22k%22%3A%22v%22%7D`
	bindingMatch        = `"identity_match":{"claims":{"given_name":{"equals":"Alice"}}}`
	bindingMatchGo      = `IdentityMatch=%7B%22claims%22%3A%7B%22given_name%22%3A%7B%22equals%22%3A%22Alice%22%7D%7D%7D`
)

func bindingRoutes() []bindingRoute {
	return []bindingRoute{
		{method: http.MethodPost, path: "/api/v1/identity/mapping", jsonRest: bindingAttrs, goRest: bindingAttrsGo,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointIdentityMappingCreate }},
		{method: http.MethodPost, path: "/api/v1/identity/mapping/resolve", jsonRest: bindingAttrs, goRest: bindingAttrsGo,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointIdentityMappingResolve }},
		{method: http.MethodPut, path: "/api/v1/identity/mapping", jsonRest: `"authentic_source_person_id":"p"`, goRest: `AuthenticSourcePersonID=p`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointIdentityMappingUpdate }},
		{method: http.MethodDelete, path: "/api/v1/identity/mapping", jsonRest: `"authentic_source_person_id":"p"`, goRest: `AuthenticSourcePersonID=p`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointIdentityMappingDelete }},
		{method: http.MethodGet, path: "/api/v1/identity/mapping/search", filtered: true, jsonRest: `"search":"s"`, goRest: `search=s`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointIdentityMappingSearch }},
		{method: http.MethodPost, path: "/api/v1/identity/mapping/bulk", shape: shapeMappings, jsonRest: bindingAttrs,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointIdentityMappingBulkCreate }},
		{method: http.MethodPost, path: "/api/v1/issuance/prepare", jsonRest: bindingMatch, goRest: bindingMatchGo,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointPrepareIssuance }},
		{method: http.MethodPost, path: "/api/v1/datastore", shape: shapeMeta, jsonRest: bindingUploadRest, goRest: bindingUploadGoRest,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreUpload }},
		{method: http.MethodGet, path: "/api/v1/datastore", jsonRest: `"document_id":"d"`, goRest: `document_id=d`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreGet }},
		{method: http.MethodDelete, path: "/api/v1/datastore", jsonRest: `"document_id":"d"`, goRest: `DocumentID=d`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreDelete }},
		{method: http.MethodPut, path: "/api/v1/datastore", shape: shapeMeta, jsonRest: bindingUploadRest, goRest: bindingUploadGoRest,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreReplace }},
		{method: http.MethodPost, path: "/api/v1/datastore/resolve", jsonRest: bindingAttrs, goRest: bindingAttrsGo,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreResolve }},
		{method: http.MethodPost, path: "/api/v1/datastore/list", jsonRest: `"identity_mapping_id":"i"`, goRest: `IdentityMappingID=i`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreList }},
		{method: http.MethodPut, path: "/api/v1/datastore/identity", jsonRest: `"document_id":"d","identity_mapping_ids":["x"]`, goRest: `DocumentID=d&IdentityMappingIDs=x`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreAddIdentity }},
		{method: http.MethodDelete, path: "/api/v1/datastore/identity", jsonRest: `"document_id":"d","authentic_source_person_id":"p"`, goRest: `DocumentID=d&AuthenticSourcePersonID=p`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreDeleteIdentity }},
		{method: http.MethodGet, path: "/api/v1/datastore/search", filtered: true, jsonRest: `"search":"s"`, goRest: `search=s`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreSearch }},
		{method: http.MethodPost, path: "/api/v1/datastore/bulk", shape: shapeDocuments, jsonRest: bindingUploadRest,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastoreBulkUpload }},
		{method: http.MethodPost, path: "/api/v1/datastore/preauth_offer", jsonRest: `"document_id":"d"`, goRest: `DocumentID=d`,
			endpoint: func(s *Service) bindingEndpoint { return s.endpointDatastorePreAuthOffer }},
	}
}

func (r bindingRoute) wrapperName() string {
	switch r.shape {
	case shapeMeta:
		return "meta"
	case shapeDocuments:
		return "documents"
	case shapeMappings:
		return "mappings"
	default:
		return ""
	}
}

// jsonBody places the selector members where the route's request type reads
// them, under the given spelling of the enclosing member.
func (r bindingRoute) jsonBody(selector, wrapper string) string {
	switch r.shape {
	case shapeMeta:
		return `{"` + wrapper + `":{` + selector + `},` + r.jsonRest + `}`
	case shapeDocuments:
		return `{"` + wrapper + `":{"d":{"meta":{` + selector + `},` + r.jsonRest + `}}}`
	case shapeMappings:
		return `{"` + wrapper + `":{"m":{` + selector + `,` + r.jsonRest + `}}}`
	default:
		return `{` + selector + `,` + r.jsonRest + `}`
	}
}

func (r bindingRoute) body(selector string) string {
	return r.jsonBody(selector, r.wrapperName())
}

func (r bindingRoute) restValues() url.Values {
	values, err := url.ParseQuery(r.goRest)
	if err != nil {
		panic(err)
	}
	return values
}

// goValues is the selector under gin's fallback to the Go field name.
func (r bindingRoute) goValues(source, scope string) url.Values {
	exact := `"authentic_source":"` + source + `","scope":"` + scope + `"`
	switch r.shape {
	case shapeDocuments:
		return url.Values{"Documents": {`{"d":{"meta":{` + exact + `},` + r.jsonRest + `}}`}}
	case shapeMappings:
		return url.Values{"Mappings": {`{"m":{` + exact + `,` + r.jsonRest + `}}`}}
	default:
		values := r.restValues()
		values.Set("AuthenticSource", source)
		values.Set("Scope", scope)
		return values
	}
}

// tagValues is the selector under the names the middleware reads.
func (r bindingRoute) tagValues(source, scope string) url.Values {
	values := r.restValues()
	values.Set("authentic_source", source)
	values.Set("scope", scope)
	return values
}

func (r bindingRoute) jsonRequest(query, body string) *http.Request {
	req := httptest.NewRequest(r.method, r.path+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (r bindingRoute) formRequest(query string, values url.Values) *http.Request {
	req := httptest.NewRequest(r.method, r.path+query, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func (r bindingRoute) multipartRequest(values url.Values) *http.Request {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for key, vals := range values {
		for _, val := range vals {
			if err := w.WriteField(key, val); err != nil {
				panic(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	req := httptest.NewRequest(r.method, r.path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func (r bindingRoute) queryRequest(query string) *http.Request {
	return httptest.NewRequest(r.method, r.path+"?"+query, nil)
}

func withHeaders(req *http.Request, source, scope string) *http.Request {
	req.Header.Set("AuthenticSource", source)
	req.Header.Set("Scope", scope)
	return req
}

const (
	exactA = `"authentic_source":"A","scope":"pid"`
	exactB = `"authentic_source":"B","scope":"pid"`
	queryA = "?authentic_source=A&scope=pid"
	tagsA  = "authentic_source=A&scope=pid&"
)

type bindingSpelling struct {
	name string
	// build returns nil when the spelling does not apply to the route.
	build func(bindingRoute) *http.Request
}

// bindingSpellings holds every reading of a request that may select B or scope
// "other" for a subject allowed only (A, pid).
func bindingSpellings() []bindingSpelling {
	inBody := func(name, selector string) bindingSpelling {
		return bindingSpelling{name, func(r bindingRoute) *http.Request {
			return r.jsonRequest("", r.body(selector))
		}}
	}
	return []bindingSpelling{
		inBody("json upper-case member beside the exact one", exactA+`,"AUTHENTIC_SOURCE":"B"`),
		inBody("json upper-case members alone", `"AUTHENTIC_SOURCE":"B","SCOPE":"pid"`),
		inBody("json Unicode-fold scope beside the exact one", exactA+`,"ſcope":"other"`),
		inBody("json Unicode-fold members alone", `"authentic_ſource":"B","ſcope":"other"`),
		inBody("json repeated member", exactA+`,"authentic_source":"B"`),
		inBody("json value then null", `"authentic_source":"B","authentic_source":null,"scope":"other","scope":null`),
		{"json trailing data", func(r bindingRoute) *http.Request {
			return r.jsonRequest("", r.body(exactB)+`{}`)
		}},
		{"json enclosing member in upper case", func(r bindingRoute) *http.Request {
			if r.shape == shapeTop {
				return nil
			}
			return r.jsonRequest("", r.jsonBody(exactB, strings.ToUpper(r.wrapperName())))
		}},
		{"json enclosing member repeated", func(r bindingRoute) *http.Request {
			if r.shape != shapeMeta {
				return nil
			}
			return r.jsonRequest("", `{"meta":{`+exactB+`},"meta":{"document_id":"d"},`+r.jsonRest+`}`)
		}},
		{"form tag names", func(r bindingRoute) *http.Request {
			return r.formRequest("", r.tagValues(sourceB, scopeA))
		}},
		{"form Go field names", func(r bindingRoute) *http.Request {
			return r.formRequest("", r.goValues(sourceB, scopeA))
		}},
		{"form tag names, query names A", func(r bindingRoute) *http.Request {
			return r.formRequest(queryA, r.tagValues(sourceB, scopeA))
		}},
		{"form Go field names, query names A", func(r bindingRoute) *http.Request {
			return r.formRequest(queryA, r.goValues(sourceB, scopeA))
		}},
		{"multipart tag names", func(r bindingRoute) *http.Request {
			return r.multipartRequest(r.tagValues(sourceB, scopeA))
		}},
		{"multipart Go field names", func(r bindingRoute) *http.Request {
			return r.multipartRequest(r.goValues(sourceB, scopeA))
		}},
		{"query Go field names", func(r bindingRoute) *http.Request {
			return r.queryRequest(r.goValues(sourceB, scopeA).Encode())
		}},
		{"query Go field names beside tag names A", func(r bindingRoute) *http.Request {
			return r.queryRequest(tagsA + r.goValues(sourceB, scopeA).Encode())
		}},
		{"query tag name repeated, A first", func(r bindingRoute) *http.Request {
			return r.queryRequest("authentic_source=A&authentic_source=B&scope=pid&" + r.restValues().Encode())
		}},
		{"header Go field names, no selector in the body", func(r bindingRoute) *http.Request {
			if r.shape == shapeDocuments || r.shape == shapeMappings {
				return nil
			}
			return withHeaders(r.jsonRequest("", `{`+r.jsonRest+`}`), sourceB, scopeA)
		}},
		{"header Go field names beside tag names A", func(r bindingRoute) *http.Request {
			return withHeaders(r.queryRequest(tagsA+r.restValues().Encode()), sourceB, scopeA)
		}},
		{"chunked body names A, query Go field names", func(r bindingRoute) *http.Request {
			req := r.jsonRequest("?"+r.goValues(sourceB, scopeA).Encode(), r.body(exactA))
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
			return req
		}},
		{"text/plain body names A, query Go field names", func(r bindingRoute) *http.Request {
			req := r.jsonRequest("?"+r.goValues(sourceB, scopeA).Encode(), r.body(exactA))
			req.Header.Set("Content-Type", "text/plain")
			return req
		}},
	}
}

// bindingHarness is the auth chain of service.go on the routes of bindingRoutes.
type bindingHarness struct {
	engine  *gin.Engine
	api     *bindingAPI
	cookies []*http.Cookie
	token   string
}

func newBindingHarness(t *testing.T) *bindingHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctx := t.Context()

	log, err := logger.New("binding-test", "", false)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "binding-test", log)
	require.NoError(t, err)
	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	validator, err := helpers.Binding.Validator()
	require.NoError(t, err)
	previous := binding.Validator
	binding.Validator = validator
	t.Cleanup(func() { binding.Validator = previous })

	priv, pubSet := generateKeyPair(t)
	raw, err := json.Marshal(pubSet)
	require.NoError(t, err)
	const jwksURL = "https://jwks.invalid/keys"
	keys := newJWKSCache()
	keys.Set(ctx, jwksURL, raw)

	apiAuth := model.APIAuth{
		Rules: []string{
			`(vc (service apigw)(method *)(path *)(subject ` + bindingSubject + `)(authentic_source A)(scope pid))`,
			`(vc (service apigw)(method *)(path *)(subject ` + bindingSubject + `)(authentic_source A)(scope identity_mapping))`,
		},
		JWKS: model.APIAuthJWKS{Enable: true, JWKSURL: jwksURL, Issuer: "https://issuer", Audience: "aud"},
	}
	apiAuthMiddleware, err := helpers.Middleware.APIAuth(ctx, "apigw", apiAuth, keys)
	require.NoError(t, err)
	spocpEngine, err := httphelpers.BuildSPOCPEngine(apiAuth)
	require.NoError(t, err)

	api := &bindingAPI{}
	s := &Service{cfg: cfg, log: log.New("httpserver"), apiv1: api, tracer: tracer, httpHelpers: helpers, spocpEngine: spocpEngine}

	engine := gin.New()
	store := cookie.NewStore([]byte("12345678901234567890123456789012"), []byte("1234567890123456"))
	engine.Use(sessions.Sessions("admin_session", store))
	engine.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(adminSessionKey, true)
		session.Set("admin_subject", bindingSubject)
		require.NoError(t, session.Save())
	})
	guarded := engine.Group("/")
	guarded.Use(helpers.Middleware.SessionOrAPIAuth(adminSessionKey, apiAuthMiddleware, spocpEngine, "apigw"))
	for _, r := range bindingRoutes() {
		helpers.Server.RegEndpoint(ctx, guarded, r.method, r.path, http.StatusOK, r.endpoint(s))
	}

	login := httptest.NewRecorder()
	engine.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login", nil))
	require.NotEmpty(t, login.Result().Cookies())

	return &bindingHarness{
		engine:  engine,
		api:     api,
		cookies: login.Result().Cookies(),
		token:   signTestJWT(t, priv, bindingSubject, "https://issuer", "aud"),
	}
}

// bindingOutcome is what one request did.
type bindingOutcome struct {
	status   int
	reached  bool
	received []bindingSelector
	body     string
}

func (h *bindingHarness) do(req *http.Request, useSession bool) bindingOutcome {
	if useSession {
		for _, c := range h.cookies {
			req.AddCookie(c)
		}
	} else {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	h.api.received, h.api.reached = nil, false
	w := httptest.NewRecorder()
	h.engine.ServeHTTP(w, req)
	return bindingOutcome{status: w.Code, reached: h.api.reached, received: h.api.received, body: w.Body.String()}
}

// TestSelectorReceivedIsSelectorAuthorized holds the guarantee of the SPOCP
// resource check: a selector that reaches the business layer is one the
// subject's policy allows, under every reading of the request.
func TestSelectorReceivedIsSelectorAuthorized(t *testing.T) {
	h := newBindingHarness(t)

	for _, auth := range []struct {
		name       string
		useSession bool
	}{{"session", true}, {"token", false}} {
		for _, r := range bindingRoutes() {
			t.Run(auth.name+" "+r.name()+" exact members", func(t *testing.T) {
				req := r.jsonRequest("", r.body(exactA))
				if r.method == http.MethodGet {
					req = r.queryRequest(r.tagValues(sourceA, scopeA).Encode())
				}
				got := h.do(req, auth.useSession)
				require.True(t, got.reached, "status %d: %s", got.status, got.body)
				assert.Less(t, got.status, 400, got.body)
				for _, s := range got.received {
					assert.Equal(t, sourceA, s.source)
				}

				got = h.do(r.jsonRequest("", r.body(exactB)), auth.useSession)
				assert.Equal(t, http.StatusForbidden, got.status, got.body)
				assert.False(t, got.reached)
			})

			for _, spelling := range bindingSpellings() {
				req := spelling.build(r)
				if req == nil {
					continue
				}
				t.Run(auth.name+" "+r.name()+" "+spelling.name, func(t *testing.T) {
					got := h.do(req, auth.useSession)
					for _, s := range got.received {
						assert.Truef(t, s.allowed(), "status %d: handler received (%s, %s)", got.status, s.source, s.scope)
					}
				})
			}
		}
	}
}
