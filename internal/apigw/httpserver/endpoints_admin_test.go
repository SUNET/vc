package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- admin status mock ---

type adminStatusMock struct {
	unimplementedApiv1

	authenticSources []string // returned by ListAuthenticSources
}

func (m *adminStatusMock) ListAuthenticSources(_ context.Context) ([]string, error) {
	return m.authenticSources, nil
}

// testSetupAdminStatus creates a gin engine with a session-authenticated admin
// and registers the /ui/status endpoint. Returns the engine with session cookie
// already established so subsequent requests are authenticated.
func testSetupAdminStatus(t *testing.T, subject string, rules []string, cfg *model.Cfg, mockAPI Apiv1) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	// Build SPOCP engine from rules (same as production service.go)
	apiAuth := model.APIAuth{Rules: rules}
	spocpEngine, err := httphelpers.BuildSPOCPEngine(apiAuth)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       mockAPI,
		tracer:      tracer,
		httpHelpers: helpers,
		spocpEngine: spocpEngine,
	}

	engine := gin.New()

	store := cookie.NewStore([]byte("12345678901234567890123456789012"), []byte("1234567890123456"))
	store.Options(sessions.Options{Path: "/", MaxAge: 900, HttpOnly: true})

	// Status endpoint behind session middleware
	rg := engine.Group("/ui")
	rg.Use(sessions.Sessions("admin_session", store))

	// Helper endpoint to establish session (simulates login)
	rg.GET("/test-login", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(adminSessionKey, true)
		session.Set("admin_subject", subject)
		_ = session.Save()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	helpers.Server.RegEndpoint(ctx, rg, http.MethodGet, "/status", http.StatusOK, s.endpointAdminStatus)

	return engine
}

// loginAndGetCookies performs the test-login and returns the session cookies.
func loginAndGetCookies(t *testing.T, engine *gin.Engine) []*http.Cookie {
	t.Helper()
	req := httptest.NewRequest("GET", "/ui/test-login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	cookies := w.Result().Cookies()
	require.NotEmpty(t, cookies, "login should set session cookie")
	return cookies
}

// getStatus performs an authenticated GET /ui/status and returns the parsed JSON response.
func getStatus(t *testing.T, engine *gin.Engine, cookies []*http.Cookie) map[string]any {
	t.Helper()
	req := httptest.NewRequest("GET", "/ui/status", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	return result
}

// ==================== Admin Status — SPOCP determines UI data ====================

// TestAdminStatus_WildcardRule_FetchesFromDB verifies that when the user has
// a wildcard authentic_source rule, the dropdown is populated from the database.
func TestAdminStatus_WildcardRule_FetchesFromDB(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET", "LADOK", "CSN"},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
				"ehic":  nil,
			},
		},
	}
	rules := []string{
		// Admin has wildcard access
		`(vc (service apigw)(method *)(path /api/v1/*)(subject admin@sunet.se)(authentic_source *)(scope *))`,
	}

	engine := testSetupAdminStatus(t, "admin@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	assert.Equal(t, true, result["authenticated"])
	assert.Equal(t, "admin@sunet.se", result["subject"])

	// With wildcard authentic_source, sources should come from the database
	sources, ok := result["allowed_authentic_sources"].([]any)
	require.True(t, ok, "allowed_authentic_sources should be an array")
	assert.ElementsMatch(t, []any{"SUNET", "LADOK", "CSN"}, sources,
		"wildcard rule should populate sources from database")

	// With wildcard scope, all configured scopes should be returned
	scopes, ok := result["scopes"].([]any)
	require.True(t, ok, "scopes should be an array")
	assert.ElementsMatch(t, []any{"eduid", "pid", "ehic"}, scopes,
		"wildcard scope should return all configured scopes")
}

// TestAdminStatus_RestrictedSources verifies that when the user has a rule
// limiting authentic_source to specific values, only those appear in the dropdown.
func TestAdminStatus_RestrictedSources(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET", "LADOK", "CSN"},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
				"ehic":  nil,
				"elm":   nil,
			},
		},
	}
	rules := []string{
		// alice can only access SUNET + eduid
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))`,
	}

	engine := testSetupAdminStatus(t, "alice@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	assert.Equal(t, true, result["authenticated"])
	assert.Equal(t, "alice@sunet.se", result["subject"])

	// Only SUNET should appear (not fetched from DB since not nil)
	sources, ok := result["allowed_authentic_sources"].([]any)
	require.True(t, ok, "allowed_authentic_sources should be an array")
	assert.Equal(t, []any{"SUNET"}, sources,
		"restricted rule should only show permitted sources")

	// Only eduid should appear in scopes
	scopes, ok := result["scopes"].([]any)
	require.True(t, ok, "scopes should be an array")
	assert.Equal(t, []any{"eduid"}, scopes,
		"restricted scope should only return allowed scopes")
}

// TestAdminStatus_SourceSet verifies that when the user's rule has a set of
// authentic sources, all set members appear in the dropdown.
func TestAdminStatus_SourceSet(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET", "LADOK", "CSN", "SKV"},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
				"ehic":  nil,
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source (* set SUNET LADOK))(scope (* set eduid pid)))`,
	}

	engine := testSetupAdminStatus(t, "alice@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	sources, ok := result["allowed_authentic_sources"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"SUNET", "LADOK"}, sources,
		"source set should populate dropdown with set members")

	scopes, ok := result["scopes"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"eduid", "pid"}, scopes,
		"scope set should filter configured scopes to set members only")
}

// TestAdminStatus_MultipleRules verifies that multiple rules accumulate
// their allowed sources and scopes.
func TestAdminStatus_MultipleRules(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET", "LADOK", "CSN"},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
				"ehic":  nil,
			},
		},
	}
	rules := []string{
		// alice has two rules granting different source/scope combos
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))`,
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source LADOK)(scope pid))`,
	}

	engine := testSetupAdminStatus(t, "alice@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	sources, ok := result["allowed_authentic_sources"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"SUNET", "LADOK"}, sources,
		"multiple rules should accumulate allowed sources")

	scopes, ok := result["scopes"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"eduid", "pid"}, scopes,
		"multiple rules should accumulate allowed scopes")
}

// TestAdminStatus_NoRules_NoEngine verifies that without SPOCP rules
// (nil engine), all sources and scopes are available.
func TestAdminStatus_NoRules_NoEngine(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET", "LADOK"},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
			},
		},
	}
	// No rules → nil engine
	engine := testSetupAdminStatus(t, "anyone@test", nil, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	assert.Equal(t, true, result["authenticated"])

	// No SPOCP engine → AllowedAuthenticSources returns nil → fetch from DB
	sources, ok := result["allowed_authentic_sources"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"SUNET", "LADOK"}, sources,
		"no rules should fetch sources from DB")

	// No SPOCP engine → all configured scopes available
	scopes, ok := result["scopes"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"eduid", "pid"}, scopes,
		"no rules should return all configured scopes")
}

// TestAdminStatus_Unauthenticated verifies that unauthenticated requests
// get a minimal response.
func TestAdminStatus_Unauthenticated(t *testing.T) {
	mock := &adminStatusMock{}
	cfg := &model.Cfg{Common: &model.Common{}}

	engine := testSetupAdminStatus(t, "nobody", nil, cfg, mock)

	// Don't login — just hit status directly
	req := httptest.NewRequest("GET", "/ui/status", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, false, result["authenticated"])
	assert.Nil(t, result["subject"])
	assert.Nil(t, result["scopes"])
	assert.Nil(t, result["allowed_authentic_sources"])
}

// TestAdminStatus_ScopeTemplates verifies that VCTM claim templates are
// returned for scopes that have VCTM configured.
func TestAdminStatus_ScopeTemplates(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET"},
	}

	firstName := "first_name"
	lastName := "last_name"
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": {
					VCTM: &sdjwtvc.VCTM{
						Claims: []sdjwtvc.Claim{
							{Path: []*string{&firstName}},
							{Path: []*string{&lastName}},
						},
					},
				},
				"pid": nil, // no VCTM
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source *)(scope *))`,
	}

	engine := testSetupAdminStatus(t, "alice@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	templates, ok := result["scope_templates"].(map[string]any)
	require.True(t, ok, "scope_templates should be an object")

	// eduid should have a template with claim placeholders
	eduidTpl, ok := templates["eduid"].(map[string]any)
	require.True(t, ok, "eduid scope should have a template")
	assert.Contains(t, eduidTpl, "first_name")
	assert.Contains(t, eduidTpl, "last_name")

	// pid has no VCTM → no template
	_, hasPid := templates["pid"]
	assert.False(t, hasPid, "pid should not have a template (no VCTM)")
}

// TestAdminStatus_EmptyDB_WildcardRule verifies that when the database has no
// authentic sources but the rule is wildcard, the field is empty (not nil).
func TestAdminStatus_EmptyDB_WildcardRule(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{}, // empty DB
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject admin@sunet.se)(authentic_source *)(scope *))`,
	}

	engine := testSetupAdminStatus(t, "admin@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	// DB returns empty → allowedSources stays nil → JSON null
	// This is acceptable — the UI should handle empty/null gracefully
	assert.Equal(t, true, result["authenticated"])
}

// TestAdminStatus_UserNotInRules verifies that a user with no matching SPOCP
// rules gets no sources and no scopes in the UI.
func TestAdminStatus_UserNotInRules(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET", "LADOK"},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
			},
		},
	}
	rules := []string{
		// Only alice has rules — bob has none
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))`,
	}

	// Login as bob — who has no SPOCP rules
	engine := testSetupAdminStatus(t, "bob@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	assert.Equal(t, true, result["authenticated"])
	assert.Equal(t, "bob@sunet.se", result["subject"])

	// No matching rules → ResolveAllowedResources returns empty →
	// filterAllowedScopes returns all scopes (no resource constraints)
	// AllowedAuthenticSources returns nil → fetch from DB
	sources, ok := result["allowed_authentic_sources"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"SUNET", "LADOK"}, sources,
		"user with no rules should get all DB sources (unrestricted)")

	scopes, ok := result["scopes"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"eduid", "pid"}, scopes,
		"user with no rules should get all scopes (no resource constraints)")
}

// TestAdminStatus_ScopeTemplates_NestedPaths verifies that VCTM claims with
// nested paths (e.g., address.street) produce nested template objects.
func TestAdminStatus_ScopeTemplates_NestedPaths(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET"},
	}

	firstName := "first_name"
	address := "address"
	street := "street"
	city := "city"
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {
					VCTM: &sdjwtvc.VCTM{
						Claims: []sdjwtvc.Claim{
							{Path: []*string{&firstName}},
							{Path: []*string{&address, &street}},
							{Path: []*string{&address, &city}},
							{Path: []*string{}},    // empty path — should be skipped
							{Path: []*string{nil}}, // nil element — should be skipped
						},
					},
				},
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source *)(scope *))`,
	}

	engine := testSetupAdminStatus(t, "alice@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	templates, ok := result["scope_templates"].(map[string]any)
	require.True(t, ok)

	pidTpl, ok := templates["pid"].(map[string]any)
	require.True(t, ok, "pid scope should have a template")

	// first_name should be a leaf
	assert.Equal(t, "", pidTpl["first_name"])

	// address should be nested
	addrMap, ok := pidTpl["address"].(map[string]any)
	require.True(t, ok, "address should be a nested map")
	assert.Equal(t, "", addrMap["street"])
	assert.Equal(t, "", addrMap["city"])
}

// TestAdminStatus_ScopeTemplates_LeafOverwrittenByNested verifies that if a
// leaf claim is later extended by a nested path, the nested map wins.
func TestAdminStatus_ScopeTemplates_LeafOverwrittenByNested(t *testing.T) {
	mock := &adminStatusMock{
		authenticSources: []string{"SUNET"},
	}

	address := "address"
	street := "street"
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {
					VCTM: &sdjwtvc.VCTM{
						Claims: []sdjwtvc.Claim{
							// First claim: "address" as a leaf
							{Path: []*string{&address}},
							// Second claim: "address.street" as nested — should overwrite
							{Path: []*string{&address, &street}},
						},
					},
				},
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source *)(scope *))`,
	}

	engine := testSetupAdminStatus(t, "alice@sunet.se", rules, cfg, mock)
	cookies := loginAndGetCookies(t, engine)
	result := getStatus(t, engine, cookies)

	templates, ok := result["scope_templates"].(map[string]any)
	require.True(t, ok)

	pidTpl, ok := templates["pid"].(map[string]any)
	require.True(t, ok)

	// address should be a nested map (overwriting the leaf placeholder)
	addrMap, ok := pidTpl["address"].(map[string]any)
	require.True(t, ok, "address should be a nested map after overwrite")
	assert.Equal(t, "", addrMap["street"])
}

// ==================== End-to-end: login → status → search documents ====================

// e2eMock captures both status (ListAuthenticSources) and search (DatastoreSearch)
// calls so we can verify the full admin flow from login to document listing.
type e2eMock struct {
	unimplementedApiv1

	authenticSources []string
	documents        []*model.CompleteDocument
	capturedSearch   *apiv1.DatastoreSearchRequest // last search request captured
}

func (m *e2eMock) ListAuthenticSources(_ context.Context) ([]string, error) {
	return m.authenticSources, nil
}

func (m *e2eMock) DatastoreSearch(_ context.Context, req *apiv1.DatastoreSearchRequest) (*apiv1.DatastoreSearchReply, error) {
	m.capturedSearch = req
	// Simulate DB-level filtering: return only documents whose source+scope match the allowed lists.
	var filtered []*model.CompleteDocument
	for _, doc := range m.documents {
		if len(req.AllowedAuthenticSources) > 0 && !slices.Contains(req.AllowedAuthenticSources, doc.Meta.AuthenticSource) {
			continue
		}
		if len(req.AllowedScopes) > 0 && !slices.Contains(req.AllowedScopes, doc.Meta.Scope) {
			continue
		}
		filtered = append(filtered, doc)
	}
	return &apiv1.DatastoreSearchReply{Data: filtered}, nil
}

// testSetupE2E creates a gin engine with both /ui/* (status + test-login) and
// /api/v1/datastore/search behind session auth + SPOCP, sharing a single session store.
func testSetupE2E(t *testing.T, subject string, rules []string, cfg *model.Cfg, mockAPI Apiv1) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	apiAuth := model.APIAuth{Rules: rules}
	spocpEngine, err := httphelpers.BuildSPOCPEngine(apiAuth)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       mockAPI,
		tracer:      tracer,
		httpHelpers: helpers,
		spocpEngine: spocpEngine,
	}

	engine := gin.New()

	store := cookie.NewStore([]byte("12345678901234567890123456789012"), []byte("1234567890123456"))
	store.Options(sessions.Options{Path: "/", MaxAge: 900, HttpOnly: true})

	// --- Admin UI routes ---
	uiGroup := engine.Group("/ui")
	uiGroup.Use(sessions.Sessions("admin_session", store))
	uiGroup.GET("/test-login", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(adminSessionKey, true)
		session.Set("admin_subject", subject)
		_ = session.Save()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	helpers.Server.RegEndpoint(ctx, uiGroup, http.MethodGet, "/status", http.StatusOK, s.endpointAdminStatus)

	// --- API routes (same session store, session+SPOCP auth) ---
	// Provide a fallback auth middleware that rejects unauthenticated requests
	// (in production this is the JWT middleware; here we just 401).
	fallbackAuth := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
	apiGroup := engine.Group("/api/v1")
	apiGroup.Use(sessions.Sessions("admin_session", store))
	apiGroup.Use(helpers.Middleware.SessionOrAPIAuth(adminSessionKey, fallbackAuth, spocpEngine, "apigw"))
	helpers.Server.RegEndpoint(ctx, apiGroup, http.MethodGet, "/datastore/search", http.StatusOK, s.endpointDatastoreSearch)

	return engine
}

// e2eLogin logs in and returns cookies + status JSON.
func e2eLogin(t *testing.T, engine *gin.Engine) ([]*http.Cookie, map[string]any) {
	t.Helper()
	cookies := loginAndGetCookies(t, engine)
	status := getStatus(t, engine, cookies)
	return cookies, status
}

// e2eSearch performs GET /api/v1/datastore/search with the session cookies and returns parsed documents.
func e2eSearch(t *testing.T, engine *gin.Engine, cookies []*http.Cookie, query string) []map[string]any {
	t.Helper()
	path := "/api/v1/datastore/search"
	if query != "" {
		path += "?" + query
	}
	req := httptest.NewRequest("GET", path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))

	data, ok := result["data"].([]any)
	if !ok {
		return nil
	}
	var docs []map[string]any
	for _, d := range data {
		docs = append(docs, d.(map[string]any))
	}
	return docs
}

// mkDoc is a helper to create a CompleteDocument with the given source and scope.
func mkDoc(source, scope, docID string) *model.CompleteDocument {
	return &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: source,
			Scope:           scope,
			DocumentID:      docID,
		},
		IdentityMappingIDs: []string{"id-1"},
		DocumentData:       map[string]any{"test": true},
	}
}

// TestE2E_WildcardAdmin_SeesAllDocuments verifies that an admin with wildcard
// rules sees all documents in the datastore at login.
func TestE2E_WildcardAdmin_SeesAllDocuments(t *testing.T) {
	mock := &e2eMock{
		authenticSources: []string{"SUNET", "LADOK", "CSN"},
		documents: []*model.CompleteDocument{
			mkDoc("SUNET", "eduid", "doc-1"),
			mkDoc("LADOK", "pid", "doc-2"),
			mkDoc("CSN", "ehic", "doc-3"),
		},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
				"ehic":  nil,
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject admin@sunet.se)(authentic_source *)(scope *))`,
	}

	engine := testSetupE2E(t, "admin@sunet.se", rules, cfg, mock)
	cookies, status := e2eLogin(t, engine)

	// Status should show all sources and scopes
	assert.ElementsMatch(t, []any{"SUNET", "LADOK", "CSN"}, status["allowed_authentic_sources"])
	assert.ElementsMatch(t, []any{"eduid", "pid", "ehic"}, status["scopes"])

	// Search should return all documents (wildcard = nil filters = no restriction)
	docs := e2eSearch(t, engine, cookies, "")
	assert.Len(t, docs, 3, "wildcard admin should see all 3 documents")

	// SPOCP filter fields should be nil (unrestricted)
	assert.Nil(t, mock.capturedSearch.AllowedAuthenticSources,
		"wildcard should pass nil AllowedAuthenticSources to DB")
	assert.Nil(t, mock.capturedSearch.AllowedScopes,
		"wildcard should pass nil AllowedScopes to DB")
}

// TestE2E_RestrictedUser_SeesOnlyAllowedDocuments verifies that a user with
// limited SPOCP rules only sees documents matching their permitted sources/scopes.
func TestE2E_RestrictedUser_SeesOnlyAllowedDocuments(t *testing.T) {
	mock := &e2eMock{
		authenticSources: []string{"SUNET", "LADOK", "CSN"},
		documents: []*model.CompleteDocument{
			mkDoc("SUNET", "eduid", "doc-1"),
			mkDoc("SUNET", "pid", "doc-2"),   // wrong scope for alice
			mkDoc("LADOK", "eduid", "doc-3"), // wrong source for alice
			mkDoc("CSN", "ehic", "doc-4"),    // wrong source+scope
		},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
				"ehic":  nil,
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))`,
	}

	engine := testSetupE2E(t, "alice@sunet.se", rules, cfg, mock)
	cookies, status := e2eLogin(t, engine)

	// Status should restrict to SUNET + eduid
	assert.Equal(t, []any{"SUNET"}, status["allowed_authentic_sources"])
	assert.Equal(t, []any{"eduid"}, status["scopes"])

	// Search: only doc-1 (SUNET/eduid) should pass the filter
	docs := e2eSearch(t, engine, cookies, "")
	require.Len(t, docs, 1, "restricted user should see only 1 document")
	meta := docs[0]["meta"].(map[string]any)
	assert.Equal(t, "SUNET", meta["authentic_source"])
	assert.Equal(t, "eduid", meta["scope"])
	assert.Equal(t, "doc-1", meta["document_id"])

	// Verify the filter was passed to the search handler
	assert.Equal(t, []string{"SUNET"}, mock.capturedSearch.AllowedAuthenticSources)
	assert.Equal(t, []string{"eduid"}, mock.capturedSearch.AllowedScopes)
}

// TestE2E_SourceSet_FiltersToSetMembers verifies that a user with a set-style
// rule gets documents from all members of the set.
func TestE2E_SourceSet_FiltersToSetMembers(t *testing.T) {
	mock := &e2eMock{
		authenticSources: []string{"SUNET", "LADOK", "CSN", "SKV"},
		documents: []*model.CompleteDocument{
			mkDoc("SUNET", "eduid", "doc-1"),
			mkDoc("LADOK", "pid", "doc-2"),
			mkDoc("CSN", "ehic", "doc-3"),   // not in source set
			mkDoc("SKV", "eduid", "doc-4"),  // not in source set
			mkDoc("SUNET", "ehic", "doc-5"), // wrong scope
		},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
				"ehic":  nil,
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source (* set SUNET LADOK))(scope (* set eduid pid)))`,
	}

	engine := testSetupE2E(t, "alice@sunet.se", rules, cfg, mock)
	cookies, status := e2eLogin(t, engine)

	// Status
	assert.ElementsMatch(t, []any{"SUNET", "LADOK"}, status["allowed_authentic_sources"])
	assert.ElementsMatch(t, []any{"eduid", "pid"}, status["scopes"])

	// Search: doc-1 (SUNET/eduid) and doc-2 (LADOK/pid) should pass
	docs := e2eSearch(t, engine, cookies, "")
	require.Len(t, docs, 2, "set user should see exactly 2 documents")

	var docIDs []any
	for _, d := range docs {
		meta := d["meta"].(map[string]any)
		docIDs = append(docIDs, meta["document_id"])
	}
	assert.ElementsMatch(t, []any{"doc-1", "doc-2"}, docIDs)
}

// TestE2E_MultipleRules_AccumulateAccess verifies that a user with multiple
// rules gets the union of their access.
func TestE2E_MultipleRules_AccumulateAccess(t *testing.T) {
	mock := &e2eMock{
		authenticSources: []string{"SUNET", "LADOK"},
		documents: []*model.CompleteDocument{
			mkDoc("SUNET", "eduid", "doc-1"),
			mkDoc("LADOK", "pid", "doc-2"),
			mkDoc("SUNET", "pid", "doc-3"),   // SUNET but pid (only LADOK/pid rule)
			mkDoc("LADOK", "eduid", "doc-4"), // LADOK but eduid (only SUNET/eduid rule)
		},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))`,
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source LADOK)(scope pid))`,
	}

	engine := testSetupE2E(t, "alice@sunet.se", rules, cfg, mock)
	cookies, status := e2eLogin(t, engine)

	// Status should accumulate both
	assert.ElementsMatch(t, []any{"SUNET", "LADOK"}, status["allowed_authentic_sources"])
	assert.ElementsMatch(t, []any{"eduid", "pid"}, status["scopes"])

	// Search: AllowedAuthenticSources=[SUNET,LADOK] + AllowedScopes=[eduid,pid]
	// This means the DB filter uses $in for both — so all 4 docs pass the source
	// and scope filters independently (not as pairs). This is the current behavior.
	docs := e2eSearch(t, engine, cookies, "")
	require.Len(t, docs, 4, "multiple rules accumulate independently (source $in + scope $in)")
}

// TestE2E_NoRules_UnrestrictedAccess verifies that when no SPOCP rules exist
// (nil engine), the user has unrestricted access to all documents.
func TestE2E_NoRules_UnrestrictedAccess(t *testing.T) {
	mock := &e2eMock{
		authenticSources: []string{"SUNET"},
		documents: []*model.CompleteDocument{
			mkDoc("SUNET", "eduid", "doc-1"),
			mkDoc("LADOK", "pid", "doc-2"),
		},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
				"pid":   nil,
			},
		},
	}

	engine := testSetupE2E(t, "admin@test", nil, cfg, mock)
	cookies, status := e2eLogin(t, engine)

	// No SPOCP → fetch sources from DB, all scopes configured
	assert.ElementsMatch(t, []any{"SUNET"}, status["allowed_authentic_sources"])
	assert.ElementsMatch(t, []any{"eduid", "pid"}, status["scopes"])

	// Search: no SPOCP engine → no session SPOCP filtering → no filters passed
	docs := e2eSearch(t, engine, cookies, "")
	assert.Len(t, docs, 2, "unrestricted user should see all documents")
	assert.Nil(t, mock.capturedSearch.AllowedAuthenticSources)
	assert.Nil(t, mock.capturedSearch.AllowedScopes)
}

// TestE2E_UnauthenticatedSearch_Rejected verifies that unauthenticated requests
// to the search endpoint are rejected.
func TestE2E_UnauthenticatedSearch_Rejected(t *testing.T) {
	mock := &e2eMock{
		documents: []*model.CompleteDocument{
			mkDoc("SUNET", "eduid", "doc-1"),
		},
	}
	cfg := &model.Cfg{Common: &model.Common{}}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject admin@sunet.se)(authentic_source *)(scope *))`,
	}

	engine := testSetupE2E(t, "admin@sunet.se", rules, cfg, mock)

	// Don't login — hit search directly without cookies
	req := httptest.NewRequest("GET", "/api/v1/datastore/search", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"unauthenticated search should be rejected")
	assert.Nil(t, mock.capturedSearch,
		"search handler should not have been called")
}

// TestE2E_SearchWithQueryParam verifies that the search term from the UI is
// passed through to the backend along with the SPOCP filters.
func TestE2E_SearchWithQueryParam(t *testing.T) {
	mock := &e2eMock{
		authenticSources: []string{"SUNET"},
		documents: []*model.CompleteDocument{
			mkDoc("SUNET", "eduid", "doc-matching"),
		},
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))`,
	}

	engine := testSetupE2E(t, "alice@sunet.se", rules, cfg, mock)
	cookies, _ := e2eLogin(t, engine)

	// Search with a search term
	docs := e2eSearch(t, engine, cookies, "search=doc-matching")
	require.Len(t, docs, 1)

	// Verify both the search term and SPOCP filters were passed
	assert.Equal(t, "doc-matching", mock.capturedSearch.Search)
	assert.Equal(t, []string{"SUNET"}, mock.capturedSearch.AllowedAuthenticSources)
	assert.Equal(t, []string{"eduid"}, mock.capturedSearch.AllowedScopes)
}

// TestE2E_EmptyDatastore_NoDocuments verifies that when the datastore is empty,
// the UI gets an empty list (not null) and the status still populates correctly.
func TestE2E_EmptyDatastore_NoDocuments(t *testing.T) {
	mock := &e2eMock{
		authenticSources: []string{"SUNET"},
		documents:        []*model.CompleteDocument{}, // empty datastore
	}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"eduid": nil,
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))`,
	}

	engine := testSetupE2E(t, "alice@sunet.se", rules, cfg, mock)
	cookies, status := e2eLogin(t, engine)

	// Status should still show sources and scopes (from SPOCP, not from datastore)
	assert.Equal(t, []any{"SUNET"}, status["allowed_authentic_sources"])
	assert.Equal(t, []any{"eduid"}, status["scopes"])

	// Search returns empty
	docs := e2eSearch(t, engine, cookies, "")
	assert.Empty(t, docs, "empty datastore should return no documents")
}
