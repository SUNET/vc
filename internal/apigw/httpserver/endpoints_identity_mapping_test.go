package httpserver

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- identity mapping mock ---

type identityMappingMock struct {
	unimplementedApiv1

	createCalled bool
	createReq    *apiv1.IdentityMappingCreateRequest
	searchCalled bool
	searchReq    *apiv1.IdentityMappingSearchRequest
	deleteCalled bool
	updateCalled bool
}

func (m *identityMappingMock) IdentityMappingCreate(_ context.Context, req *apiv1.IdentityMappingCreateRequest) (*apiv1.IdentityMappingCreateReply, error) {
	m.createCalled = true
	m.createReq = req
	return &apiv1.IdentityMappingCreateReply{AuthenticSourcePersonID: "person-1"}, nil
}

func (m *identityMappingMock) IdentityMappingSearch(_ context.Context, req *apiv1.IdentityMappingSearchRequest) (*apiv1.IdentityMappingSearchReply, error) {
	m.searchCalled = true
	m.searchReq = req
	return &apiv1.IdentityMappingSearchReply{Data: []*model.IdentityMapping{}}, nil
}

func (m *identityMappingMock) IdentityMappingDelete(_ context.Context, _ *apiv1.IdentityMappingDeleteRequest) error {
	m.deleteCalled = true
	return nil
}

func (m *identityMappingMock) IdentityMappingUpdate(_ context.Context, _ *apiv1.IdentityMappingUpdateRequest) error {
	m.updateCalled = true
	return nil
}

// --- test setup with identity mapping routes ---

func testSetupIdentityMapping(t *testing.T, rules []string, mockAPI Apiv1) (*gin.Engine, *ecdsa.PrivateKey) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common: &model.Common{},
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	priv, pubSet := generateKeyPair(t)

	raw, err := json.Marshal(pubSet)
	require.NoError(t, err)
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(jwksSrv.Close)

	cache := newJWKSCache()
	cache.Set(ctx, jwksSrv.URL, raw)

	apiAuth := model.APIAuth{
		Rules: rules,
		JWKS: model.APIAuthJWKS{
			Enable:   true,
			JWKSURL:  jwksSrv.URL,
			Issuer:   "https://test-issuer",
			Audience: "test-audience",
		},
	}

	apiAuthMiddleware, err := helpers.Middleware.APIAuth(ctx, "apigw", apiAuth, cache)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       mockAPI,
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()

	store := cookie.NewStore([]byte("test-auth-key-32-bytes-long!!!!"), []byte("test-enc-key-32-bytes-long!!!!!"))
	store.Options(sessions.Options{Path: "/", MaxAge: 900, HttpOnly: true})

	rg := engine.Group("/api/v1")
	rg.Use(sessions.Sessions("admin_session", store))
	rg.Use(helpers.Middleware.SessionOrAPIAuth(adminSessionKey, apiAuthMiddleware, nil, "apigw"))

	// Identity mapping routes matching production service.go
	rgIdentity := rg.Group("/identity")
	helpers.Server.RegEndpoint(ctx, rgIdentity, http.MethodPost, "/mapping", http.StatusOK, s.endpointIdentityMappingCreate)
	helpers.Server.RegEndpoint(ctx, rgIdentity, http.MethodGet, "/mapping/search", http.StatusOK, s.endpointIdentityMappingSearch)
	helpers.Server.RegEndpoint(ctx, rgIdentity, http.MethodDelete, "/mapping", http.StatusOK, s.endpointIdentityMappingDelete)
	helpers.Server.RegEndpoint(ctx, rgIdentity, http.MethodPut, "/mapping", http.StatusOK, s.endpointIdentityMappingUpdate)

	// Also register datastore for mixed tests
	rgDatastore := rg.Group("/datastore")
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodGet, "/search", http.StatusOK, s.endpointDatastoreSearch)

	return engine, priv
}

func testSetupIdentityMappingNoAuth(t *testing.T, mockAPI Apiv1) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common: &model.Common{},
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	apiAuth := model.APIAuth{} // no auth

	apiAuthMiddleware, err := helpers.Middleware.APIAuth(ctx, "apigw", apiAuth, nil)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       mockAPI,
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()

	store := cookie.NewStore([]byte("test-auth-key-32-bytes-long!!!!!"), []byte("test-enc-key-32-bytes-long!!!!!!"))
	store.Options(sessions.Options{Path: "/", MaxAge: 900, HttpOnly: true})

	rg := engine.Group("/api/v1")
	rg.Use(sessions.Sessions("admin_session", store))
	rg.Use(helpers.Middleware.SessionOrAPIAuth(adminSessionKey, apiAuthMiddleware, nil, "apigw"))

	rgIdentity := rg.Group("/identity")
	helpers.Server.RegEndpoint(ctx, rgIdentity, http.MethodPost, "/mapping", http.StatusOK, s.endpointIdentityMappingCreate)
	helpers.Server.RegEndpoint(ctx, rgIdentity, http.MethodGet, "/mapping/search", http.StatusOK, s.endpointIdentityMappingSearch)
	helpers.Server.RegEndpoint(ctx, rgIdentity, http.MethodDelete, "/mapping", http.StatusOK, s.endpointIdentityMappingDelete)
	helpers.Server.RegEndpoint(ctx, rgIdentity, http.MethodPut, "/mapping", http.StatusOK, s.endpointIdentityMappingUpdate)

	return engine
}

// ==================== Identity Mapping — with SPOCP rules ====================

// TestIdentityMappingCreate_SPOCPAllowed verifies that a user with a matching
// SPOCP rule (including the synthetic identity_mapping scope) can create a mapping.
func TestIdentityMappingCreate_SPOCPAllowed(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method POST)(path /api/v1/identity/mapping)(subject alice)(authentic_source SUNET)(scope identity_mapping))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	body := map[string]any{"authentic_source": "SUNET", "attributes": map[string]string{"eppn": "alice@sunet.se"}}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", token, body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.createCalled)
}

// TestIdentityMappingCreate_SPOCPDenied verifies that a user whose SPOCP rule
// doesn't match the requested authentic_source gets 403.
func TestIdentityMappingCreate_SPOCPDenied(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		// alice is only allowed for authentic_source LADOK
		`(vc (service apigw)(method POST)(path /api/v1/identity/mapping)(subject alice)(authentic_source LADOK)(scope identity_mapping))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	// Request for SUNET → should be denied
	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	body := map[string]any{"authentic_source": "SUNET", "attributes": map[string]string{"eppn": "alice@sunet.se"}}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", token, body)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.createCalled)
}

// TestIdentityMappingCreate_SPOCPWrongSubject verifies that a different user is denied.
func TestIdentityMappingCreate_SPOCPWrongSubject(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method POST)(path /api/v1/identity/mapping)(subject alice)(authentic_source SUNET)(scope identity_mapping))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "bob", "https://test-issuer", "test-audience")
	body := map[string]any{"authentic_source": "SUNET", "attributes": map[string]string{"eppn": "bob@sunet.se"}}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", token, body)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.createCalled)
}

// TestIdentityMappingCreate_SPOCPWildcardScope verifies that a rule with
// scope wildcard also matches identity_mapping (the synthetic scope).
func TestIdentityMappingCreate_SPOCPWildcardScope(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		// Wildcard scope should match the synthetic identity_mapping scope
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice)(authentic_source SUNET)(scope *))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	body := map[string]any{"authentic_source": "SUNET", "attributes": map[string]string{"eppn": "alice@sunet.se"}}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", token, body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.createCalled)
}

// TestIdentityMappingCreate_SPOCPScopeSet verifies that a rule with a scope set
// containing identity_mapping allows the request.
func TestIdentityMappingCreate_SPOCPScopeSet(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice)(authentic_source SUNET)(scope (* set eduid identity_mapping)))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	body := map[string]any{"authentic_source": "SUNET", "attributes": map[string]string{"eppn": "alice@sunet.se"}}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", token, body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.createCalled)
}

// TestIdentityMappingCreate_SPOCPScopeSetMissing verifies that a scope set
// without identity_mapping denies access to identity mapping endpoints.
func TestIdentityMappingCreate_SPOCPScopeSetMissing(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		// Scope set doesn't include identity_mapping
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice)(authentic_source SUNET)(scope (* set eduid pid)))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	body := map[string]any{"authentic_source": "SUNET", "attributes": map[string]string{"eppn": "alice@sunet.se"}}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", token, body)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.createCalled)
}

// TestIdentityMappingDelete_SPOCPAllowed verifies DELETE mapping with matching rules.
func TestIdentityMappingDelete_SPOCPAllowed(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject admin)(authentic_source *)(scope *))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "admin", "https://test-issuer", "test-audience")
	// DELETE with query params: authentic_source triggers resource pair extraction
	w := doRequest(engine, "DELETE", "/api/v1/identity/mapping?authentic_source=SUNET&authentic_source_person_id=person-1", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.deleteCalled)
}

// TestIdentityMappingSearch_SPOCPAllowed verifies search passes with matching SPOCP rules.
func TestIdentityMappingSearch_SPOCPAllowed(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/identity/mapping/search)(subject alice)(authentic_source (* set SUNET LADOK))(scope *))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/identity/mapping/search?search=test&authentic_source=SUNET", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
	// AllowedAuthenticSources should be populated from SPOCP
	assert.NotNil(t, mock.searchReq)
	assert.ElementsMatch(t, []string{"SUNET", "LADOK"}, mock.searchReq.AllowedAuthenticSources,
		"SPOCP-derived AllowedAuthenticSources should be forwarded to the search request")
}

// TestIdentityMappingSearch_SPOCPDenied verifies search with non-matching SPOCP rules.
func TestIdentityMappingSearch_SPOCPDenied(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/identity/mapping/search)(subject alice)(authentic_source SUNET)(scope *))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	// bob has no SPOCP rule → request with authentic_source triggers denial
	token := signTestJWT(t, priv, "bob", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/identity/mapping/search?authentic_source=SUNET", token, nil)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.searchCalled)
}

// ==================== Identity Mapping — without SPOCP rules ====================

// TestIdentityMappingCreate_NoRules_AuthOnly verifies that without SPOCP rules
// any authenticated user can create mappings (auth-only mode).
func TestIdentityMappingCreate_NoRules_AuthOnly(t *testing.T) {
	mock := &identityMappingMock{}
	// No SPOCP rules — authentication only
	engine, priv := testSetupIdentityMapping(t, nil, mock)

	token := signTestJWT(t, priv, "anyone", "https://test-issuer", "test-audience")
	body := map[string]any{"authentic_source": "SUNET", "attributes": map[string]string{"eppn": "anyone@sunet.se"}}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", token, body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.createCalled)
}

// TestIdentityMappingCreate_NoAuth verifies that without any token, the request is rejected.
func TestIdentityMappingCreate_NoAuth(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method POST)(path /api/v1/identity/mapping)(subject alice)(authentic_source SUNET)(scope identity_mapping))`,
	}
	engine, _ := testSetupIdentityMapping(t, rules, mock)

	body := map[string]any{"authentic_source": "SUNET"}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", "", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.createCalled)
}

// TestIdentityMappingSearch_NoRules_AuthOnly verifies search without SPOCP rules.
func TestIdentityMappingSearch_NoRules_AuthOnly(t *testing.T) {
	mock := &identityMappingMock{}
	engine, priv := testSetupIdentityMapping(t, nil, mock)

	token := signTestJWT(t, priv, "anyone", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/identity/mapping/search?search=test", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
	// Without SPOCP rules, AllowedAuthenticSources should be empty
	assert.Empty(t, mock.searchReq.AllowedAuthenticSources,
		"without SPOCP rules, AllowedAuthenticSources should be empty (no filtering)")
}

// TestIdentityMapping_NoAuthMode verifies no-auth mode lets everything through.
func TestIdentityMapping_NoAuthMode(t *testing.T) {
	mock := &identityMappingMock{}
	engine := testSetupIdentityMappingNoAuth(t, mock)

	body := map[string]any{"authentic_source": "SUNET", "attributes": map[string]string{"eppn": "anon@sunet.se"}}
	w := doRequest(engine, "POST", "/api/v1/identity/mapping", "", body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.createCalled)
}

// ==================== SPOCP context forwarding ====================

// TestDatastoreSearch_SPOCPContextForwarding verifies that the middleware
// populates both AllowedAuthenticSources and AllowedScopes on the search request.
func TestDatastoreSearch_SPOCPContextForwarding(t *testing.T) {
	// Use a combined mock that captures both datastore search requests
	dsMock := &mockApiv1{}
	rules := []string{
		// alice has access to SUNET/eduid and SUNET/pid
		`(vc (service apigw)(method GET)(path /api/v1/*)(subject alice)(authentic_source SUNET)(scope (* set eduid pid)))`,
	}
	engine, priv := testSetup(t, rules, dsMock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?search=test", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	require.True(t, dsMock.searchCalled)
	require.NotNil(t, dsMock.searchReq)

	// The middleware should have extracted AllowedAuthenticSources and AllowedScopes
	// from the SPOCP engine and set them in the gin context.
	assert.Equal(t, []string{"SUNET"}, dsMock.searchReq.AllowedAuthenticSources,
		"AllowedAuthenticSources should be populated from SPOCP rules")
	assert.ElementsMatch(t, []string{"eduid", "pid"}, dsMock.searchReq.AllowedScopes,
		"AllowedScopes should be populated from SPOCP scope set")
}

// TestDatastoreSearch_SPOCPContextForwarding_WildcardSource verifies that
// a wildcard authentic_source rule results in ["*"] being forwarded.
func TestDatastoreSearch_SPOCPContextForwarding_WildcardSource(t *testing.T) {
	dsMock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/*)(subject admin)(authentic_source *)(scope *))`,
	}
	engine, priv := testSetup(t, rules, dsMock)

	token := signTestJWT(t, priv, "admin", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?search=test", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	require.True(t, dsMock.searchCalled)
	require.NotNil(t, dsMock.searchReq)

	// Wildcard authentic_source/scope → AllowedAuthenticSources/AllowedScopes = nil
	// (nil means "unrestricted" — the DB layer won't apply any filter)
	assert.Nil(t, dsMock.searchReq.AllowedAuthenticSources,
		"wildcard authentic_source should result in nil (unrestricted)")
	assert.Nil(t, dsMock.searchReq.AllowedScopes,
		"wildcard scope should result in nil (unrestricted)")
}

// TestDatastoreSearch_NoRules_NoContextForwarding verifies that without SPOCP rules
// AllowedAuthenticSources and AllowedScopes are not set.
func TestDatastoreSearch_NoRules_NoContextForwarding(t *testing.T) {
	dsMock := &mockApiv1{}
	engine, priv := testSetup(t, nil, dsMock) // no rules

	token := signTestJWT(t, priv, "anyone", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?search=test", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	require.True(t, dsMock.searchCalled)
	require.NotNil(t, dsMock.searchReq)

	assert.Empty(t, dsMock.searchReq.AllowedAuthenticSources,
		"without SPOCP rules, AllowedAuthenticSources should be empty")
	assert.Empty(t, dsMock.searchReq.AllowedScopes,
		"without SPOCP rules, AllowedScopes should be empty")
}

// TestIdentityMappingSearch_SPOCPContextForwarding verifies that the middleware
// forwards AllowedAuthenticSources to identity mapping search.
func TestIdentityMappingSearch_SPOCPContextForwarding(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice)(authentic_source (* set SUNET LADOK))(scope *))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/identity/mapping/search?search=test", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	require.True(t, mock.searchCalled)
	require.NotNil(t, mock.searchReq)

	assert.ElementsMatch(t, []string{"SUNET", "LADOK"}, mock.searchReq.AllowedAuthenticSources,
		"AllowedAuthenticSources should contain the SPOCP source set elements")
}

// TestIdentityMappingSearch_SPOCPDenied_NoIdentityMappingScope verifies that a user
// whose SPOCP rules only grant a credential scope (e.g. pid) cannot list
// identity mappings.
func TestIdentityMappingSearch_SPOCPDenied_NoIdentityMappingScope(t *testing.T) {
	mock := &identityMappingMock{}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject bob)(authentic_source SUNET)(scope pid))`,
	}
	engine, priv := testSetupIdentityMapping(t, rules, mock)

	token := signTestJWT(t, priv, "bob", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/identity/mapping/search?search=test", token, nil)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.searchCalled, "search should be denied when user lacks identity_mapping scope")
}

// ==================== Cross-scope isolation ====================

// TestUploadDenied_WrongScope verifies that a user with scope "eduid" cannot
// upload a document with scope "pid".
func TestUploadDenied_WrongScope(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		// alice can only upload eduid documents
		`(vc (service apigw)(method POST)(path /api/v1/datastore)(subject alice)(authentic_source SUNET)(scope eduid))`,
	}
	engine, priv := testSetup(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	body := map[string]any{
		"meta":                 map[string]any{"authentic_source": "SUNET", "scope": "pid", "document_id": "doc1"},
		"identity_mapping_ids": []string{"id1"},
		"document_data":        map[string]any{"key": "value"},
	}
	w := doRequest(engine, "POST", "/api/v1/datastore", token, body)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.uploadCalled, "upload should be denied for wrong scope")
}

// TestUploadDenied_WrongAuthenticSource verifies that a user with authentic_source
// "SUNET" cannot upload a document with authentic_source "LADOK".
func TestUploadDenied_WrongAuthenticSource(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method POST)(path /api/v1/datastore)(subject alice)(authentic_source SUNET)(scope eduid))`,
	}
	engine, priv := testSetup(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	body := map[string]any{
		"meta":                 map[string]any{"authentic_source": "LADOK", "scope": "eduid", "document_id": "doc1"},
		"identity_mapping_ids": []string{"id1"},
		"document_data":        map[string]any{"key": "value"},
	}
	w := doRequest(engine, "POST", "/api/v1/datastore", token, body)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.uploadCalled, "upload should be denied for wrong authentic_source")
}
