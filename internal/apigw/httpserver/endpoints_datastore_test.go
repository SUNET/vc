package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test helpers ---

type jwksCache struct {
	store map[string][]byte
}

func newJWKSCache() *jwksCache { return &jwksCache{store: map[string][]byte{}} }
func (c *jwksCache) Get(_ context.Context, key string) ([]byte, bool) {
	v, ok := c.store[key]
	return v, ok
}
func (c *jwksCache) Set(_ context.Context, key string, value []byte) { c.store[key] = value }

func generateKeyPair(t *testing.T) (*ecdsa.PrivateKey, jwk.Set) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(priv.Public())
	require.NoError(t, err)
	require.NoError(t, pubJWK.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, pubJWK.Set(jwk.AlgorithmKey, jwa.ES256()))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubJWK))

	return priv, set
}

func signTestJWT(t *testing.T, priv *ecdsa.PrivateKey, eppn, iss, aud string) string {
	t.Helper()
	privJWK, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.ES256()))

	tok, err := jwxjwt.NewBuilder().
		Subject("12312312345").
		Issuer(iss).
		Audience([]string{aud}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5*time.Minute)).
		Claim("eppn", eppn).
		Build()
	require.NoError(t, err)

	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.ES256(), privJWK))
	require.NoError(t, err)
	return string(signed)
}

// testSetup creates a gin engine with session + SPOCP + JWKS middleware protecting
// a datastore group, wired to the given mock apiv1.
func testSetup(t *testing.T, rules []string, mockAPI Apiv1) (*gin.Engine, *ecdsa.PrivateKey) {
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

	// Serve the JWKS from a test server
	raw, err := json.Marshal(pubSet)
	require.NoError(t, err)
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(jwksSrv.Close)

	// Pre-seed the cache so no network fetch is needed
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

	// Set up session + auth middleware matching production
	store := cookie.NewStore([]byte("test-auth-key-32-bytes-long!!!!"), []byte("test-enc-key-32-bytes-long!!!!!"))
	store.Options(sessions.Options{Path: "/", MaxAge: 900, HttpOnly: true})

	rg := engine.Group("/api/v1")
	rg.Use(sessions.Sessions("admin_session", store))
	rg.Use(helpers.Middleware.SessionOrAPIAuth(adminSessionKey, apiAuthMiddleware, nil, "apigw"))

	rgDatastore := rg.Group("/datastore")
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodPost, "", http.StatusOK, s.endpointDatastoreUpload)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodGet, "", http.StatusOK, s.endpointDatastoreGet)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodGet, "/search", http.StatusOK, s.endpointDatastoreSearch)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodDelete, "", http.StatusNoContent, s.endpointDatastoreDelete)

	return engine, priv
}

func doRequest(engine *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// --- mock apiv1 ---

// unimplementedApiv1 satisfies the Apiv1 interface with methods that panic if called.
// Embed in test mocks to only override the methods under test.
type unimplementedApiv1 struct{}

func (u unimplementedApiv1) DatastoreUpload(context.Context, *vcclient.UploadRequest) (*apiv1.DatastoreUploadReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreAddIdentity(context.Context, *apiv1.DatastoreAddIdentityRequest) error {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreDeleteIdentity(context.Context, *apiv1.DatastoreDeleteIdentityRequest) error {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreGet(context.Context, *apiv1.DatastoreGetRequest) (*apiv1.DatastoreGetReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreList(context.Context, *apiv1.DatastoreListRequest) (*apiv1.DatastoreListReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreDelete(context.Context, *apiv1.DatastoreDeleteRequest) error {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreGetByKey(context.Context, *apiv1.DatastoreGetByKeyRequest) (*apiv1.DatastoreGetByKeyReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreResolve(context.Context, *apiv1.DatastoreResolveRequest) (*apiv1.DatastoreResolveReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreDeleteByKey(context.Context, *apiv1.DatastoreDeleteByKeyRequest) error {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreReplace(context.Context, *vcclient.UploadRequest) error {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreSearch(context.Context, *apiv1.DatastoreSearchRequest) (*apiv1.DatastoreSearchReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) DatastoreBulkUpload(context.Context, *apiv1.DatastoreBulkUploadRequest) (*apiv1.DatastoreBulkUploadReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) IdentityMappingCreate(context.Context, *apiv1.IdentityMappingCreateRequest) (*apiv1.IdentityMappingCreateReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) IdentityMappingBulkCreate(context.Context, *apiv1.IdentityMappingBulkCreateRequest) (*apiv1.IdentityMappingBulkCreateReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) IdentityMappingResolve(context.Context, *apiv1.IdentityMappingResolveRequest) (*apiv1.IdentityMappingResolveReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) IdentityMappingUpdate(context.Context, *apiv1.IdentityMappingUpdateRequest) error {
	panic("not implemented")
}

func (u unimplementedApiv1) IdentityMappingDelete(context.Context, *apiv1.IdentityMappingDeleteRequest) error {
	panic("not implemented")
}

func (u unimplementedApiv1) IdentityMappingSearch(context.Context, *apiv1.IdentityMappingSearchRequest) (*apiv1.IdentityMappingSearchReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) UserAuthenticSourceLookup(context.Context, *vcclient.UserAuthenticSourceLookupRequest) (*vcclient.UserAuthenticSourceLookupReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) UserLookup(context.Context, *vcclient.UserLookupRequest) (*vcclient.UserLookupReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) VCINonce(context.Context) (*openid4vci.NonceResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) VCICredential(context.Context, *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) VCICredentialOfferURI(context.Context, *openid4vci.CredentialOfferURIRequest) (*openid4vci.CredentialOfferParameters, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) VCIDeferredCredential(context.Context, *openid4vci.DeferredCredentialRequest) (*openid4vci.CredentialResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) VCINotification(context.Context, *openid4vci.NotificationRequest) error {
	panic("not implemented")
}

func (u unimplementedApiv1) VCIMetadata(context.Context) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) OAuthPar(context.Context, *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) OAuthAuthorize(context.Context, *openid4vci.AuthorizeRequest) (*openid4vci.AuthorizationResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) OAuthAuthorizationConsent(context.Context, *apiv1.OauthAuthorizationConsentRequest) (*apiv1.OAuthAuthorizationConsentResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) OAuthAuthorizationConsentCallback(context.Context, *apiv1.OauthAuthorizationConsentCallbackRequest) (*apiv1.OAuthAuthorizationConsentCallbackResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) OAuthToken(context.Context, *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) OAuthMetadata(context.Context) (*oauth2.AuthorizationServerMetadata, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) JWKS(context.Context) (*apiv1.JWKSResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) SDJWTVCIssuerMetadata(context.Context) (*apiv1.SDJWTVCIssuerMetadataResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) VerificationRequestObject(context.Context, *apiv1.VerificationRequestObjectRequest) (string, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) VerificationDirectPost(context.Context, *apiv1.VerificationDirectPostRequest) (*apiv1.VerificationDirectPostResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) UICredentialOffers(context.Context) (*apiv1.CredentialOfferLookupMetadata, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) UICreateCredentialOffer(context.Context, *apiv1.UICredentialOfferRequest) (*apiv1.CredentialOfferReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) GetVCTMFromScope(context.Context, *apiv1.GetVCTMFromScopeRequest) (*sdjwtvc.VCTM, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) GetMDDLFromScope(context.Context, *apiv1.GetMDDLFromScopeRequest) (*mdoc.MDDLSchema, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) SVGTemplateReply(context.Context, *apiv1.SVGTemplateRequest) (*vcclient.SVGTemplateReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) TypeMetadata(context.Context, *apiv1.TypeMetadataRequest) (json.RawMessage, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) OIDCRPInitiate(context.Context, *apiv1.OIDCRPInitiateRequest, any) (*apiv1.OIDCRPInitiateResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) OIDCRPCallback(context.Context, *apiv1.OIDCRPCallbackRequest, any) (*apiv1.OIDCRPCallbackResponse, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) StoreVCIDocuments(context.Context, string, map[string]*model.CompleteDocument) error {
	panic("not implemented")
}

func (u unimplementedApiv1) HasVCIDocuments(context.Context, string) bool {
	panic("not implemented")
}

func (u unimplementedApiv1) LookupDatastoreByIdentity(context.Context, string, string, string, map[string]any, *model.DatastoreScope) error {
	panic("not implemented")
}

func (u unimplementedApiv1) ResolveIdentifier(context.Context, string, map[string]any) (string, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) ResolveVCIIdentifier(context.Context, *cache.AuthorizationContext, map[string]any, ...string) (string, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) AdminLoginURL(context.Context) (*apiv1.AdminLoginURLReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) AdminCallback(context.Context, *apiv1.AdminCallbackRequest) (*apiv1.AdminCallbackReply, error) {
	panic("not implemented")
}

func (u unimplementedApiv1) AdminLogoutURL(context.Context, string) string {
	panic("not implemented")
}

func (u unimplementedApiv1) ListAuthenticSources(context.Context) ([]string, error) {
	return nil, nil
}

func (u unimplementedApiv1) Health(context.Context, *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	panic("not implemented")
}

// mockApiv1 embeds unimplementedApiv1 and overrides only the methods under test
type mockApiv1 struct {
	unimplementedApiv1
	searchCalled bool
	searchReq    *apiv1.DatastoreSearchRequest
	uploadCalled bool
}

func (m *mockApiv1) DatastoreSearch(_ context.Context, req *apiv1.DatastoreSearchRequest) (*apiv1.DatastoreSearchReply, error) {
	m.searchCalled = true
	m.searchReq = req
	return &apiv1.DatastoreSearchReply{Data: []*model.CompleteDocument{}}, nil
}

func (m *mockApiv1) DatastoreUpload(_ context.Context, _ *vcclient.UploadRequest) (*apiv1.DatastoreUploadReply, error) {
	m.uploadCalled = true
	return &apiv1.DatastoreUploadReply{DocumentID: "test-doc-id"}, nil
}

func (m *mockApiv1) DatastoreGet(_ context.Context, _ *apiv1.DatastoreGetRequest) (*apiv1.DatastoreGetReply, error) {
	return &apiv1.DatastoreGetReply{}, nil
}

func (m *mockApiv1) DatastoreDelete(_ context.Context, _ *apiv1.DatastoreDeleteRequest) error {
	return nil
}

func (m *mockApiv1) DatastoreDeleteByKey(_ context.Context, _ *apiv1.DatastoreDeleteByKeyRequest) error {
	return nil
}

func (m *mockApiv1) AdminLoginURL(_ context.Context) (*apiv1.AdminLoginURLReply, error) {
	return &apiv1.AdminLoginURLReply{}, nil
}

// --- tests ---

func TestDatastoreSearch_NoAuth_Returns401(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, _ := testSetup(t, rules, mock)

	w := doRequest(engine, "GET", "/api/v1/datastore/search", "", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestDatastoreSearch_ValidJWT_SPOCPAllowed(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, priv := testSetup(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?search=test", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
}

func TestDatastoreSearch_ValidJWT_SPOCPDenied(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		// Only bob is allowed
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject bob)(authentic_source SUNET)(scope eduid))`,
	}
	engine, priv := testSetup(t, rules, mock)

	// alice sends a request with resource pair → SPOCP denies
	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?search=test&authentic_source=SUNET&scope=eduid", token, nil)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestDatastoreSearch_ValidJWT_WildcardSubject(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path (* prefix /api/v1/))(subject (*))(authentic_source *)(scope *))`,
	}
	engine, priv := testSetup(t, rules, mock)

	token := signTestJWT(t, priv, "anyone", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
}

func TestDatastoreSearch_InvalidToken_Returns401(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, _ := testSetup(t, rules, mock)

	w := doRequest(engine, "GET", "/api/v1/datastore/search", "invalid.jwt.token", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestDatastoreSearch_ExpiredToken_Returns401(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, priv := testSetup(t, rules, mock)

	// Create an expired token
	privJWK, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.ES256()))

	tok, err := jwxjwt.NewBuilder().
		Subject("alice").
		Issuer("https://test-issuer").
		Audience([]string{"test-audience"}).
		IssuedAt(time.Now().Add(-10 * time.Minute)).
		Expiration(time.Now().Add(-5 * time.Minute)).
		Build()
	require.NoError(t, err)

	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.ES256(), privJWK))
	require.NoError(t, err)

	w := doRequest(engine, "GET", "/api/v1/datastore/search", string(signed), nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestDatastoreUpload_SPOCPMethodMismatch(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		// Only GET is allowed, not POST
		`(vc (service apigw)(method GET)(path /api/v1/datastore)(subject alice)(authentic_source TEST)(scope test))`,
	}
	engine, priv := testSetup(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	body := map[string]any{
		"meta":                 map[string]any{"authentic_source": "TEST", "scope": "test", "document_id": "doc1"},
		"identity_mapping_ids": []string{"id1"},
		"document_data":        map[string]any{"key": "value"},
	}
	w := doRequest(engine, "POST", "/api/v1/datastore", token, body)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.uploadCalled)
}

func TestDatastoreUpload_SPOCPAllowed(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method POST)(path /api/v1/datastore)(subject api-client)(authentic_source TEST)(scope test))`,
	}
	engine, priv := testSetup(t, rules, mock)

	token := signTestJWT(t, priv, "api-client", "https://test-issuer", "test-audience")
	body := map[string]any{
		"meta":                 map[string]any{"authentic_source": "TEST", "scope": "test", "document_id": "doc1"},
		"identity_mapping_ids": []string{"id1"},
		"document_data":        map[string]any{"key": "value"},
	}
	w := doRequest(engine, "POST", "/api/v1/datastore", token, body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.uploadCalled)
}

func TestDatastoreDelete_SPOCPAllowed(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method DELETE)(path /api/v1/datastore)(subject admin)(authentic_source TEST)(scope test))`,
	}
	engine, priv := testSetup(t, rules, mock)

	token := signTestJWT(t, priv, "admin", "https://test-issuer", "test-audience")
	w := doRequest(engine, "DELETE", "/api/v1/datastore?authentic_source=TEST&scope=test&document_id=doc1", token, nil)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDatastoreSearch_NoSPOCPRules_AuthOnly(t *testing.T) {
	mock := &mockApiv1{}
	// No SPOCP rules — authentication-only mode
	engine, priv := testSetup(t, nil, mock)

	token := signTestJWT(t, priv, "anyone", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
}

func TestDatastoreSearch_WrongIssuer_Returns401(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, priv := testSetup(t, rules, mock)

	// Token signed with correct key but wrong issuer
	token := signTestJWT(t, priv, "alice", "https://wrong-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search", token, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestDatastoreSearch_WrongAudience_Returns401(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, priv := testSetup(t, rules, mock)

	// Token with wrong audience
	token := signTestJWT(t, priv, "alice", "https://test-issuer", "wrong-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search", token, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestDatastoreSearch_SPOCPPathPrefix(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		// Allow all paths under /api/v1/datastore for alice
		`(vc (service apigw)(method GET)(path (* prefix /api/v1/datastore))(subject alice)(authentic_source *)(scope *))`,
	}
	engine, priv := testSetup(t, rules, mock)

	token := signTestJWT(t, priv, "alice", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?search=foo", token, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
}

func TestDatastoreSearch_SPOCPSubjectSet(t *testing.T) {
	mock := &mockApiv1{}
	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject (* set alice bob carol))(authentic_source *)(scope *))`,
	}
	engine, priv := testSetup(t, rules, mock)

	// Bob is in the set — request with resource pair to trigger SPOCP check
	token := signTestJWT(t, priv, "bob", "https://test-issuer", "test-audience")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?authentic_source=SUNET&scope=eduid", token, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	// Eve is not in the set
	mock.searchCalled = false
	token = signTestJWT(t, priv, "eve", "https://test-issuer", "test-audience")
	w = doRequest(engine, "GET", "/api/v1/datastore/search?authentic_source=SUNET&scope=eduid", token, nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.searchCalled)
}

// --- OIDC discovery mode tests using mockoidc ---

// testSetupOIDC creates a gin engine with OIDC discovery mode middleware.
// It starts a real mock OIDC server and configures the middleware to discover
// JWKS from it. Returns the engine and the mock OIDC server (for signing tokens).
func testSetupOIDC(t *testing.T, rules []string, mockAPI Apiv1) (*gin.Engine, *mockoidc.MockOIDC) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	m, err := mockoidc.Run()
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown() })

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

	// Fetch JWKS from the mock server and pre-seed the cache
	resp, err := http.Get(m.JWKSEndpoint())
	require.NoError(t, err)
	defer resp.Body.Close()
	var jwksBytes []byte
	jwksBytes, err = json.Marshal(json.RawMessage(mustReadAll(t, resp.Body)))
	require.NoError(t, err)

	cache := newJWKSCache()
	cache.Set(ctx, m.JWKSEndpoint(), jwksBytes)

	apiAuth := model.APIAuth{
		Rules: rules,
		OIDC: model.APIAuthOIDC{
			Enable:    true,
			IssuerURL: m.Issuer(),
			Audience:  m.ClientID,
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

	rgDatastore := rg.Group("/datastore")
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodPost, "", http.StatusOK, s.endpointDatastoreUpload)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodGet, "", http.StatusOK, s.endpointDatastoreGet)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodGet, "/search", http.StatusOK, s.endpointDatastoreSearch)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodDelete, "", http.StatusNoContent, s.endpointDatastoreDelete)

	return engine, m
}

// signMockOIDCToken creates a JWT signed by the mock OIDC server's keypair
// with the given eppn as the identity claim
func signMockOIDCToken(t *testing.T, m *mockoidc.MockOIDC, eppn string) string {
	t.Helper()
	type oidcClaims struct {
		jwt.RegisteredClaims
		EPPN string `json:"eppn"`
	}
	claims := &oidcClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.Issuer(),
			Subject:   "opaque-id",
			Audience:  jwt.ClaimStrings{m.ClientID},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		EPPN: eppn,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.Keypair.Kid
	signed, err := token.SignedString(m.Keypair.PrivateKey)
	require.NoError(t, err)
	return signed
}

// signMockOIDCTokenSubOnly creates a JWT with only standard claims (no eppn/email)
func signMockOIDCTokenSubOnly(t *testing.T, m *mockoidc.MockOIDC, sub string) string {
	t.Helper()
	claims := &jwt.RegisteredClaims{
		Issuer:    m.Issuer(),
		Subject:   sub,
		Audience:  jwt.ClaimStrings{m.ClientID},
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.Keypair.Kid
	signed, err := token.SignedString(m.Keypair.PrivateKey)
	require.NoError(t, err)
	return signed
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return b
}

func TestOIDC_SearchAuthorized(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	token := signMockOIDCToken(t, m, "alice")
	w := doRequest(engine, "GET", "/api/v1/datastore/search", token, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
}

func TestOIDC_SearchForbidden(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	// eve is not authorized — include resource pair to trigger SPOCP check
	token := signMockOIDCToken(t, m, "eve")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?authentic_source=SUNET&scope=eduid", token, nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestOIDC_Upload(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method POST)(path /api/v1/datastore)(subject api-client)(authentic_source test)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	token := signMockOIDCToken(t, m, "api-client")
	body := map[string]any{
		"meta":                 map[string]any{"authentic_source": "test", "scope": "test", "document_id": "doc1"},
		"identity_mapping_ids": []string{"id1"},
		"document_data":        map[string]any{"key": "value"},
	}
	w := doRequest(engine, "POST", "/api/v1/datastore", token, body)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.uploadCalled)
}

func TestOIDC_InvalidToken(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, _ := testSetupOIDC(t, rules, mock)

	w := doRequest(engine, "GET", "/api/v1/datastore/search", "not-a-valid-jwt", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestOIDC_ExpiredToken(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	// Create an expired token
	claims := &jwt.RegisteredClaims{
		Issuer:    m.Issuer(),
		Subject:   "alice",
		Audience:  jwt.ClaimStrings{m.ClientID},
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.Keypair.Kid
	signed, err := token.SignedString(m.Keypair.PrivateKey)
	require.NoError(t, err)

	w := doRequest(engine, "GET", "/api/v1/datastore/search", signed, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestOIDC_WrongAudience(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice)(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	// Token with wrong audience
	claims := &jwt.RegisteredClaims{
		Issuer:    m.Issuer(),
		Subject:   "alice",
		Audience:  jwt.ClaimStrings{"wrong-audience"},
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.Keypair.Kid
	signed, err := token.SignedString(m.Keypair.PrivateKey)
	require.NoError(t, err)

	w := doRequest(engine, "GET", "/api/v1/datastore/search", signed, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, mock.searchCalled)
}

func TestOIDC_WildcardSubject(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject (*))(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	// Any subject should be accepted
	token := signMockOIDCToken(t, m, "anyone")
	w := doRequest(engine, "GET", "/api/v1/datastore/search", token, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
}

// TestOIDC_RealisticOpaqueSubject verifies that the API auth middleware
// extracts the SPOCP subject from eppn/email claims (not the opaque "sub").
// A realistic OIDC token has an opaque UUID as "sub" and the human-readable
// identity in "eppn" or "email"
func TestOIDC_RealisticOpaqueSubject(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		// Rule targets the user's email
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice@sunet.se)(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	// Create a realistic OIDC token: opaque sub, human identity in eppn/email claims
	type oidcClaims struct {
		jwt.RegisteredClaims
		Email string `json:"email"`
		EPPN  string `json:"eppn"`
	}
	claims := &oidcClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.Issuer(),
			Subject:   "a3f8b2c1-9d4e-4f6a-b7c8-1234567890ab", // opaque sub
			Audience:  jwt.ClaimStrings{m.ClientID},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		Email: "alice@sunet.se",
		EPPN:  "alice@sunet.se",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.Keypair.Kid
	signed, err := token.SignedString(m.Keypair.PrivateKey)
	require.NoError(t, err)

	// Middleware extracts eppn → email; eppn matches the SPOCP rule
	w := doRequest(engine, "GET", "/api/v1/datastore/search", signed, nil)
	assert.Equal(t, http.StatusOK, w.Code, "middleware should use eppn as SPOCP subject")
	assert.True(t, mock.searchCalled)
}

// TestOIDC_EmailFallback verifies the eppn → email → sub fallback chain.
// When eppn is absent, the middleware should use email
func TestOIDC_EmailFallback(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice@sunet.se)(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	// Token with email but no eppn
	type emailOnlyClaims struct {
		jwt.RegisteredClaims
		Email string `json:"email"`
	}
	claims := &emailOnlyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.Issuer(),
			Subject:   "a3f8b2c1-9d4e-4f6a-b7c8-1234567890ab",
			Audience:  jwt.ClaimStrings{m.ClientID},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		Email: "alice@sunet.se",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.Keypair.Kid
	signed, err := token.SignedString(m.Keypair.PrivateKey)
	require.NoError(t, err)

	w := doRequest(engine, "GET", "/api/v1/datastore/search", signed, nil)
	assert.Equal(t, http.StatusOK, w.Code, "middleware should fall back to email")
	assert.True(t, mock.searchCalled)
}

// TestOIDC_NoEppnOrEmail verifies that tokens without eppn or email are
// rejected — the opaque "sub" claim is not used as SPOCP subject
func TestOIDC_NoEppnOrEmail(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject api-service-account)(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	// Token with only sub, no eppn or email
	token := signMockOIDCTokenSubOnly(t, m, "api-service-account")
	w := doRequest(engine, "GET", "/api/v1/datastore/search", token, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "tokens without eppn/email must be rejected")
	assert.False(t, mock.searchCalled)
}

// TestOIDC_EppnMismatch verifies that a token with eppn bob@sunet.se is
// denied by a SPOCP rule that only allows alice@sunet.se
func TestOIDC_EppnMismatch(t *testing.T) {
	mock := &mockApiv1{}

	rules := []string{
		`(vc (service apigw)(method GET)(path /api/v1/datastore/search)(subject alice@sunet.se)(authentic_source *)(scope *))`,
	}
	engine, m := testSetupOIDC(t, rules, mock)

	// bob is not alice — include resource pair to trigger SPOCP check
	token := signMockOIDCToken(t, m, "bob@sunet.se")
	w := doRequest(engine, "GET", "/api/v1/datastore/search?authentic_source=SUNET&scope=eduid", token, nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, mock.searchCalled)
}

// --- No-auth mode tests ---

// testSetupNoAuth creates a gin engine with no authentication configured.
// Neither OIDC nor JWKS is enabled — all requests pass through.
func testSetupNoAuth(t *testing.T, mockAPI Apiv1) *gin.Engine {
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

	apiAuth := model.APIAuth{} // nothing enabled

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

	rgDatastore := rg.Group("/datastore")
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodPost, "", http.StatusOK, s.endpointDatastoreUpload)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodGet, "", http.StatusOK, s.endpointDatastoreGet)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodGet, "/search", http.StatusOK, s.endpointDatastoreSearch)
	helpers.Server.RegEndpoint(ctx, rgDatastore, http.MethodDelete, "", http.StatusNoContent, s.endpointDatastoreDelete)

	// Admin login endpoint
	rgUI := engine.Group("/ui")
	rgUI.Use(sessions.Sessions("admin_session", store))
	helpers.Server.RegEndpoint(ctx, rgUI, http.MethodGet, "/login", http.StatusOK, s.endpointAdminLogin)

	return engine
}

func TestNoAuth_APIAccessWithoutToken(t *testing.T) {
	mock := &mockApiv1{}
	engine := testSetupNoAuth(t, mock)

	// No Bearer token — should still be allowed
	w := doRequest(engine, "GET", "/api/v1/datastore/search", "", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, mock.searchCalled)
}

func TestNoAuth_LoginGrantsFullAccess(t *testing.T) {
	mock := &mockApiv1{}
	engine := testSetupNoAuth(t, mock)

	// Click Login — should redirect to /ui with a session
	req := httptest.NewRequest("GET", "/ui/login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/ui", w.Header().Get("Location"))

	// Extract session cookie and use it for a subsequent API request
	cookies := w.Result().Cookies()
	require.NotEmpty(t, cookies, "login should set a session cookie")

	req2 := httptest.NewRequest("GET", "/api/v1/datastore/search", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.True(t, mock.searchCalled)
}
