package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/internal/verifier/apiv1"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end tests for the click-time same-device commit. The signal MUST
// be an explicit flag written before the browser leaves for the wallet:
// inferring same-vs-cross device from SSE listener liveness races against
// TCP teardown and reverse-proxy buffering, and misdetects native wallets
// that never carry the tab's cookies. These tests exercise the resolution
// of session_id from the gin cookie into UpdateSessionPreference. The
// standalone UI now sends the id explicitly in the body - the cookie is
// kept as a legacy / storage-unavailable fallback and this suite covers
// that fallback alongside the primary body-driven path.

// sessionPrefApiv1 is a minimal Apiv1 implementation used to drive
// endpointSessionPreference end-to-end. It delegates UpdateSessionPreference
// to a real in-memory AuthorizationContext store so tests can observe the
// resulting flag state; every other method returns zero values and is
// present only to satisfy the interface.
type sessionPrefApiv1 struct {
	unimplementedApiv1
	store pkgcache.AuthContextStore
}

func (s *sessionPrefApiv1) UpdateSessionPreference(ctx context.Context, req *apiv1.UpdateSessionPreferenceRequest) (*apiv1.UpdateSessionPreferenceResponse, error) {
	if req.SessionID == "" {
		return nil, apiv1.ErrSessionNotFound
	}
	authCtx, err := s.store.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, apiv1.ErrSessionNotFound
	}
	if authCtx == nil {
		return nil, apiv1.ErrSessionNotFound
	}
	authCtx.ShowCredentialDetails = req.ShowCredentialDetails
	if req.WalletFollowsRedirect != nil {
		authCtx.WalletFollowsRedirect = *req.WalletFollowsRedirect
	}
	if err := s.store.Update(ctx, authCtx); err != nil {
		return nil, err
	}
	return &apiv1.UpdateSessionPreferenceResponse{Success: true}, nil
}

func setupSessionPreferenceEngine(t *testing.T, store pkgcache.AuthContextStore) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common:   &model.Common{},
		Verifier: &model.Verifier{PublicURL: "https://verifier.example.com"},
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		tracer:      tracer,
		httpHelpers: helpers,
		apiv1:       &sessionPrefApiv1{store: store},
	}

	engine := gin.New()
	sessionStore := cookie.NewStore(
		[]byte("12345678901234567890123456789012"),
		[]byte("1234567890123456"),
	)
	sessionStore.Options(sessions.Options{Path: "/", MaxAge: 900, HttpOnly: true})

	rg := engine.Group("/")
	rg.Use(sessions.Sessions("verifier_user_session", sessionStore))

	// Mirrors endpointUIInteraction: seed session_id into the cookie session.
	rg.POST("/test-set-session-id", func(c *gin.Context) {
		var body struct {
			SessionID string `json:"session_id"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		sess := sessions.Default(c)
		sess.Set("session_id", body.SessionID)
		require.NoError(t, sess.Save())
		c.Status(http.StatusOK)
	})

	sgVerification := rg.Group("/verification")
	helpers.Server.RegEndpoint(ctx, sgVerification, http.MethodPost, "session-preference", http.StatusOK, s.endpointSessionPreference)

	return engine
}

func seedAuthContext(t *testing.T, store pkgcache.AuthContextStore, sessionID string) {
	t.Helper()
	require.NoError(t, store.Save(context.Background(), &pkgcache.AuthorizationContext{
		SessionID:    sessionID,
		Status:       pkgcache.SessionStatusPending,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute).Unix(),
		ClientID:     "test-client",
		RedirectURI:  "https://client.example.com/callback",
		ResponseType: "code",
		Scopes:       []string{"openid"},
		State:        "client-state-" + sessionID,
	}))
}

func loginSessionID(t *testing.T, engine *gin.Engine, sessionID string) []*http.Cookie {
	t.Helper()
	body, err := json.Marshal(map[string]string{"session_id": sessionID})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/test-set-session-id", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	cookies := w.Result().Cookies()
	require.NotEmpty(t, cookies, "seed request must set a session cookie")
	return cookies
}

func postSessionPreference(t *testing.T, engine *gin.Engine, cookies []*http.Cookie, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/verification/session-preference", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// Legacy / storage-unavailable fallback: a caller that cannot send
// session_id in the body (older build, sessionStorage blocked by
// browser policy, or a bare probe) relies on the gin cookie session
// written by /ui/interaction. This endpoint must stay mounted under
// that middleware, or the fallback path cannot commit the flag.
func TestEndpointSessionPreference_CookieFallback_CommitsFlag(t *testing.T) {
	store := pkgcache.NewMemoryStore(15 * time.Minute)
	engine := setupSessionPreferenceEngine(t, store)

	const sessionID = "session-cookie-fallback"
	seedAuthContext(t, store, sessionID)

	cookies := loginSessionID(t, engine, sessionID)

	w := postSessionPreference(t, engine, cookies, map[string]any{
		"wallet_follows_redirect": true,
	})
	require.Equal(t, http.StatusOK, w.Code, "cookie-only call must succeed: body=%s", w.Body.String())

	got, err := store.GetByID(context.Background(), sessionID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.WalletFollowsRedirect, "cookie-driven click handler must set the same-device flag")
}

// The OIDC-OP flow (authorize_enhanced.html) sends session_id in the body
// alongside the flag. When both are present the body wins: a stray cookie
// from an unrelated tab must not redirect the write onto a different
// session.
func TestEndpointSessionPreference_BodySessionIDWins(t *testing.T) {
	store := pkgcache.NewMemoryStore(15 * time.Minute)
	engine := setupSessionPreferenceEngine(t, store)

	const cookieSession = "session-cookie-holder"
	const bodySession = "session-body-target"
	seedAuthContext(t, store, cookieSession)
	seedAuthContext(t, store, bodySession)

	cookies := loginSessionID(t, engine, cookieSession)

	w := postSessionPreference(t, engine, cookies, map[string]any{
		"session_id":              bodySession,
		"wallet_follows_redirect": true,
	})
	require.Equal(t, http.StatusOK, w.Code, "body-driven call must succeed: body=%s", w.Body.String())

	target, err := store.GetByID(context.Background(), bodySession)
	require.NoError(t, err)
	require.NotNil(t, target)
	assert.True(t, target.WalletFollowsRedirect, "body session must receive the flag")

	other, err := store.GetByID(context.Background(), cookieSession)
	require.NoError(t, err)
	require.NotNil(t, other)
	assert.False(t, other.WalletFollowsRedirect, "cookie session must be untouched when body carries a different id")
}

// Cross-device browser scenario: a user visits the verifier without going
// through /ui/interaction (no cookie session), or a bare probe. There is
// nothing to commit and the endpoint must refuse rather than silently
// succeed against an empty id.
func TestEndpointSessionPreference_NoSessionRejected(t *testing.T) {
	store := pkgcache.NewMemoryStore(15 * time.Minute)
	engine := setupSessionPreferenceEngine(t, store)

	w := postSessionPreference(t, engine, nil, map[string]any{
		"wallet_follows_redirect": true,
	})
	assert.GreaterOrEqual(t, w.Code, 400, "no session_id anywhere must not return 2xx")
}

// unimplementedApiv1 is a zero-value stub covering the Apiv1 interface, so
// individual tests only override the methods they care about. Each method
// panics if actually called from a route the tests do not register.
type unimplementedApiv1 struct{}

func (unimplementedApiv1) OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error) {
	panic("OAuthMetadata not implemented in test")
}
func (unimplementedApiv1) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	panic("Health not implemented in test")
}
func (unimplementedApiv1) VerificationRequestObject(ctx context.Context, req *apiv1.VerificationRequestObjectRequest) (string, error) {
	panic("VerificationRequestObject not implemented in test")
}
func (unimplementedApiv1) VerificationDirectPost(ctx context.Context, req *apiv1.VerificationDirectPostRequest) (*apiv1.VerificationDirectPostResponse, error) {
	panic("VerificationDirectPost not implemented in test")
}
func (unimplementedApiv1) VerificationCallback(ctx context.Context, req *apiv1.VerificationCallbackRequest) (*apiv1.VerificationCallbackResponse, error) {
	panic("VerificationCallback not implemented in test")
}
func (unimplementedApiv1) UIInteraction(ctx context.Context, req *apiv1.UIInteractionRequest) (*apiv1.UIInteractionReply, error) {
	panic("UIInteraction not implemented in test")
}
func (unimplementedApiv1) UIMetadata(ctx context.Context) (*apiv1.UIMetadataReply, error) {
	panic("UIMetadata not implemented in test")
}
func (unimplementedApiv1) IsActiveAuthSession(ctx context.Context, sessionID string) bool {
	panic("IsActiveAuthSession not implemented in test")
}
func (unimplementedApiv1) GetDiscoveryMetadata(ctx context.Context) (*apiv1.DiscoveryMetadata, error) {
	panic("GetDiscoveryMetadata not implemented in test")
}
func (unimplementedApiv1) GetJWKS(ctx context.Context) (*jose.JWKS, error) {
	panic("GetJWKS not implemented in test")
}
func (unimplementedApiv1) Authorize(ctx context.Context, req *apiv1.AuthorizeRequest) (*apiv1.AuthorizeResponse, error) {
	panic("Authorize not implemented in test")
}
func (unimplementedApiv1) Token(ctx context.Context, req *apiv1.TokenRequest) (*apiv1.TokenResponse, error) {
	panic("Token not implemented in test")
}
func (unimplementedApiv1) GetUserInfo(ctx context.Context, req *apiv1.UserInfoRequest) (apiv1.UserInfoResponse, error) {
	panic("GetUserInfo not implemented in test")
}
func (unimplementedApiv1) GetOIDCRequestObject(ctx context.Context, req *apiv1.GetRequestObjectRequest) (*apiv1.GetRequestObjectResponse, error) {
	panic("GetOIDCRequestObject not implemented in test")
}
func (unimplementedApiv1) ProcessDirectPost(ctx context.Context, req *apiv1.DirectPostRequest) (*apiv1.DirectPostResponse, error) {
	panic("ProcessDirectPost not implemented in test")
}
func (unimplementedApiv1) ProcessCallback(ctx context.Context, req *apiv1.CallbackRequest) (*apiv1.CallbackResponse, error) {
	panic("ProcessCallback not implemented in test")
}
func (unimplementedApiv1) GetQRCode(ctx context.Context, req *apiv1.GetQRCodeRequest) (*apiv1.GetQRCodeResponse, error) {
	panic("GetQRCode not implemented in test")
}
func (unimplementedApiv1) PollSession(ctx context.Context, req *apiv1.PollSessionRequest) (*apiv1.PollSessionResponse, error) {
	panic("PollSession not implemented in test")
}
func (unimplementedApiv1) RegisterClient(ctx context.Context, req *apiv1.ClientRegistrationRequest) (*apiv1.ClientRegistrationResponse, error) {
	panic("RegisterClient not implemented in test")
}
func (unimplementedApiv1) GetClientInformation(ctx context.Context, req *apiv1.GetClientInformationRequest) (*apiv1.ClientInformationResponse, error) {
	panic("GetClientInformation not implemented in test")
}
func (unimplementedApiv1) UpdateClient(ctx context.Context, req *apiv1.UpdateClientRequest) (*apiv1.ClientRegistrationResponse, error) {
	panic("UpdateClient not implemented in test")
}
func (unimplementedApiv1) DeleteClient(ctx context.Context, req *apiv1.DeleteClientRequest) error {
	panic("DeleteClient not implemented in test")
}
func (unimplementedApiv1) UpdateSessionPreference(ctx context.Context, req *apiv1.UpdateSessionPreferenceRequest) (*apiv1.UpdateSessionPreferenceResponse, error) {
	panic("UpdateSessionPreference not implemented in test")
}
func (unimplementedApiv1) ConfirmCredentialDisplay(ctx context.Context, req *apiv1.ConfirmCredentialDisplayRequest) (*apiv1.ConfirmCredentialDisplayResponse, error) {
	panic("ConfirmCredentialDisplay not implemented in test")
}
func (unimplementedApiv1) GetCredentialDisplayData(ctx context.Context, req *apiv1.GetCredentialDisplayDataRequest) (*apiv1.GetCredentialDisplayDataResponse, error) {
	panic("GetCredentialDisplayData not implemented in test")
}
