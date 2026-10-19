package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// challengeAPI records the request the transport layer built and answers
// with whatever the test under way needs back.
type challengeAPI struct {
	unimplementedApiv1

	seen  *apiv1.AuthorizationChallengeRequest
	reply *apiv1.AuthorizationChallengeResponse
	err   error
	calls int
}

func (a *challengeAPI) OAuthAuthorizationChallenge(_ context.Context, req *apiv1.AuthorizationChallengeRequest) (*apiv1.AuthorizationChallengeResponse, error) {
	a.seen = req
	a.calls++
	return a.reply, a.err
}

func (a *challengeAPI) OAuthPar(context.Context, *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	return nil, nil
}

func challengeEngine(t *testing.T, api *challengeAPI) *gin.Engine {
	return challengeEngineWithLimit(t, api, 0)
}

// challengeEngineWithLimit registers the route the way service.go does,
// with the rate limiter wired in the same shape (rgRoot.Group("") +
// RateLimiter.Middleware()). rpm <= 0 leaves it off.
func challengeEngineWithLimit(t *testing.T, api *challengeAPI, rpm int) *gin.Engine {
	t.Helper()
	ctx := t.Context()

	log, err := logger.New("challenge-endpoint-test", t.TempDir(), true)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "challenge-endpoint-test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       api,
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()
	rg := engine.Group("")
	if rpm > 0 {
		rg.Use(httphelpers.NewRateLimiter(cache.NewMemoryRateLimitCounter(), rpm).Middleware())
	}
	helpers.Server.RegEndpoint(ctx, rg, http.MethodPost, "authorize-challenge", http.StatusOK, s.endpointOAuthAuthorizationChallenge)
	return engine
}

func postChallenge(t *testing.T, engine *gin.Engine, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/authorize-challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// The Interaction Required Response is the whole next step of the flow,
// and it travels in the body of a 403. Rendering it through a generic
// OAuth error renderer would leave the wallet with error and
// error_description and nothing to act on.
func TestEndpointAuthorizationChallenge_RendersTheInteractionRequiredResponse(t *testing.T) {
	api := &challengeAPI{err: &apiv1.AuthorizationChallengeError{
		ErrorCode:               "insufficient_authorization",
		InteractionTypeRequired: "urn:openid:dcp:ia:openid4vp_presentation",
		AuthSession:             "opaque-handle",
		OpenID4VPRequest:        json.RawMessage(`{"request":"ey.."}`),
		HTTPStatus:              http.StatusForbidden,
	}}

	w := postChallenge(t, challengeEngine(t, api), url.Values{
		"response_type":               {"code"},
		"client_id":                   {"wallet-1"},
		"scope":                       {"pid"},
		"interaction_types_supported": {"urn:openid:dcp:ia:openid4vp_presentation"},
	}, nil)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"),
		"the response carries the material for an authorization code")

	body := map[string]any{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "insufficient_authorization", body["error"])
	assert.Equal(t, "urn:openid:dcp:ia:openid4vp_presentation", body["interaction_type_required"])
	assert.Equal(t, "opaque-handle", body["auth_session"])
	assert.Equal(t, map[string]any{"request": "ey.."}, body["openid4vp_request"],
		"openid4vp_request must reach the wallet as the JSON object it is, not as a string")
}

func TestEndpointAuthorizationChallenge_RendersTheAuthorizationCode(t *testing.T) {
	api := &challengeAPI{reply: &apiv1.AuthorizationChallengeResponse{AuthorizationCode: "the-code"}}

	w := postChallenge(t, challengeEngine(t, api), url.Values{"auth_session": {"opaque-handle"}}, nil)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Body.String(), `"authorization_code":"the-code"`)
}

// An ordinary OAuth refusal still goes through the shared renderer, so the
// endpoint does not acquire a second error format of its own.
func TestEndpointAuthorizationChallenge_OrdinaryOAuthErrorsAreNotRenderedHere(t *testing.T) {
	api := &challengeAPI{err: oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest, "scope is required", 400)}

	w := postChallenge(t, challengeEngine(t, api), url.Values{"response_type": {"code"}}, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

// The three credentials that do not travel in the form body have to be
// lifted off the headers, or client authentication and the DPoP binding
// are simply never presented to the handler.
func TestEndpointAuthorizationChallenge_CarriesTheHeaderCredentials(t *testing.T) {
	api := &challengeAPI{reply: &apiv1.AuthorizationChallengeResponse{AuthorizationCode: "the-code"}}

	postChallenge(t, challengeEngine(t, api), url.Values{
		"response_type":               {"code"},
		"client_id":                   {"wallet-1"},
		"scope":                       {"pid"},
		"interaction_types_supported": {"urn:openid:dcp:ia:openid4vp_presentation"},
	}, map[string]string{
		"OAuth-Client-Attestation":     "attestation-jwt",
		"OAuth-Client-Attestation-PoP": "pop-jwt",
		"DPoP":                         "dpop-jwt",
	})

	require.NotNil(t, api.seen)
	assert.Equal(t, "attestation-jwt", api.seen.ClientAttestation)
	assert.Equal(t, "pop-jwt", api.seen.ClientAttestationPoP)
	assert.Equal(t, "dpop-jwt", api.seen.DPOP)

	// And the form body still binds, so the header lifting did not replace
	// the ordinary binding.
	assert.Equal(t, "code", api.seen.ResponseType)
	assert.Equal(t, "wallet-1", api.seen.ClientID)
	assert.Equal(t, "pid", api.seen.Scope)
	assert.Equal(t, "urn:openid:dcp:ia:openid4vp_presentation", api.seen.InteractionTypesSupported)
}

// The Authorization Challenge Endpoint is rate limited, and service.go
// registers it on its own rgRoot.Group("") with RateLimiter.Middleware -
// the same shape as the credential, token and offer routes.
//
// It needs one of its own because of what an ACCEPTED request costs. The
// initial request carries nothing an attacker cannot mint - a public
// client's own parameters and a fresh DPoP proof - and each one that is
// accepted persists an authorization context plus an ephemeral P-256 key
// until the auth_session expires. Request volume is therefore storage
// growth, and nothing else in the flow bounds it: there is no code to
// forfeit and no session to exhaust before the records are written.
func TestEndpointOAuthAuthorizationChallenge_RateLimited(t *testing.T) {
	api := &challengeAPI{reply: &apiv1.AuthorizationChallengeResponse{AuthorizationCode: "code"}}
	engine := challengeEngineWithLimit(t, api, 3)

	form := url.Values{"auth_session": {"opaque-handle"}}
	for i := range 3 {
		w := postChallenge(t, engine, form, nil)
		require.Equal(t, http.StatusOK, w.Code, "request %d should be within the limit", i+1)
	}

	w := postChallenge(t, engine, form, nil)
	require.Equal(t, http.StatusTooManyRequests, w.Code,
		"the request over the limit must be rejected before it reaches the endpoint")
	assert.Equal(t, 3, api.calls,
		"a rate limited request must not reach OAuthAuthorizationChallenge")
}

// The Authorization Challenge Endpoint speaks JSON in both directions,
// whatever the Accept header says. It is a protocol endpoint a wallet
// posts to, not a page a browser navigates to.
//
// Without authorize-challenge in the renderer's JSON-only list, Accept:
// text/plain reached the "%v" branch and a successful exchange came back
// as "&{the-code}" - a 200 no wallet can read the authorization code out
// of - and Accept: text/html produced the shared HTML error page.
func TestEndpointAuthorizationChallenge_IsJSONWhateverTheAcceptHeaderSays(t *testing.T) {
	for _, accept := range []string{
		"text/plain",
		"text/html",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", // a browser's
		"application/json",
		"application/xml",
		"image/png",
		"*/*",
		"",
	} {
		t.Run("Accept: "+accept, func(t *testing.T) {
			api := &challengeAPI{reply: &apiv1.AuthorizationChallengeResponse{AuthorizationCode: "the-code"}}

			headers := map[string]string{}
			if accept != "" {
				headers["Accept"] = accept
			}
			w := postChallenge(t, challengeEngine(t, api), url.Values{"auth_session": {"opaque-handle"}}, headers)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

			body := map[string]any{}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body),
				"the body must be JSON, got %q", w.Body.String())
			assert.Equal(t, "the-code", body["authorization_code"])
		})
	}
}

// A body this endpoint cannot read is a malformed request, and the wallet
// is told so in OAuth's own terms.
//
// Returned bare, the binding failure went to the generic renderer and came
// back as {"error":{"title":"internal_server_error","details":{}}} - a 400
// whose body blames the server, in a shape no OAuth client parses - and
// with Accept: text/html it came back as an 8 KB HTML error page.
func TestEndpointAuthorizationChallenge_MalformedBodyIsAnOAuthError(t *testing.T) {
	for _, tc := range []struct{ name, body, accept string }{
		{name: "a malformed escape", body: "response_type=%ZZ"},
		{name: "a malformed escape, asking for HTML", body: "response_type=%ZZ", accept: "text/html"},
		{name: "a malformed escape, asking for text", body: "response_type=%ZZ", accept: "text/plain"},
		{name: "a stray percent", body: "client_id=wallet%"},
		{name: "a semicolon separator, which Go refuses", body: "a=1;b=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &challengeAPI{}
			engine := challengeEngine(t, api)

			req := httptest.NewRequest(http.MethodPost, "/authorize-challenge", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			require.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Header().Get("Content-Type"), "application/json",
				"a protocol endpoint answers in JSON, got %q", w.Header().Get("Content-Type"))

			var oauthErr oauth2.OAuthError
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &oauthErr),
				"the body must be an OAuth error, got %q", w.Body.String())
			assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
			assert.NotEmpty(t, oauthErr.ErrorDescription)

			assert.NotContains(t, w.Body.String(), "internal_server_error",
				"a body the server cannot read is the request's fault, not the server's")
			assert.NotContains(t, w.Body.String(), tc.body,
				"the description must not echo the bytes it could not read back at the sender")

			assert.Zero(t, api.calls, "a request that did not bind must not reach the handler")
		})
	}
}

// A failure the endpoint cannot phrase in the protocol's terms is still an
// OAuth error, not a nested internal_server_error object.
//
// Returned untyped - a context-save failure is the ordinary way it happens
// - the error reached the generic renderer and came back as
// {"error":{"title":"internal_server_error","details":{}}}, which no OAuth
// client parses. From a wallet's side that is the endpoint being broken,
// which is what server_error means.
func TestEndpointAuthorizationChallenge_UntypedFailureIsAServerError(t *testing.T) {
	api := &challengeAPI{err: errors.New("failed to save authorization context: store unavailable")}

	w := postChallenge(t, challengeEngine(t, api), url.Values{"auth_session": {"opaque-handle"}}, nil)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var oauthErr oauth2.OAuthError
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &oauthErr),
		"the body must be an OAuth error, got %q", w.Body.String())
	assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode)
	assert.NotEmpty(t, oauthErr.ErrorDescription)

	assert.NotContains(t, w.Body.String(), "internal_server_error")
	assert.NotContains(t, w.Body.String(), "store unavailable",
		"the cause names internal state and belongs in the log, not the response")
}

// And a failure the endpoint CAN phrase keeps its own words: wrapping
// every error as server_error would turn a precise refusal into a generic
// one, which is the opposite mistake.
func TestEndpointAuthorizationChallenge_TypedFailuresArePassedThrough(t *testing.T) {
	api := &challengeAPI{err: oauth2.NewOAuthError(
		oauth2.ErrCodeInvalidGrant, "auth_session is not valid", http.StatusBadRequest)}

	w := postChallenge(t, challengeEngine(t, api), url.Values{"auth_session": {"opaque-handle"}}, nil)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var oauthErr oauth2.OAuthError
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &oauthErr))
	assert.Equal(t, oauth2.ErrCodeInvalidGrant, oauthErr.ErrorCode)
	assert.Equal(t, "auth_session is not valid", oauthErr.ErrorDescription)
}
