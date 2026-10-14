package httpserver

import (
	"context"
	"encoding/json"
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

// prepareAPI records the request the transport layer built.
type prepareAPI struct {
	unimplementedApiv1
	seen *apiv1.PrepareIssuanceRequest
}

func (a *prepareAPI) PrepareIssuance(_ context.Context, req *apiv1.PrepareIssuanceRequest) (*apiv1.PrepareIssuanceReply, error) {
	a.seen = req
	return &apiv1.PrepareIssuanceReply{IssuerState: "prepared"}, nil
}

// The scope this endpoint acts on must be the scope the authorization
// middleware checked.
//
// httphelpers.Binding.Request binds headers BEFORE the JSON body, and
// gin's header binder falls back to the FIELD NAME when there is no
// header tag - so a "Scope:" header set the field, and a body that simply
// omits the member left it set. The SPOCP middleware extracts the resource
// pairs it authorizes from the query string and the JSON body and never
// reads headers, so a scope smuggled through one was acted on without
// having been authorized at all.
func TestEndpointPrepareIssuance_ScopeCannotComeFromAHeader(t *testing.T) {
	ctx := t.Context()

	log, err := logger.New("prepare-endpoint-test", t.TempDir(), true)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "prepare-endpoint-test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	api := &prepareAPI{}
	s := &Service{cfg: cfg, log: log.New("httpserver"), apiv1: api, tracer: tracer, httpHelpers: helpers}

	engine := gin.New()
	helpers.Server.RegEndpoint(ctx, engine.Group(""), http.MethodPost, "issuance/prepare", http.StatusOK, s.endpointPrepareIssuance)

	body := `{"identity_match":{"claims":{"given_name":{"equals":"Alice"}}},"scope":"allowed_scope"}`
	req := httptest.NewRequest(http.MethodPost, "/issuance/prepare", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Scope", "forbidden_scope")

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	require.NotNil(t, api.seen, "the request should have reached the handler; body: %s", w.Body.String())
	assert.Equal(t, "allowed_scope", api.seen.Scope,
		"a Scope header must not decide which credential is prepared")

	// And a body with no scope at all must not inherit the header's,
	// which is the shape that actually slipped past the middleware.
	api.seen = nil
	bodyWithoutScope := `{"identity_match":{"claims":{"given_name":{"equals":"Alice"}}}}`
	req = httptest.NewRequest(http.MethodPost, "/issuance/prepare", strings.NewReader(bodyWithoutScope))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Scope", "forbidden_scope")

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if api.seen != nil {
		assert.Empty(t, api.seen.Scope,
			"a scope the authorization middleware never saw must not reach the handler")
	}
}

// encoding/json matches members to struct fields case-INSENSITIVELY and
// lets a later member overwrite an earlier one, while the authorization
// middleware reads the body into a map and looks up the exact key
// "scope". So {"scope":"a","Scope":"b"} is one request with two scopes:
// the middleware authorizes "a" and the handler would act on "b".
//
// Refusing the ambiguity is the fix rather than picking a winner. There
// is no reading of such a body that a caller could have meant, and any
// rule for choosing between the two would have to be kept in step with
// encoding/json's own.
func TestEndpointPrepareIssuance_RefusesACaseVariantScope(t *testing.T) {
	ctx := t.Context()

	log, err := logger.New("prepare-ambiguous-test", t.TempDir(), true)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "prepare-ambiguous-test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	api := &prepareAPI{}
	s := &Service{cfg: cfg, log: log.New("httpserver"), apiv1: api, tracer: tracer, httpHelpers: helpers}

	engine := gin.New()
	helpers.Server.RegEndpoint(ctx, engine.Group(""), http.MethodPost, "issuance/prepare", http.StatusOK, s.endpointPrepareIssuance)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/issuance/prepare", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w
	}

	const match = `"identity_match":{"claims":{"given_name":{"equals":"Alice"}}}`

	api.seen = nil
	w := post(`{"scope":"allowed_scope","Scope":"forbidden_scope",` + match + `}`)
	assert.Nil(t, api.seen,
		"a body naming one member twice must not reach preparation at all")
	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())

	// The other order too: which of the two encoding/json happens to keep
	// is not something this should depend on.
	api.seen = nil
	w = post(`{"Scope":"forbidden_scope","scope":"allowed_scope",` + match + `}`)
	assert.Nil(t, api.seen)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// A LONE case variant, with no lowercase member beside it. This is
	// the sharper version: nothing collides, the middleware's map lookup
	// of "scope" finds nothing at all so no resource pair is authorized,
	// and encoding/json still puts the value in the field. A rule that
	// only refused bodies carrying BOTH spellings would leave it open.
	api.seen = nil
	w = post(`{"Scope":"forbidden_scope",` + match + `}`)
	assert.Nil(t, api.seen,
		"a scope the authorization middleware cannot see must not reach preparation")
	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())

	// And the same for the other members, since the rule is about the
	// names rather than about this one field.
	api.seen = nil
	w = post(`{"scope":"allowed_scope","Authentic_Source":"B",` + match + `}`)
	assert.Nil(t, api.seen)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// U+017F LATIN SMALL LETTER LONG S. encoding/json does not compare
	// member names with strings.ToLower - it uses a Unicode fold in which
	// "ſ" folds to "s" (the same rule that folds U+212A KELVIN SIGN
	// to "k") - so "ſcope" binds into Scope while an exact map lookup
	// of "scope" sees only the member beside it. A case-folding check
	// written with ToLower would NOT catch this, which is why the rule
	// here is exact membership rather than any kind of folding.
	api.seen = nil
	w = post("{\"scope\":\"allowed_scope\",\"\u017Fcope\":\"forbidden_scope\"," + match + "}")
	assert.Nil(t, api.seen,
		"a Unicode fold of scope must not reach preparation either")
	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())

	// The same spelling on its own, with no member for the middleware to
	// find at all.
	api.seen = nil
	w = post("{\"\u017Fcope\":\"forbidden_scope\"," + match + "}")
	assert.Nil(t, api.seen)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// And for authentic_source, which the authorization pair also reads.
	api.seen = nil
	w = post("{\"scope\":\"allowed_scope\",\"authentic_\u017Fource\":\"B\"," + match + "}")
	assert.Nil(t, api.seen)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// An ordinary body is unaffected.
	api.seen = nil
	w = post(`{"scope":"allowed_scope",` + match + `}`)
	require.NotNil(t, api.seen, "body: %s", w.Body.String())
	assert.Equal(t, "allowed_scope", api.seen.Scope)

	// Including one using every member this request defines.
	api.seen = nil
	w = post(`{"scope":"allowed_scope","authentic_source":"A","ttl_seconds":60,` + match + `}`)
	require.NotNil(t, api.seen, "body: %s", w.Body.String())
	assert.Equal(t, "A", api.seen.AuthenticSource)
	assert.Equal(t, 60, api.seen.TTLSeconds)
}
