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
}

func (a *challengeAPI) OAuthAuthorizationChallenge(_ context.Context, req *apiv1.AuthorizationChallengeRequest) (*apiv1.AuthorizationChallengeResponse, error) {
	a.seen = req
	return a.reply, a.err
}

func (a *challengeAPI) OAuthPar(context.Context, *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	return nil, nil
}

func challengeEngine(t *testing.T, api *challengeAPI) *gin.Engine {
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
