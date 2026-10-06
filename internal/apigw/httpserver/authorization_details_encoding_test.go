package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parAPI records the PAR request the route bound, so a test can assert on the
// authorization_details that actually came out of the endpoint rather than on
// a reimplementation of its parsing.
type parAPI struct {
	unimplementedApiv1
	got   *openid4vci.PARRequest
	calls int
}

func (p *parAPI) OAuthPar(_ context.Context, req *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	p.got = req
	p.calls++
	return &openid4vci.ParResponse{RequestURI: "urn:ietf:params:oauth:request_uri:abc", ExpiresIn: 60}, nil
}

// parTestEngine registers the real PAR route the way service.go does.
// acceptNonStandard drives model.OpenID4VCICompat.
func parTestEngine(t *testing.T, mockAPI Apiv1, acceptNonStandard bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common: &model.Common{},
		APIGW: &model.APIGW{
			Delivery: model.APIGWDelivery{
				OpenID4VCICompat: model.OpenID4VCICompat{
					AcceptNonStandardAuthorizationDetailsArrays: &acceptNonStandard,
				},
			},
		},
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       mockAPI,
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()
	rg := engine.Group("")
	helpers.Server.RegEndpoint(ctx, rg, http.MethodPost, "op/par", http.StatusCreated, s.endpointOAuthPar)

	return engine
}

const (
	detailPID  = `{"type":"openid_credential","credential_configuration_id":"pid"}`
	detailEHIC = `{"type":"openid_credential","credential_configuration_id":"ehic"}`
)

// parForm builds a PAR body with every required parameter, then lets the
// caller add authorization_details in whichever encoding is under test.
func parForm(details ...[2]string) string {
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"wallet-1"},
		"redirect_uri":          {"https://wallet.example.com/cb"},
		"code_challenge":        {strings.Repeat("c", 43)},
		"code_challenge_method": {"S256"},
	}
	for _, kv := range details {
		form.Add(kv[0], kv[1])
	}
	return form.Encode()
}

func postPAR(t *testing.T, engine *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/op/par", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func configurationIDs(req *openid4vci.PARRequest) []string {
	ids := make([]string, 0, len(req.AuthorizationDetails))
	for _, d := range req.AuthorizationDetails {
		ids = append(ids, d.CredentialConfigurationID)
	}
	return ids
}

// The encoding OpenID4VCI 1.0 §5.1.1 defines - one parameter holding the
// URL-encoded JSON array - works with the compat switch off, which is the
// default.
func TestPAR_SpecifiedArrayEncoding(t *testing.T) {
	api := &parAPI{}
	engine := parTestEngine(t, api, false)

	w := postPAR(t, engine, parForm([2]string{"authorization_details", "[" + detailPID + "," + detailEHIC + "]"}))

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	require.Equal(t, 1, api.calls)
	assert.Equal(t, []string{"pid", "ehic"}, configurationIDs(api.got))
}

// ... and it keeps working with the switch on, unchanged.
func TestPAR_SpecifiedArrayEncodingUnaffectedByCompat(t *testing.T) {
	api := &parAPI{}
	engine := parTestEngine(t, api, true)

	w := postPAR(t, engine, parForm([2]string{"authorization_details", "[" + detailPID + "," + detailEHIC + "]"}))

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, []string{"pid", "ehic"}, configurationIDs(api.got))
}

// Repeated keys are refused by default: RFC 6749 §3.1 says a parameter must
// not appear more than once, so this is a protocol violation, not a dialect.
func TestPAR_RepeatedKeyRefusedByDefault(t *testing.T) {
	api := &parAPI{}
	engine := parTestEngine(t, api, false)

	w := postPAR(t, engine, parForm(
		[2]string{"authorization_details", detailPID},
		[2]string{"authorization_details", detailEHIC},
	))

	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Zero(t, api.calls, "the request must not reach the API")
}

// A bracketed key is an unknown parameter by default, and OAuth says to
// ignore unknown parameters - so the request is accepted with no
// authorization_details rather than refused.
func TestPAR_BracketedKeyIgnoredByDefault(t *testing.T) {
	api := &parAPI{}
	engine := parTestEngine(t, api, false)

	w := postPAR(t, engine, parForm(
		[2]string{openid4vci.AuthorizationDetailsBracketKey, detailPID},
		[2]string{openid4vci.AuthorizationDetailsBracketKey, detailEHIC},
	))

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	require.Equal(t, 1, api.calls)
	assert.Empty(t, api.got.AuthorizationDetails)
}

// With the switch on, both non-standard encodings reach the API as the array
// the wallet meant, in the order it sent them (SUNET/vc#710).
func TestPAR_RepeatedKeyAcceptedWhenEnabled(t *testing.T) {
	api := &parAPI{}
	engine := parTestEngine(t, api, true)

	w := postPAR(t, engine, parForm(
		[2]string{"authorization_details", detailPID},
		[2]string{"authorization_details", detailEHIC},
	))

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, []string{"pid", "ehic"}, configurationIDs(api.got))
}

func TestPAR_BracketedKeyAcceptedWhenEnabled(t *testing.T) {
	api := &parAPI{}
	engine := parTestEngine(t, api, true)

	w := postPAR(t, engine, parForm(
		[2]string{openid4vci.AuthorizationDetailsBracketKey, detailPID},
		[2]string{openid4vci.AuthorizationDetailsBracketKey, detailEHIC},
	))

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, []string{"pid", "ehic"}, configurationIDs(api.got))
}

// Leniency about the container is not leniency about the contents: a value
// that is not JSON is still refused, and an entry that fails per-entry
// validation is still refused.
func TestPAR_EnabledStillRefusesGarbage(t *testing.T) {
	for name, value := range map[string]string{
		"not json":     "notjson",
		"bare string":  `"openid_credential"`,
		"wrong type":   `{"type":"not_openid_credential","credential_configuration_id":"pid"}`,
		"empty object": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			api := &parAPI{}
			engine := parTestEngine(t, api, true)

			w := postPAR(t, engine, parForm(
				[2]string{openid4vci.AuthorizationDetailsBracketKey, value},
			))

			require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
			assert.Zero(t, api.calls)
		})
	}
}

// A single value that is already an array is the specified encoding, so the
// compat path leaves it to the strict parser - which still refuses it when it
// is malformed.
func TestPAR_EnabledStillRefusesAMalformedArray(t *testing.T) {
	api := &parAPI{}
	engine := parTestEngine(t, api, true)

	w := postPAR(t, engine, parForm([2]string{"authorization_details", "[" + detailPID}))

	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Zero(t, api.calls)
}
