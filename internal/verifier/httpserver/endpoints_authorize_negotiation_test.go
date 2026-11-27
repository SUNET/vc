package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/internal/verifier/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authorizeApiv1 answers /authorize with a fixed response, so the test
// observes how the endpoint renders it rather than how it was built.
type authorizeApiv1 struct {
	unimplementedApiv1
}

func (authorizeApiv1) Authorize(ctx context.Context, req *apiv1.AuthorizeRequest) (*apiv1.AuthorizeResponse, error) {
	return &apiv1.AuthorizeResponse{
		SessionID:      "session-1",
		QRCodeData:     "openid4vp://cb?client_id=verifier&request_uri=https://verifier.example.com/verification/request-object/session-1",
		QRCodeImageURL: "/qr/session-1",
		DeepLinkURL:    "openid4vp://cb?client_id=verifier&request_uri=https://verifier.example.com/verification/request-object/session-1",
		PollURL:        "/poll/session-1",
		Title:          "Employee Verification",
	}, nil
}

// setupAuthorizeEngine registers /authorize exactly as the real server does,
// wrapper included: the wrapper is what turns a returned response into JSON,
// so a test that called the handler directly would not observe the body at
// all.
func setupAuthorizeEngine(t *testing.T) *gin.Engine {
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
		apiv1:       authorizeApiv1{},
	}

	engine := gin.New()
	engine.SetHTMLTemplate(htmlTemplates())
	engine.GET("/authorize", func(c *gin.Context) {
		response, err := s.endpointAuthorize(ctx, c)
		if err != nil {
			s.log.Error(err, "Authorize endpoint error")
		}
		if response != nil {
			c.JSON(http.StatusOK, response)
		}
	})

	return engine
}

func authorizeRequest(t *testing.T, engine *gin.Engine, accept string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=rp&redirect_uri=https://rp.example.com/cb&scope=openid", nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)

	return recorder
}

// A customer embedding the presentation request on its own page needs the
// request as data, not as the verifier's page. Everything required to render
// it is already in the response the endpoint builds for its own template.
func TestAuthorizeServesJSONWhenItIsAsked(t *testing.T) {
	recorder := authorizeRequest(t, setupAuthorizeEngine(t), "application/json")

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Content-Type"), "application/json")

	var got apiv1.AuthorizeResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &got))

	assert.Equal(t, "session-1", got.SessionID)
	assert.Contains(t, got.QRCodeData, "openid4vp://")
	assert.Equal(t, "/qr/session-1", got.QRCodeImageURL)
	assert.Equal(t, "/poll/session-1", got.PollURL)
	assert.NotEmpty(t, got.DeepLinkURL)
}

// The page is what a browser has always been served here, and a browser's
// Accept header accepts JSON through its */* range - so negotiating on "is
// JSON acceptable" would have handed the page away to every visitor.
func TestAuthorizeStillServesThePageToABrowser(t *testing.T) {
	engine := setupAuthorizeEngine(t)

	for name, accept := range map[string]string{
		"a browser's default header": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"no Accept header":           "",
		"curl's wildcard":            "*/*",
	} {
		t.Run(name, func(t *testing.T) {
			recorder := authorizeRequest(t, engine, accept)

			require.Equal(t, http.StatusOK, recorder.Code)
			assert.Contains(t, recorder.Header().Get("Content-Type"), "text/html")
			assert.Contains(t, recorder.Body.String(), "Employee Verification")
		})
	}
}
