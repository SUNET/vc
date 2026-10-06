package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// svgAPI answers the two scope lookups and the template fetch the consent
// endpoint makes.
type svgAPI struct {
	unimplementedApiv1
	vctmErr     error
	mddl        *mdoc.MDDLSchema
	templateErr error
	template    string
	calls       int
}

func (a *svgAPI) GetVCTMFromScope(context.Context, *apiv1.GetVCTMFromScopeRequest) (*sdjwtvc.VCTM, error) {
	if a.vctmErr != nil {
		return nil, a.vctmErr
	}
	return &sdjwtvc.VCTM{VCT: "urn:example:pid"}, nil
}

func (a *svgAPI) GetMDDLFromScope(context.Context, *apiv1.GetMDDLFromScopeRequest) (*mdoc.MDDLSchema, error) {
	return a.mddl, nil
}

func (a *svgAPI) SVGTemplateReply(context.Context, *apiv1.SVGTemplateRequest) (*vcclient.SVGTemplateReply, error) {
	a.calls++
	if a.templateErr != nil {
		return nil, a.templateErr
	}
	return &vcclient.SVGTemplateReply{Template: a.template}, nil
}

// svgTestEngine registers the real route behind the same session middleware
// service.go puts it behind, and seeds the scope the handler reads.
func svgTestEngine(t *testing.T, mockAPI Apiv1) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
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
	rg.Use(helpers.Middleware.UserSession("test_session",
		"0123456789abcdef0123456789abcdef", "0123456789abcdef", sessions.Options{Path: "/"}))
	rg.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("scope", "pid")
		_ = session.Save()
		c.Next()
	})
	helpers.Server.RegEndpoint(ctx, rg, http.MethodGet, "authorization/consent/svg-template",
		http.StatusOK, s.endpointOAuthAuthorizationConsentSvgTemplate)

	return engine
}

func getSVGTemplate(t *testing.T, engine *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/authorization/consent/svg-template", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// A credential type with no card image is a normal configuration, and the
// consent page calls this endpoint on every load. Answering 400 made each of
// those loads log an error, and made a real fetch failure indistinguishable
// from a credential that simply has no card (SUNET/vc#737).
func TestConsentSVGTemplate_NoTemplateIsNotAnError(t *testing.T) {
	api := &svgAPI{templateErr: apiv1.ErrNoSVGTemplate}
	w := getSVGTemplate(t, svgTestEngine(t, api))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var reply vcclient.SVGTemplateReply
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reply))
	assert.Empty(t, reply.Template, "an empty template is how the page is told to render no card")
}

// A fetch that really failed still is an error, or the distinction above
// buys nothing.
func TestConsentSVGTemplate_AFetchFailureIsStillAnError(t *testing.T) {
	api := &svgAPI{templateErr: errors.New("origin returned 503")}
	w := getSVGTemplate(t, svgTestEngine(t, api))

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
}

func TestConsentSVGTemplate_ReturnsTheTemplate(t *testing.T) {
	api := &svgAPI{template: "PHN2Zy8+"}
	w := getSVGTemplate(t, svgTestEngine(t, api))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var reply vcclient.SVGTemplateReply
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reply))
	assert.Equal(t, "PHN2Zy8+", reply.Template)
}

// An mso_mdoc scope has no VCTM, so the handler falls back to the MDDL
// schema - the path both credentials in the report take.
func TestConsentSVGTemplate_MDocScopeUsesTheMDDLSchema(t *testing.T) {
	api := &svgAPI{
		vctmErr:  apiv1.ErrScopeIsMDoc,
		mddl:     &mdoc.MDDLSchema{Display: []mdoc.DisplayProperties{{Name: "mDL"}}},
		template: "PG1kbC8+",
	}
	w := getSVGTemplate(t, svgTestEngine(t, api))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, 1, api.calls)

	var reply vcclient.SVGTemplateReply
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reply))
	assert.Equal(t, "PG1kbC8+", reply.Template)
}
