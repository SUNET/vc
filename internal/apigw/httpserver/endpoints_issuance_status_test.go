package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type issuanceStatusMock struct {
	unimplementedApiv1
	got *apiv1.IssuanceStatusRequest
}

func (m *issuanceStatusMock) IssuanceStatus(_ context.Context, req *apiv1.IssuanceStatusRequest) (*apiv1.IssuanceStatusReply, error) {
	m.got = req
	return &apiv1.IssuanceStatusReply{IssuanceID: req.IssuanceID}, nil
}

func TestEndpointIssuanceStatus_BindsFromQueryOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)
	cfg := &model.Cfg{Common: &model.Common{}}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	mock := &issuanceStatusMock{}
	s := &Service{cfg: cfg, log: log.New("httpserver"), apiv1: mock, tracer: tracer, httpHelpers: helpers}
	engine := gin.New()
	helpers.Server.RegEndpoint(ctx, engine.Group("/api/v1"), http.MethodGet, "/issuance/status", http.StatusOK, s.endpointIssuanceStatus)

	// The query is what authorization checks; the body names someone else's source, scope and id.
	body := `{"issuance_id":"foreign-id","AUTHENTIC_SOURCE":"OTHER","SCOPE":"ehic"}`
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/issuance/status?issuance_id=my-id&authentic_source=SUNET&scope=pid", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, mock.got)
	assert.Equal(t, "my-id", mock.got.IssuanceID)
	assert.Equal(t, "SUNET", mock.got.AuthenticSource)
	assert.Equal(t, "pid", mock.got.Scope)
}
