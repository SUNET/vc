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

// resetAPI records who approved the reset it is asked for.
type resetAPI struct {
	unimplementedApiv1
	approvedBy string
}

func (r *resetAPI) ResetUniqueCommitment(_ context.Context, _ *apiv1.ResetUniqueCommitmentRequest, approvedBy string) error {
	r.approvedBy = approvedBy
	return nil
}

// A reset is approved by the authenticated operator, and refused without
// one.
func TestEndpointResetUniqueCommitment_Operator(t *testing.T) {
	ctx := t.Context()
	log, err := logger.New("reset-endpoint-test", t.TempDir(), true)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "reset-endpoint-test", log)
	require.NoError(t, err)
	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	api := &resetAPI{}
	s := &Service{cfg: cfg, log: log.New("httpserver"), apiv1: api, tracer: tracer, httpHelpers: helpers}
	operator := ""
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		if operator != "" {
			c.Set("jwt_subject", operator)
		}
	})
	helpers.Server.RegEndpoint(ctx, engine.Group(""), http.MethodPost, "auxiliary_data/reset", http.StatusNoContent, s.endpointResetUniqueCommitment)
	post := func() int {
		body := `{"scope":"nym_auth","path":["eu.europa.ec.eudi.nym_auth.1","psc"],"key":[{"path":["eu.europa.ec.eudi.nym_auth.1","ssc"],"inputs":["SE","pan-200"]}],"evidence_ref":"case-1"}`
		req := httptest.NewRequest(http.MethodPost, "/auxiliary_data/reset", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w.Code
	}

	assert.Equal(t, http.StatusForbidden, post())
	assert.Empty(t, api.approvedBy, "the reset was not attempted")

	operator = "admin@example.org"
	assert.Equal(t, http.StatusNoContent, post())
	assert.Equal(t, operator, api.approvedBy)
}
