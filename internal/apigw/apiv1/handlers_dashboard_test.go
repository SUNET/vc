package apiv1

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/status"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dashboardTestClient builds a minimal Client sufficient to exercise the
// dashboard handler: config with a Dashboard.Services list and optionally a
// preconfigured statusAggregator.
func dashboardTestClient(t *testing.T, services []model.DashboardService, agg *status.Aggregator) *Client {
	t.Helper()
	log := logger.NewSimple("test")
	tracer, err := trace.NewForTesting(t.Context(), "test", log)
	require.NoError(t, err)
	return &Client{
		log:    log,
		tracer: tracer,
		cfg: &model.Cfg{
			APIGW: &model.APIGW{
				Dashboard: model.APIGWDashboard{
					Services: services,
				},
			},
		},
		statusAggregator: agg,
	}
}

func TestDashboard_ReturnsServicesFromConfig(t *testing.T) {
	services := []model.DashboardService{
		{Name: "apigw", URL: "https://apigw.example.com", Description: "API gateway"},
		{Name: "issuer", URL: "https://issuer.example.com"},
	}
	c := dashboardTestClient(t, services, nil)

	reply, err := c.Dashboard(t.Context())
	require.NoError(t, err)
	require.NotNil(t, reply)
	assert.Equal(t, "SUNET Verifiable Credentials", reply.Title)
	require.Len(t, reply.Services, 2)
	assert.Equal(t, "apigw", reply.Services[0].Name)
	assert.Equal(t, "https://apigw.example.com", reply.Services[0].URL)
	assert.Equal(t, "issuer", reply.Services[1].Name)
}

func TestDashboard_TitleOverride(t *testing.T) {
	c := dashboardTestClient(t, nil, nil)
	c.cfg.APIGW.Dashboard.Title = "Demo Deployment"

	reply, err := c.Dashboard(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "Demo Deployment", reply.Title)
}

func TestApplyHealth_NilAggregatorMarksUnknown(t *testing.T) {
	c := dashboardTestClient(t, nil, nil)
	views := []DashboardServiceView{{Name: "apigw"}, {Name: "issuer"}}

	c.applyHealth(t.Context(), views)

	for _, v := range views {
		assert.Equal(t, "unknown", v.Health)
		assert.Empty(t, v.Message)
	}
}

func TestApplyHealth_ClassifiesFromAggregator(t *testing.T) {
	agg := status.New("apigw", status.WithCacheTTL(0)).
		RegisterFunc("db", func(context.Context) error { return nil }).
		RegisterDownstream("issuer", func(context.Context) (*apiv1_status.StatusReply, error) {
			return status.Probes{
				{Name: "issuer.signer", Healthy: true, Message: "OK"},
			}.Check("issuer"), nil
		}).
		RegisterDownstream("registry", func(context.Context) (*apiv1_status.StatusReply, error) {
			return status.Probes{
				{Name: "registry.mongo", Healthy: false, Message: "connection refused"},
			}.Check("registry"), nil
		})

	c := dashboardTestClient(t, nil, agg)
	views := []DashboardServiceView{
		{Name: "apigw"},
		{Name: "issuer"},
		{Name: "registry"},
		{Name: "verifier"},
	}

	c.applyHealth(t.Context(), views)

	assert.Equal(t, "healthy", views[0].Health, "apigw local probes all healthy")
	assert.Equal(t, "healthy", views[1].Health, "issuer downstream returned healthy probes")
	assert.Equal(t, "unhealthy", views[2].Health, "registry downstream reported unhealthy probe")
	assert.Contains(t, views[2].Message, "registry.mongo")
	assert.Contains(t, views[2].Message, "connection refused")
	assert.Equal(t, "unknown", views[3].Health, "verifier has no probes")
	assert.Empty(t, views[3].Message)
}

// TestApplyHealth_DownstreamFetchFailureIsUnhealthy covers the case Copilot
// flagged in PR #661: when a downstream fetcher itself errors, the aggregator
// emits a synthetic probe named "apigw.<downstream>" (its own service prefix
// applied to the bare downstream name). That probe must classify the affected
// service as "unhealthy", not "unknown".
func TestApplyHealth_DownstreamFetchFailureIsUnhealthy(t *testing.T) {
	agg := status.New("apigw", status.WithCacheTTL(0)).
		RegisterDownstream("issuer", func(context.Context) (*apiv1_status.StatusReply, error) {
			return nil, errors.New("dial tcp: connection refused")
		})

	c := dashboardTestClient(t, nil, agg)
	views := []DashboardServiceView{{Name: "issuer"}}

	c.applyHealth(t.Context(), views)

	assert.Equal(t, "unhealthy", views[0].Health)
	assert.Contains(t, views[0].Message, "apigw.issuer")
	assert.Contains(t, views[0].Message, "connection refused")
}

func TestDashboardURLAllowed(t *testing.T) {
	services := []model.DashboardService{
		{
			Name: "issuer",
			URL:  "https://issuer.example.com",
			Links: []model.DashboardLink{
				{Label: "Health", URL: "https://issuer.example.com/health", Type: "json"},
				{Label: "Admin UI", URL: "https://issuer.example.com/ui", Type: "page"},
				{Label: "Other host", URL: "https://other.example.com/foo", Type: "json"},
			},
		},
	}
	c := dashboardTestClient(t, services, nil)

	cases := []struct {
		url     string
		allowed bool
	}{
		{"https://issuer.example.com/health", true},                // exact JSON link
		{"https://issuer.example.com/health?ts=1", true},           // query ignored
		{"https://other.example.com/foo", true},                    // exact JSON link on other host
		{"https://issuer.example.com/anything", false},             // path not advertised
		{"https://issuer.example.com/ui", false},                   // page link, not json
		{"https://issuer.example.com/metrics", false},              // unadvertised path on allowed host
		{"https://other.example.com/anything", false},              // unadvertised path on allowed host
		{"https://evil.example.com/foo", false},                    // unknown host
		{"http://issuer.example.com/health", false},                // scheme mismatch
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			u, err := url.Parse(tc.url)
			require.NoError(t, err)
			assert.Equal(t, tc.allowed, c.dashboardURLAllowed(u))
		})
	}
}
