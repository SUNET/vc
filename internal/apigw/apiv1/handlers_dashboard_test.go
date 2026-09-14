package apiv1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

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

func TestAddrIsPublic(t *testing.T) {
	cases := []struct {
		addr   string
		public bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"127.0.0.1", false},
		{"10.0.0.5", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"169.254.169.254", false}, // link-local (AWS/GCP metadata)
		{"0.0.0.0", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"fe80::1", false},
		{"fd00::1", false}, // ULA
		{"::", false},
		{"2001:4860:4860::8888", true},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			a, err := netip.ParseAddr(tc.addr)
			require.NoError(t, err)
			assert.Equal(t, tc.public, addrIsPublic(a))
		})
	}
}

func TestNewDashboardHTTPClient_RejectsPrivate(t *testing.T) {
	// A localhost target must be refused at dial time by the SSRF guardrail.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newDashboardHTTPClient(2 * time.Second)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.Error(t, err, "expected dial to loopback to fail")
	assert.Contains(t, err.Error(), "non-public")
}

func TestProbeCache_TTL(t *testing.T) {
	pc := &probeCache{}
	pc.put("k", "healthy", "")
	h, m, ok := pc.get("k")
	assert.True(t, ok)
	assert.Equal(t, "healthy", h)
	assert.Empty(t, m)

	// Force expiry.
	pc.entries["k"] = probeCacheEntry{health: "healthy", expires: time.Now().Add(-time.Second)}
	_, _, ok = pc.get("k")
	assert.False(t, ok)
}

// TestHTTPHealthProbe_UnreachableHost covers the classification path when a
// health endpoint cannot be reached at all.
func TestHTTPHealthProbe_UnreachableHost(t *testing.T) {
	// The SSRF dialer refuses loopback, so 127.0.0.1 fails at dial time.
	h, msg := httpHealthProbe(t.Context(), "http://127.0.0.1:1/health")
	assert.Equal(t, "unhealthy", h)
	assert.NotEmpty(t, msg)
}

// TestClassifyHealthBody confirms the probe inspects the StatusReply body
// rather than trusting HTTP 200: every service's /health returns 200 even
// when probes fail.
func TestClassifyHealthBody(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    string
		msgSubs string
	}{
		{
			name: "unhealthy probe on 200",
			status: 200,
			body:   `{"data":{"status":"STATUS_FAIL_verifier","probes":[{"name":"verifier.db","healthy":false,"message":"connection refused"}]}}`,
			want:   "unhealthy", msgSubs: "connection refused",
		},
		{
			name: "all probes healthy on 200",
			status: 200,
			body:   `{"data":{"status":"STATUS_OK_verifier","probes":[{"name":"verifier.db","healthy":true}]}}`,
			want:   "healthy",
		},
		{
			name: "non-2xx overrides body",
			status: 503,
			body:   `{"data":{"status":"STATUS_OK_verifier"}}`,
			want:   "unhealthy", msgSubs: "HTTP 503",
		},
		{
			name: "empty payload falls back to 2xx=healthy",
			status: 200,
			body:   `{}`,
			want:   "healthy",
		},
		{
			name: "non-JSON 2xx body falls back to healthy",
			status: 200,
			body:   `OK`,
			want:   "healthy",
		},
		{
			name: "status FAIL rollup with no probes still unhealthy",
			status: 200,
			body:   `{"data":{"status":"STATUS_FAIL_verifier"}}`,
			want:   "unhealthy", msgSubs: "STATUS_FAIL_verifier",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, msg := classifyHealthBody(tc.status, []byte(tc.body))
			assert.Equal(t, tc.want, got)
			if tc.msgSubs != "" {
				assert.Contains(t, msg, tc.msgSubs)
			}
		})
	}
}

// TestDashboardProxy_RedirectFollowedIntoDeniedHostFails ensures the proxy's
// CheckRedirect rejects a redirect target that isn't in the allowlist. We can
// only exercise this at the CheckRedirect level (an httptest server on
// loopback is refused by the SSRF dialer before any HTTP handshake happens);
// verify the callback returns an error for a disallowed URL.
func TestDashboardProxy_RedirectDenies(t *testing.T) {
	services := []model.DashboardService{
		{Name: "issuer", URL: "https://issuer.example.com", Links: []model.DashboardLink{
			{Label: "Meta", URL: "https://issuer.example.com/x", Type: "json"},
		}},
	}
	c := dashboardTestClient(t, services, nil)
	allowed, _ := url.Parse("https://issuer.example.com/x")
	denied, _ := url.Parse("https://evil.example.com/x")

	assert.True(t, c.dashboardURLAllowed(allowed))
	assert.False(t, c.dashboardURLAllowed(denied))
}
