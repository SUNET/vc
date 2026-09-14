package apiv1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/model"
)

// DashboardReply is the view model rendered by GET /dashboard.
type DashboardReply struct {
	Title    string
	Services []DashboardServiceView
}

// DashboardServiceView is a single service card on the dashboard.
type DashboardServiceView struct {
	Name        string
	URL         string
	Description string
	Links       []model.DashboardLink
	// Health is "healthy", "unhealthy" or "unknown".
	Health string
	// Message carries the first failing probe message when Health=="unhealthy".
	Message string
}

// Dashboard builds the /dashboard view model from cfg.APIGW.Dashboard.Services
// (seeded from sibling sections at config load, plus operator overrides) and
// joins per-service health from the cached status aggregator.
func (c *Client) Dashboard(ctx context.Context) (*DashboardReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:Dashboard")
	defer span.End()

	title := c.cfg.APIGW.Dashboard.Title
	if title == "" {
		title = "SUNET Verifiable Credentials"
	}

	entries := c.cfg.APIGW.Dashboard.Services
	services := make([]DashboardServiceView, 0, len(entries))
	for _, s := range entries {
		services = append(services, DashboardServiceView{
			Name:        s.Name,
			URL:         s.URL,
			Description: s.Description,
			Links:       s.Links,
		})
	}

	c.applyHealth(ctx, services)

	return &DashboardReply{Title: title, Services: services}, nil
}

// applyHealth joins per-service health from the cached aggregator onto the
// service views. A service is healthy iff every probe named "<service>." is
// healthy. A downstream-fetch failure emits a synthetic probe named
// "apigw.<service>" (the outer aggregator prefixes unqualified names with its
// own service prefix); that exact name is also matched, so an unreachable
// issuer or registry surfaces as "unhealthy" rather than "unknown". Services
// with no probes (e.g. verifier, which apigw does not aggregate) are marked
// "unknown".
func (c *Client) applyHealth(ctx context.Context, services []DashboardServiceView) {
	if c.statusAggregator == nil {
		for i := range services {
			services[i].Health = "unknown"
		}
		return
	}
	reply := c.statusAggregator.Reply(ctx)
	probes := reply.GetData().GetProbes()
	svcName := reply.GetData().GetServiceName()

	for i := range services {
		prefix := services[i].Name + "."
		unreachableName := svcName + "." + services[i].Name
		healthy := true
		var msg string
		seen := false
		for _, p := range probes {
			name := p.GetName()
			if !strings.HasPrefix(name, prefix) && name != unreachableName {
				continue
			}
			seen = true
			if !p.GetHealthy() {
				healthy = false
				if msg == "" {
					msg = name + ": " + p.GetMessage()
				}
			}
		}
		switch {
		case !seen:
			services[i].Health = "unknown"
		case healthy:
			services[i].Health = "healthy"
		default:
			services[i].Health = "unhealthy"
			services[i].Message = msg
		}
	}
}

// DashboardProxyReply carries a URL fetched by the dashboard proxy.
type DashboardProxyReply struct {
	Body        []byte
	ContentType string
}

// dashboardProxyMaxBytes caps proxied response bodies. Dashboard targets are
// small (health, metadata, JWKS); anything larger is almost certainly wrong.
const dashboardProxyMaxBytes = 1 << 20 // 1 MiB

var errDashboardProxyDenied = errors.New("url not in dashboard allowlist")

// DashboardProxy fetches an allowlisted URL and returns the raw body plus its
// Content-Type. The allowlist is derived from the seeded Dashboard.Services
// list, so only hosts the operator (implicitly or explicitly) advertised on
// the dashboard can be reached — this endpoint is not a general-purpose proxy.
func (c *Client) DashboardProxy(ctx context.Context, target string) (*DashboardProxyReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:DashboardProxy")
	defer span.End()

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errDashboardProxyDenied
	}
	if !c.dashboardURLAllowed(u) {
		return nil, errDashboardProxyDenied
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, */*")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, dashboardProxyMaxBytes))
	if err != nil {
		return nil, err
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	return &DashboardProxyReply{Body: body, ContentType: ct}, nil
}

func (c *Client) dashboardURLAllowed(u *url.URL) bool {
	if c.cfg == nil || c.cfg.APIGW == nil {
		return false
	}
	sameHost := func(rawBase string) bool {
		b, err := url.Parse(rawBase)
		if err != nil {
			return false
		}
		return b.Scheme == u.Scheme && b.Host == u.Host
	}
	for _, s := range c.cfg.APIGW.Dashboard.Services {
		if sameHost(s.URL) {
			return true
		}
		for _, l := range s.Links {
			if sameHost(l.URL) {
				return true
			}
		}
	}
	return false
}
