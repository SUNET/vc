package apiv1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	c.probeUnknownServices(ctx, services)

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

// probeUnknownServices HTTP-GETs the "Health" link of every service still
// classified "unknown" after the aggregator pass. Any service the aggregator
// doesn't know about (verifier is the canonical case — it isn't part of the
// issuance chain apigw's own /health tracks) gets a live probe here, without
// coupling those services back into apigw's readiness signal. Probes run in
// parallel with a short per-request timeout so a single unreachable service
// can't slow the whole dashboard down.
func (c *Client) probeUnknownServices(ctx context.Context, services []DashboardServiceView) {
	const perProbeTimeout = 2 * time.Second

	var wg sync.WaitGroup
	for i := range services {
		if services[i].Health != "unknown" {
			continue
		}
		healthURL := healthLinkURL(services[i].Links)
		if healthURL == "" {
			continue
		}
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, perProbeTimeout)
			defer cancel()
			health, msg := httpHealthProbe(probeCtx, url)
			services[idx].Health = health
			services[idx].Message = msg
		}(i, healthURL)
	}
	wg.Wait()
}

func healthLinkURL(links []model.DashboardLink) string {
	for _, l := range links {
		if l.Label == "Health" && l.URL != "" {
			return l.URL
		}
	}
	return ""
}

// httpHealthProbe issues a GET against url and returns ("healthy", "") on a
// 2xx response, ("unhealthy", message) otherwise. Any transport error, non-2xx
// status, or timeout maps to "unhealthy".
func httpHealthProbe(ctx context.Context, target string) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "unhealthy", err.Error()
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "unhealthy", err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "unhealthy", fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return "healthy", ""
}

// DashboardProxyReply carries a URL fetched by the dashboard proxy.
type DashboardProxyReply struct {
	Body        []byte
	ContentType string
	// StatusCode is the upstream HTTP status. Callers should forward it so a
	// 4xx/5xx from a proxied link is not silently rewritten to 200.
	StatusCode int
}

// dashboardProxyMaxBytes caps proxied response bodies. Dashboard targets are
// small (health, metadata, JWKS); anything larger is almost certainly wrong.
const dashboardProxyMaxBytes = 1 << 20 // 1 MiB

var errDashboardProxyDenied = errors.New("url not in dashboard allowlist")

// DashboardProxy fetches an allowlisted URL and returns the raw body, its
// Content-Type, and the upstream HTTP status. The allowlist is restricted to
// URLs explicitly advertised as JSON links in Dashboard.Services — path
// included — so this endpoint cannot be used as a general-purpose proxy for
// unadvertised paths on those hosts (metrics, admin, etc.).
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

	client := &http.Client{
		Timeout: 5 * time.Second,
		// Re-check every redirect target against the same allowlist. Without
		// this, a server on an allowed host could redirect the APIGW into
		// 127.0.0.1, cloud metadata, or another internal host on behalf of
		// an anonymous caller.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !c.dashboardURLAllowed(req.URL) {
				return errDashboardProxyDenied
			}
			return nil
		},
	}
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
	return &DashboardProxyReply{Body: body, ContentType: ct, StatusCode: resp.StatusCode}, nil
}

// dashboardURLAllowed returns true iff u exactly matches (scheme+host+path) a
// link advertised on Dashboard.Services with type "json". Query strings are
// ignored on both sides — they are the only bit callers might reasonably
// vary — but path is compared verbatim so an operator advertising
// "/.well-known/openid-configuration" does not implicitly grant access to
// "/metrics" or "/admin" on the same host.
func (c *Client) dashboardURLAllowed(u *url.URL) bool {
	if c.cfg == nil || c.cfg.APIGW == nil {
		return false
	}
	for _, s := range c.cfg.APIGW.Dashboard.Services {
		for _, l := range s.Links {
			if l.Type != "json" {
				continue
			}
			b, err := url.Parse(l.URL)
			if err != nil {
				continue
			}
			if b.Scheme == u.Scheme && b.Host == u.Host && b.Path == u.Path {
				return true
			}
		}
	}
	return false
}
