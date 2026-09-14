package apiv1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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
// can't slow the whole dashboard down. Results are cached (dashboardProbeTTL)
// so repeated dashboard hits don't fan out to unbounded upstream traffic.
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
		if health, msg, ok := dashboardProbeCache.get(healthURL); ok {
			services[i].Health = health
			services[i].Message = msg
			continue
		}
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, perProbeTimeout)
			defer cancel()
			health, msg := httpHealthProbe(probeCtx, url)
			dashboardProbeCache.put(url, health, msg)
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

// httpHealthProbe issues a GET against url with an SSRF-safe transport (no
// redirects, private/loopback/link-local IPs rejected at dial time) and
// returns ("healthy", "") on a 2xx response, ("unhealthy", message) otherwise.
// Any transport error, non-2xx status, or timeout maps to "unhealthy".
func httpHealthProbe(ctx context.Context, target string) (string, string) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "unhealthy", "invalid url"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "unhealthy", err.Error()
	}
	client := newDashboardHTTPClient(0)
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unhealthy", err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "unhealthy", fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return "healthy", ""
}

// dashboardProbeTTL bounds how often /dashboard fans out to health links for
// services the aggregator doesn't cover. Short enough to stay useful, long
// enough that anonymous page hits can't drive unbounded upstream traffic.
const dashboardProbeTTL = 10 * time.Second

type probeCacheEntry struct {
	health, message string
	expires         time.Time
}

type probeCache struct {
	mu      sync.Mutex
	entries map[string]probeCacheEntry
}

func (p *probeCache) get(key string) (string, string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[key]
	if !ok || time.Now().After(e.expires) {
		return "", "", false
	}
	return e.health, e.message, true
}

func (p *probeCache) put(key, health, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries == nil {
		p.entries = map[string]probeCacheEntry{}
	}
	p.entries[key] = probeCacheEntry{health: health, message: message, expires: time.Now().Add(dashboardProbeTTL)}
}

var dashboardProbeCache = &probeCache{}

// newDashboardHTTPClient returns an HTTP client whose dialer resolves the
// target host and rejects any resolved IP that is loopback, private,
// link-local, multicast, or unspecified. This is the SSRF guardrail for every
// outbound request made on behalf of the anonymous /dashboard endpoints: an
// operator-advertised URL is only followed if its host resolves entirely to
// public addresses.
func newDashboardHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := dialer.Resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				a, ok := netip.AddrFromSlice(ip.IP)
				if !ok {
					continue
				}
				if !addrIsPublic(a) {
					lastErr = fmt.Errorf("dashboard: refusing to dial non-public address %s", a)
					continue
				}
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
				if derr == nil {
					return conn, nil
				}
				lastErr = derr
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("dashboard: no resolvable public address for %s", host)
			}
			return nil, lastErr
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func addrIsPublic(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	return true
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

	client := newDashboardHTTPClient(5 * time.Second)
	// Re-check every redirect target against the same allowlist. Without
	// this, a server on an allowed host could redirect the APIGW into
	// 127.0.0.1, cloud metadata, or another internal host on behalf of
	// an anonymous caller. The SSRF-safe dialer is a second line of defence
	// for hostnames that resolve to private IPs (DNS rebinding).
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if !c.dashboardURLAllowed(req.URL) {
			return errDashboardProxyDenied
		}
		return nil
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
	// Force a non-executable Content-Type: /dashboard/proxy is anonymous and
	// same-origin, so a direct navigation to it must never render an
	// allowlisted response as text/html or another active type. The dashboard
	// allowlist is JSON-only.
	return &DashboardProxyReply{Body: body, ContentType: "application/json; charset=utf-8", StatusCode: resp.StatusCode}, nil
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
