// Package registry provides trust registry management.
// This file implements SSRF-safe HTTP client utilities.
package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// SafeClientConfig configures SSRF protection for HTTP clients.
type SafeClientConfig struct {
	// AllowPrivateIPs permits requests to private/internal networks.
	// Default: false (private IPs are blocked).
	// Use only in controlled environments (e.g., testing, corporate networks).
	AllowPrivateIPs bool

	// AllowedHosts restricts requests to specific hostnames.
	// Empty means all hosts are allowed (after other checks).
	AllowedHosts []string

	// AllowHTTP permits non-TLS (HTTP) connections.
	// Default: false (HTTPS required).
	AllowHTTP bool

	// Timeout for HTTP requests.
	// Default: 30 seconds.
	Timeout time.Duration

	// InsecureSkipVerify disables TLS certificate verification.
	// Use only for testing.
	InsecureSkipVerify bool
}

// SafeHTTPClient wraps http.Client with SSRF protections.
//
// SSRF protections include:
//   - Private/internal IP address blocking (configurable)
//   - Cloud metadata endpoint blocking (169.254.169.254)
//   - HTTPS enforcement (configurable)
//   - Optional host allowlisting
//   - DNS rebinding protection via IP validation after resolution
type SafeHTTPClient struct {
	client       *http.Client
	config       SafeClientConfig
	allowedHosts map[string]bool
}

// NewSafeHTTPClient creates an HTTP client with SSRF protections.
//
// Example usage:
//
//	client := NewSafeHTTPClient(SafeClientConfig{
//	    Timeout: 30 * time.Second,
//	})
//	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
//	resp, err := client.Do(req)
func NewSafeHTTPClient(config SafeClientConfig) *SafeHTTPClient {
	allowedHosts := make(map[string]bool)
	for _, h := range config.AllowedHosts {
		allowedHosts[strings.ToLower(h)] = true
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Create a custom dialer that validates IP addresses after DNS resolution.
	// This provides DNS rebinding protection by checking the actual resolved IP.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Clone http.DefaultTransport to preserve proxy settings (HTTP_PROXY/HTTPS_PROXY/NO_PROXY)
	// and other default behavior, then customize for SSRF protection.
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		defaultTransport = &http.Transport{}
	}
	transport := defaultTransport.Clone()

	// Override DialContext for IP validation (DNS rebinding protection)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		// Resolve DNS first to check the actual IP addresses
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("DNS lookup returned no addresses for %s", host)
		}

		// Check all resolved IPs before connecting
		if !config.AllowPrivateIPs {
			for _, ip := range ips {
				if IsPrivateIP(ip) {
					return nil, fmt.Errorf("SSRF protection: refusing connection to private/internal IP %s (resolved from %s)", ip, host)
				}
			}
		}

		// Connect using the first resolved IP to prevent DNS rebinding
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}

	// Harden TLS configuration
	transport.TLSHandshakeTimeout = 10 * time.Second
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.TLSClientConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	transport.TLSClientConfig.InsecureSkipVerify = config.InsecureSkipVerify

	client := &SafeHTTPClient{
		config:       config,
		allowedHosts: allowedHosts,
	}

	// Create HTTP client with redirect validation to prevent SSRF bypass via redirects
	client.client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Validate each redirect target for SSRF protection
			if err := client.validateRequest(req); err != nil {
				return fmt.Errorf("SSRF validation failed on redirect: %w", err)
			}
			// Preserve standard redirect limit (10)
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	return client
}

// Do executes an HTTP request with SSRF validation.
//
// The request is validated for:
//   - URL scheme (HTTPS required unless AllowHTTP is set)
//   - Host allowlist (if configured)
//
// The underlying dialer additionally checks resolved IP addresses.
func (c *SafeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.validateRequest(req); err != nil {
		return nil, fmt.Errorf("SSRF validation failed: %w", err)
	}
	return c.client.Do(req)
}

// validateRequest performs pre-request SSRF validation.
func (c *SafeHTTPClient) validateRequest(req *http.Request) error {
	u := req.URL

	// Scheme validation
	if !c.config.AllowHTTP && u.Scheme != "https" {
		return fmt.Errorf("HTTPS required, got scheme %q", u.Scheme)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}

	// Host allowlist check
	if len(c.allowedHosts) > 0 {
		host := strings.ToLower(u.Hostname())
		if !c.allowedHosts[host] {
			return fmt.Errorf("host %q not in allowlist", host)
		}
	}

	return nil
}

// IsPrivateIP checks if an IP address is private, internal, or otherwise
// unsuitable for external requests.
//
// Returns true for:
//   - Loopback addresses (127.0.0.0/8, ::1)
//   - Private addresses (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//   - Unique local addresses (RFC 4193: fd00::/8)
//   - Link-local addresses (169.254.0.0/16, fe80::/10)
//   - Unspecified addresses (0.0.0.0, ::)
//   - Cloud metadata endpoints (169.254.169.254)
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true // Treat nil as private (defensive)
	}

	// Standard checks from net package
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	// Cloud metadata endpoint protection
	// AWS, GCP, Azure all use 169.254.169.254 for instance metadata
	// This is a link-local address but worth explicit mention
	cloudMetadata := net.ParseIP("169.254.169.254")
	return ip.Equal(cloudMetadata)
}

// HTTPClientInterface defines the interface for HTTP clients used by registries.
// This allows using either a standard http.Client or SafeHTTPClient.
type HTTPClientInterface interface {
	Do(req *http.Request) (*http.Response, error)
}
