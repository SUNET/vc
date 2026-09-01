package revocation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
)

// maxCRLBytes bounds a CRL download. A national CA's list is measured in
// hundreds of kilobytes; anything past this is a misconfigured URL or a
// hostile response, and reading it into memory unbounded would be the more
// interesting bug.
const maxCRLBytes = 16 << 20

// CRLChecker reports whether an X.509 certificate appears on one of the CRLs
// its own distribution points name.
//
// It is deliberately separate from StatusListChecker: an access certificate
// (WRPAC) is revoked through an X.509 CRL, a registration certificate (WRPRC)
// through a Token Status List, and the two mechanisms share nothing but the
// word "revocation".
type CRLChecker struct {
	httpClient *http.Client
}

// CRLCheckerOption configures a CRLChecker.
type CRLCheckerOption func(*CRLChecker)

// WithCRLHTTPClient sets a custom HTTP client.
func WithCRLHTTPClient(client *http.Client) CRLCheckerOption {
	return func(c *CRLChecker) {
		c.httpClient = client
	}
}

// NewCRLChecker creates a CRL checker.
func NewCRLChecker(opts ...CRLCheckerOption) *CRLChecker {
	c := &CRLChecker{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CheckCertificate reports the certificate's revocation status according to
// its own CRL distribution points.
//
// The result is StatusUnknown, never StatusValid, when no usable distribution
// point exists or none could be fetched. An unreachable CRL is not evidence
// that a certificate is good, and collapsing the two is how a fetch failure
// becomes a silent pass.
//
// A certificate found on any fetched list is StatusInvalid immediately: one
// authority saying "revoked" is not softened by another failing to answer.
func (c *CRLChecker) CheckCertificate(ctx context.Context, cert *x509.Certificate) (*CheckResult, error) {
	result := &CheckResult{Status: StatusUnknown, CheckedAt: time.Now()}
	if cert == nil {
		return result, fmt.Errorf("no certificate to check")
	}

	endpoints := rpcert.CRLDistributionPoints(cert)
	if len(endpoints) == 0 {
		return result, fmt.Errorf("certificate names no fetchable CRL distribution point")
	}

	var lastErr error
	reached := false

	for _, uri := range endpoints {
		list, err := c.fetch(ctx, uri)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", uri, err)
			continue
		}
		reached = true
		result.URI = uri

		for _, revoked := range list.RevokedCertificateEntries {
			if revoked.SerialNumber != nil && revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				result.Status = StatusInvalid
				return result, nil
			}
		}
	}

	if !reached {
		return result, fmt.Errorf("no CRL distribution point could be fetched: %w", lastErr)
	}

	result.Status = StatusValid
	return result, nil
}

// fetch downloads and parses one CRL.
func (c *CRLChecker) fetch(ctx context.Context, uri string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	// Reject non-HTTP(S) schemes to reduce SSRF surface, as
	// StatusListChecker does. CRLDistributionPoints already filters these
	// out, so this guards fetch being called with anything else and keeps
	// the error ours rather than the transport's.
	switch req.URL.Scheme {
	case "http", "https":
		// allowed
	default:
		return nil, fmt.Errorf("unsupported CRL URI scheme: %q", req.URL.Scheme)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// Read one byte past the limit so an oversized list is reported as
	// such. Truncating at exactly the limit would hand ParseRevocationList
	// a half a CRL and surface as a parse error, which says nothing about
	// what actually went wrong.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxCRLBytes {
		return nil, fmt.Errorf("CRL exceeds maximum size (%d bytes)", maxCRLBytes)
	}

	// A CRL is DER; some distribution points serve PEM despite the spec, so
	// both are accepted rather than failing on a list we could plainly read.
	if der, ok := pemToDER(body); ok {
		body = der
	}

	list, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}
	return list, nil
}

// pemToDER unwraps a PEM-encoded CRL, reporting whether the input was PEM.
func pemToDER(body []byte) ([]byte, bool) {
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, false
	}
	return block.Bytes, true
}
