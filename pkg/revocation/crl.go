package revocation

import (
	"bytes"
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
//
// issuer is the CA certificate that signed cert, and is required: a CRL is
// otherwise just bytes from a URL, and only its signature makes it evidence
// of anything. A nil issuer is StatusUnknown, not StatusValid.
func (c *CRLChecker) CheckCertificate(ctx context.Context, cert, issuer *x509.Certificate) (*CheckResult, error) {
	result := &CheckResult{Status: StatusUnknown, CheckedAt: time.Now()}
	if cert == nil {
		return result, fmt.Errorf("no certificate to check")
	}
	if issuer == nil {
		return result, fmt.Errorf("no issuer certificate to authenticate the CRL against")
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
		// An unauthenticated list is not a reached distribution point. It
		// must not set reached, or a forged empty CRL would end the loop at
		// StatusValid - the exact silent pass this type exists to avoid.
		if err := verifyList(list, cert, issuer, result.CheckedAt); err != nil {
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
		return result, fmt.Errorf("no CRL distribution point yielded an authenticated list: %w", lastErr)
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
	// The block type is checked so an endpoint serving some other PEM object
	// - a certificate, most likely - fails as "not a CRL" rather than as an
	// opaque DER parse error further down.
	if block, _ := pem.Decode(body); block != nil {
		if block.Type != "X509 CRL" && block.Type != "CRL" {
			return nil, fmt.Errorf("PEM block is %q, not a CRL", block.Type)
		}
		body = block.Bytes
	}

	list, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}
	return list, nil
}

// verifyList authenticates a fetched CRL against the CA that issued the
// certificate under test.
//
// Without this the list is attacker-controlled input: whoever can answer the
// distribution point URI - a compromised CA endpoint, anyone on the path of a
// plain-http one - could hand us a list naming our own serial and have us
// report ourselves revoked, or an empty list and have us report a genuinely
// revoked certificate as good.
func verifyList(list *x509.RevocationList, cert, issuer *x509.Certificate, now time.Time) error {
	// RFC 5280 clause 6.3.3: the CRL must come from the certificate's own
	// issuer. Checking the signature alone would accept a validly signed
	// list from some other CA that happens to reuse a serial number.
	if !bytes.Equal(list.RawIssuer, cert.RawIssuer) {
		return fmt.Errorf("CRL issuer %q is not the certificate issuer %q", list.Issuer, cert.Issuer)
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL signature: %w", err)
	}
	// An expired list is stale evidence, not evidence of validity: honouring
	// it would freeze our answer at whatever a CA said before it stopped
	// publishing. Undetermined is the honest reading.
	if !list.NextUpdate.IsZero() && now.After(list.NextUpdate) {
		return fmt.Errorf("CRL expired at %s", list.NextUpdate.Format(time.RFC3339))
	}
	if !list.ThisUpdate.IsZero() && now.Before(list.ThisUpdate) {
		return fmt.Errorf("CRL is not valid until %s", list.ThisUpdate.Format(time.RFC3339))
	}
	return nil
}
