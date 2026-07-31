package revocation

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
)

// StatusListChecker implements the Checker interface using Token Status Lists
// (draft-ietf-oauth-status-list).
type StatusListChecker struct {
	httpClient  *http.Client
	cache       cache.Cache[[]uint8]
	keyResolver KeyResolver
}

// StatusListCheckerOption configures a StatusListChecker.
type StatusListCheckerOption func(*StatusListChecker)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.httpClient = client
	}
}

// WithCache sets an external cache implementation.
// The cache's TTL (set at creation time) controls how long status lists are cached.
func WithCache(ch cache.Cache[[]uint8]) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.cache = ch
	}
}

// WithKeyResolver sets the key resolver for verifying status list token signatures.
// The checker uses this internally to build format-specific verification (e.g., jwt.Keyfunc).
func WithKeyResolver(kr KeyResolver) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.keyResolver = kr
	}
}

// NewStatusListChecker creates a new Token Status List checker.
// A cache must be provided via WithCache.
func NewStatusListChecker(opts ...StatusListCheckerOption) (*StatusListChecker, error) {
	c := &StatusListChecker{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.cache == nil {
		return nil, errors.New("cache is required: use WithCache")
	}
	if c.keyResolver == nil {
		return nil, errors.New("key resolver is required: use WithKeyResolver")
	}

	return c, nil
}

// Supports returns true for the status_list scheme.
func (c *StatusListChecker) Supports(scheme Scheme) bool {
	return scheme == SchemeStatusList
}

// Extract extracts a Token Status List reference from credential claims.
func (c *StatusListChecker) Extract(claims map[string]any) *Reference {
	return ExtractStatusListReference(claims)
}

// CheckStatus checks the revocation status via Token Status List.
func (c *StatusListChecker) CheckStatus(ctx context.Context, ref *Reference) (*CheckResult, error) {
	if ref == nil {
		return nil, errors.New("status reference is required")
	}
	if ref.Scheme != SchemeStatusList {
		return nil, fmt.Errorf("unsupported scheme: %s", ref.Scheme)
	}
	if ref.URI == "" {
		return nil, errors.New("status list URI is required")
	}
	if ref.Index < 0 {
		return nil, errors.New("status index must be non-negative")
	}

	statuses, err := c.getStatusList(ctx, ref.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get status list: %w", err)
	}

	if ref.Index >= int64(len(statuses)) {
		return nil, fmt.Errorf("status index %d out of range (list size: %d)", ref.Index, len(statuses))
	}

	statusCode := statuses[ref.Index]
	status := mapStatusCode(statusCode)

	return &CheckResult{
		Status:     status,
		StatusCode: statusCode,
		CheckedAt:  time.Now(),
		URI:        ref.URI,
		Index:      ref.Index,
	}, nil
}

func (c *StatusListChecker) getStatusList(ctx context.Context, uri string) ([]uint8, error) {
	if statuses, ok := c.cache.Get(ctx, uri); ok {
		return statuses, nil
	}

	statuses, err := c.fetchStatusList(ctx, uri)
	if err != nil {
		return nil, err
	}

	c.cache.Set(ctx, uri, statuses)
	return statuses, nil
}

func (c *StatusListChecker) fetchStatusList(ctx context.Context, uri string) ([]uint8, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Reject non-HTTP(S) schemes to reduce SSRF surface
	switch req.URL.Scheme {
	case "http", "https":
		// allowed
	default:
		return nil, fmt.Errorf("unsupported status list URI scheme: %q", req.URL.Scheme)
	}

	req.Header.Set("Accept", fmt.Sprintf("%s, %s", tokenstatuslist.MediaTypeJWT, tokenstatuslist.MediaTypeCWT))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch status list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status list request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	return c.parseStatusListToken(ctx, body, contentType)
}

func (c *StatusListChecker) parseStatusListToken(ctx context.Context, data []byte, contentType string) ([]uint8, error) {
	switch contentType {
	case tokenstatuslist.MediaTypeCWT:
		return c.parseCWTStatusList(ctx, data)
	case tokenstatuslist.MediaTypeJWT:
		return c.parseJWTStatusList(ctx, data)
	default:
		if len(data) > 0 && data[0] == 0xD2 {
			return c.parseCWTStatusList(ctx, data)
		}
		return c.parseJWTStatusList(ctx, data)
	}
}

func (c *StatusListChecker) parseCWTStatusList(ctx context.Context, data []byte) ([]uint8, error) {
	// Decode COSE_Sign1 (CBOR Tag 18)
	var coseTag cbor.Tag
	if err := cbor.Unmarshal(data, &coseTag); err != nil {
		return nil, fmt.Errorf("failed to decode COSE_Sign1: %w", err)
	}
	if coseTag.Number != 18 {
		return nil, fmt.Errorf("invalid COSE tag: expected 18 (COSE_Sign1), got %d", coseTag.Number)
	}

	components, ok := coseTag.Content.([]any)
	if !ok || len(components) != 4 {
		return nil, fmt.Errorf("invalid COSE_Sign1 structure")
	}

	protectedBytes, _ := components[0].([]byte)
	unprotected, _ := components[1].(map[any]any)
	payloadBytes, _ := components[2].([]byte)
	signature, _ := components[3].([]byte)

	sign1 := &mdoc.COSESign1{
		Protected:   protectedBytes,
		Unprotected: unprotected,
		Payload:     payloadBytes,
		Signature:   signature,
	}

	// Extract key ID from protected headers
	var headers map[int64]any
	if err := cbor.Unmarshal(protectedBytes, &headers); err != nil {
		return nil, fmt.Errorf("failed to decode CWT protected headers: %w", err)
	}
	kid, _ := headers[mdoc.HeaderKeyID].(string)
	if kidBytes, ok := headers[mdoc.HeaderKeyID].([]byte); ok {
		kid = string(kidBytes)
	}

	// Decode CWT claims to extract issuer
	var claims map[int]any
	if err := cbor.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode CWT claims: %w", err)
	}
	issuer, _ := claims[1].(string) // CWT claim 1 = iss

	// Resolve signing key and verify signature
	key, err := c.keyResolver.ResolveKey(ctx, issuer, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CWT signing key: %w", err)
	}
	pubKey, ok := key.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("resolved key is not a crypto.PublicKey: %T", key)
	}
	if err := mdoc.Verify1(sign1, nil, pubKey, nil); err != nil {
		return nil, fmt.Errorf("CWT signature verification failed: %w", err)
	}

	// Extract status list from verified claims
	statusListRaw, ok := claims[65534]
	if !ok {
		return nil, errors.New("status_list claim not found in CWT")
	}

	var lstBytes []byte
	switch sl := statusListRaw.(type) {
	case map[any]any:
		for k, v := range sl {
			switch key := k.(type) {
			case int:
				if key == 2 {
					if b, ok := v.([]byte); ok {
						lstBytes = b
					}
				}
			case int64:
				if key == 2 {
					if b, ok := v.([]byte); ok {
						lstBytes = b
					}
				}
			case uint64:
				if key == 2 {
					if b, ok := v.([]byte); ok {
						lstBytes = b
					}
				}
			}
		}
	case map[int]any:
		if b, ok := sl[2].([]byte); ok {
			lstBytes = b
		}
	default:
		return nil, fmt.Errorf("invalid status_list claim format: %T", statusListRaw)
	}

	if lstBytes == nil {
		return nil, errors.New("lst not found in status_list claim")
	}

	return tokenstatuslist.DecompressStatuses(lstBytes)
}

func (c *StatusListChecker) parseJWTStatusList(ctx context.Context, data []byte) ([]uint8, error) {
	tokenString := string(data)

	if c.keyResolver == nil {
		return nil, errors.New("status list JWT signature verification required but no key resolver configured")
	}

	// Build a jwt.Keyfunc that delegates to the generic KeyResolver
	keyFunc := func(token *jwt.Token) (any, error) {
		claims, _ := token.Claims.(jwt.MapClaims)
		issuer, _ := claims["iss"].(string)
		kid, _ := token.Header["kid"].(string)
		if issuer == "" {
			return nil, errors.New("status list token missing iss claim")
		}
		return c.keyResolver.ResolveKey(ctx, issuer, kid)
	}

	token, err := jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods([]string{
		"ES256", "ES384", "ES512",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"EdDSA",
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("invalid JWT token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to extract JWT claims")
	}

	statusListClaim, ok := claims["status_list"].(map[string]any)
	if !ok {
		return nil, errors.New("status_list claim not found or invalid")
	}

	lst, ok := statusListClaim["lst"].(string)
	if !ok {
		return nil, errors.New("lst not found in status_list claim")
	}

	return tokenstatuslist.DecodeAndDecompress(lst)
}

func mapStatusCode(code uint8) Status {
	switch code {
	case tokenstatuslist.StatusValid:
		return StatusValid
	case tokenstatuslist.StatusInvalid:
		return StatusInvalid
	case tokenstatuslist.StatusSuspended:
		return StatusSuspended
	default:
		return StatusUnknown
	}
}
