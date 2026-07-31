package revocation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/golang-jwt/jwt/v5"
)

// StatusListChecker implements the Checker interface using Token Status Lists
// (draft-ietf-oauth-status-list).
type StatusListChecker struct {
	httpClient  *http.Client
	cache       cache.Cache[[]uint8]
	cacheExpiry time.Duration
	keyFunc     jwt.Keyfunc
}

// StatusListCheckerOption configures a StatusListChecker.
type StatusListCheckerOption func(*StatusListChecker)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.httpClient = client
	}
}

// WithCacheExpiry sets the cache expiry duration.
func WithCacheExpiry(expiry time.Duration) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.cacheExpiry = expiry
	}
}

// WithCache sets an external cache implementation.
func WithCache(ch cache.Cache[[]uint8]) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.cache = ch
	}
}

// WithKeyFunc sets the key function for JWT signature verification.
func WithKeyFunc(keyFunc jwt.Keyfunc) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.keyFunc = keyFunc
	}
}

// NewStatusListChecker creates a new Token Status List checker.
// A cache must be provided via WithCache.
func NewStatusListChecker(opts ...StatusListCheckerOption) (*StatusListChecker, error) {
	c := &StatusListChecker{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cacheExpiry: 5 * time.Minute,
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.cache == nil {
		return nil, errors.New("cache is required: use WithCache")
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
	return c.parseStatusListToken(body, contentType)
}

func (c *StatusListChecker) parseStatusListToken(data []byte, contentType string) ([]uint8, error) {
	switch contentType {
	case tokenstatuslist.MediaTypeCWT:
		return c.parseCWTStatusList(data)
	case tokenstatuslist.MediaTypeJWT:
		return c.parseJWTStatusList(data)
	default:
		if len(data) > 0 && data[0] == 0xD2 {
			return c.parseCWTStatusList(data)
		}
		return c.parseJWTStatusList(data)
	}
}

func (c *StatusListChecker) parseCWTStatusList(data []byte) ([]uint8, error) {
	claims, err := tokenstatuslist.ParseCWT(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CWT status list: %w", err)
	}

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

func (c *StatusListChecker) parseJWTStatusList(data []byte) ([]uint8, error) {
	tokenString := string(data)

	if c.keyFunc != nil {
		token, err := jwt.Parse(tokenString, c.keyFunc)
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

	// Parse without signature verification (extract claims only)
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		StatusList struct {
			Lst string `json:"lst"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return tokenstatuslist.DecodeAndDecompress(claims.StatusList.Lst)
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
