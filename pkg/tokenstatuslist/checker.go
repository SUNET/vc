package tokenstatuslist

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

	"github.com/golang-jwt/jwt/v5"
)

// StatusReference contains the status list reference embedded in a credential.
// This follows the draft-ietf-oauth-status-list specification.
// Used by both SD-JWT (via "status" claim) and mDoc credentials.
type StatusReference struct {
	// URI is the URI of the Status List Token.
	URI string `json:"uri"`
	// Index is the index within the status list for this credential.
	Index int64 `json:"idx"`
}

// CredentialStatus represents the revocation status of a credential.
type CredentialStatus int

const (
	// CredentialStatusValid indicates the credential is valid (not revoked).
	CredentialStatusValid CredentialStatus = iota
	// CredentialStatusInvalid indicates the credential has been revoked.
	CredentialStatusInvalid
	// CredentialStatusSuspended indicates the credential is temporarily suspended.
	CredentialStatusSuspended
	// CredentialStatusUnknown indicates the status could not be determined.
	CredentialStatusUnknown
)

// String returns a string representation of the credential status.
func (s CredentialStatus) String() string {
	switch s {
	case CredentialStatusValid:
		return "valid"
	case CredentialStatusInvalid:
		return "invalid"
	case CredentialStatusSuspended:
		return "suspended"
	default:
		return "unknown"
	}
}

// MapStatusCode maps a raw status code byte to a CredentialStatus.
func MapStatusCode(code uint8) CredentialStatus {
	switch code {
	case StatusValid:
		return CredentialStatusValid
	case StatusInvalid:
		return CredentialStatusInvalid
	case StatusSuspended:
		return CredentialStatusSuspended
	default:
		return CredentialStatusUnknown
	}
}

// ExtractStatusReference extracts a StatusReference from SD-JWT credential claims.
// Returns nil if no status claim is present (credential is not revocable).
// Returns error if status claim is malformed.
func ExtractStatusReference(claims map[string]any) (*StatusReference, error) {
	statusRaw, ok := claims["status"]
	if !ok {
		return nil, nil // No status claim — credential is not revocable
	}

	statusMap, ok := statusRaw.(map[string]any)
	if !ok {
		return nil, nil // Status claim is not a map — ignore
	}

	statusListRaw, ok := statusMap["status_list"]
	if !ok {
		return nil, nil // No status_list sub-claim
	}

	statusList, ok := statusListRaw.(map[string]any)
	if !ok {
		return nil, nil // status_list is not a map
	}

	uri, _ := statusList["uri"].(string)
	if uri == "" {
		return nil, nil // No URI — can't check
	}

	var index int64
	switch idx := statusList["idx"].(type) {
	case float64:
		index = int64(idx)
	case int64:
		index = idx
	case int:
		index = int64(idx)
	case json.Number:
		i, err := idx.Int64()
		if err != nil {
			return nil, nil
		}
		index = i
	default:
		return nil, nil // No valid index
	}

	return &StatusReference{URI: uri, Index: index}, nil
}

// StatusCheckResult contains the result of a credential status check.
type StatusCheckResult struct {
	// Status is the credential status (valid, invalid, suspended).
	Status CredentialStatus
	// StatusCode is the raw status code from the status list.
	StatusCode uint8
	// CheckedAt is the timestamp when the status was checked.
	CheckedAt time.Time
	// StatusListURI is the URI of the status list that was checked.
	StatusListURI string
	// Index is the index in the status list.
	Index int64
}

// StatusChecker checks the revocation status of credentials using Token Status Lists.
type StatusChecker struct {
	httpClient  *http.Client
	cache       cache.Cache[[]uint8]
	cacheExpiry time.Duration
	keyFunc     jwt.Keyfunc
}

// StatusCheckerOption configures the StatusChecker.
type StatusCheckerOption func(*StatusChecker)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) StatusCheckerOption {
	return func(sc *StatusChecker) {
		sc.httpClient = client
	}
}

// WithCacheExpiry sets the cache expiry duration.
func WithCacheExpiry(expiry time.Duration) StatusCheckerOption {
	return func(sc *StatusChecker) {
		sc.cacheExpiry = expiry
	}
}

// WithStatusCache sets an external cache implementation.
func WithStatusCache(c cache.Cache[[]uint8]) StatusCheckerOption {
	return func(sc *StatusChecker) {
		sc.cache = c
	}
}

// WithKeyFunc sets the key function for JWT signature verification of status list tokens.
func WithKeyFunc(keyFunc jwt.Keyfunc) StatusCheckerOption {
	return func(sc *StatusChecker) {
		sc.keyFunc = keyFunc
	}
}

// NewStatusChecker creates a new StatusChecker.
// A cache must be provided via WithStatusCache.
func NewStatusChecker(opts ...StatusCheckerOption) (*StatusChecker, error) {
	sc := &StatusChecker{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cacheExpiry: 5 * time.Minute,
	}

	for _, opt := range opts {
		opt(sc)
	}

	if sc.cache == nil {
		return nil, errors.New("cache is required: use WithStatusCache")
	}

	return sc, nil
}

// CheckStatus checks the status of a credential using its status reference.
func (sc *StatusChecker) CheckStatus(ctx context.Context, ref *StatusReference) (*StatusCheckResult, error) {
	if ref == nil {
		return nil, errors.New("status reference is required")
	}
	if ref.URI == "" {
		return nil, errors.New("status list URI is required")
	}
	if ref.Index < 0 {
		return nil, errors.New("status index must be non-negative")
	}

	statuses, err := sc.getStatusList(ctx, ref.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get status list: %w", err)
	}

	if ref.Index >= int64(len(statuses)) {
		return nil, fmt.Errorf("status index %d out of range (list size: %d)", ref.Index, len(statuses))
	}

	statusCode := statuses[ref.Index]
	status := MapStatusCode(statusCode)

	return &StatusCheckResult{
		Status:        status,
		StatusCode:    statusCode,
		CheckedAt:     time.Now(),
		StatusListURI: ref.URI,
		Index:         ref.Index,
	}, nil
}

func (sc *StatusChecker) getStatusList(ctx context.Context, uri string) ([]uint8, error) {
	if statuses, ok := sc.cache.Get(ctx, uri); ok {
		return statuses, nil
	}

	statuses, err := sc.fetchStatusList(ctx, uri)
	if err != nil {
		return nil, err
	}

	sc.cache.Set(ctx, uri, statuses)
	return statuses, nil
}

func (sc *StatusChecker) fetchStatusList(ctx context.Context, uri string) ([]uint8, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", fmt.Sprintf("%s, %s", MediaTypeJWT, MediaTypeCWT))

	resp, err := sc.httpClient.Do(req)
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
	return sc.parseStatusListToken(body, contentType)
}

func (sc *StatusChecker) parseStatusListToken(data []byte, contentType string) ([]uint8, error) {
	switch contentType {
	case MediaTypeCWT:
		return sc.parseCWTStatusList(data)
	case MediaTypeJWT:
		return sc.parseJWTStatusList(data)
	default:
		if len(data) > 0 && data[0] == 0xD2 {
			return sc.parseCWTStatusList(data)
		}
		return sc.parseJWTStatusList(data)
	}
}

func (sc *StatusChecker) parseCWTStatusList(data []byte) ([]uint8, error) {
	claims, err := ParseCWT(data)
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

	return DecompressStatuses(lstBytes)
}

func (sc *StatusChecker) parseJWTStatusList(data []byte) ([]uint8, error) {
	tokenString := string(data)

	if sc.keyFunc != nil {
		token, err := jwt.Parse(tokenString, sc.keyFunc)
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

		return DecodeAndDecompress(lst)
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

	return DecodeAndDecompress(claims.StatusList.Lst)
}
