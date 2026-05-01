// Package mdoc implements the ISO/IEC 18013-5:2021 Mobile Driving Licence (mDL) data model.
package mdoc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/golang-jwt/jwt/v5"
)

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

// CredentialStatus represents the status of a credential.
type CredentialStatus int

const (
	// CredentialStatusValid indicates the credential is valid.
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

// StatusReference contains the status list reference embedded in an mDL.
// This follows the draft-ietf-oauth-status-list specification.
type StatusReference struct {
	// URI is the URI of the Status List Token.
	URI string `json:"uri" cbor:"uri"`
	// Index is the index within the status list for this credential.
	Index int64 `json:"idx" cbor:"idx"`
}

// StatusChecker checks the revocation status of mDL credentials.
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

// WithStatusCache sets an external cache implementation (e.g. MongoCache for HA).
func WithStatusCache(c cache.Cache[[]uint8]) StatusCheckerOption {
	return func(sc *StatusChecker) {
		sc.cache = c
	}
}

// WithKeyFunc sets the key function for JWT verification.
func WithKeyFunc(keyFunc jwt.Keyfunc) StatusCheckerOption {
	return func(sc *StatusChecker) {
		sc.keyFunc = keyFunc
	}
}

// NewStatusChecker creates a new StatusChecker.
// A cache must be provided via WithStatusCache.
// TODO(masv): wire into the verifier so status checking is actually performed at presentation time.
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

	// Check cache first
	statuses, err := sc.getStatusList(ctx, ref.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get status list: %w", err)
	}

	// Get status at index
	if ref.Index >= int64(len(statuses)) {
		return nil, fmt.Errorf("status index %d out of range (list size: %d)", ref.Index, len(statuses))
	}

	statusCode := statuses[ref.Index]
	status := mapStatusCode(statusCode)

	return &StatusCheckResult{
		Status:        status,
		StatusCode:    statusCode,
		CheckedAt:     time.Now(),
		StatusListURI: ref.URI,
		Index:         ref.Index,
	}, nil
}

// getStatusList retrieves the status list, using cache if available.
func (sc *StatusChecker) getStatusList(ctx context.Context, uri string) ([]uint8, error) {
	if statuses, ok := sc.cache.Get(ctx, uri); ok {
		return statuses, nil
	}

	// Fetch from URI
	statuses, err := sc.fetchStatusList(ctx, uri)
	if err != nil {
		return nil, err
	}

	// Cache the result
	sc.cache.Set(ctx, uri, statuses)

	return statuses, nil
}

// fetchStatusList fetches and parses a status list from a URI.
func (sc *StatusChecker) fetchStatusList(ctx context.Context, uri string) ([]uint8, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Accept both JWT and CWT formats
	req.Header.Set("Accept", fmt.Sprintf("%s, %s", tokenstatuslist.MediaTypeJWT, tokenstatuslist.MediaTypeCWT))

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

	// Parse based on content type
	contentType := resp.Header.Get("Content-Type")
	return sc.parseStatusListToken(body, contentType)
}

// parseStatusListToken parses a status list token (JWT or CWT format).
func (sc *StatusChecker) parseStatusListToken(data []byte, contentType string) ([]uint8, error) {
	// Try to parse based on content type or auto-detect
	switch contentType {
	case tokenstatuslist.MediaTypeCWT:
		return sc.parseCWTStatusList(data)
	case tokenstatuslist.MediaTypeJWT:
		return sc.parseJWTStatusList(data)
	default:
		// Try to auto-detect based on content
		if len(data) > 0 && data[0] == 0xD2 {
			// CBOR tag 18 (COSE_Sign1) starts with 0xD2
			return sc.parseCWTStatusList(data)
		}
		// Assume JWT format
		return sc.parseJWTStatusList(data)
	}
}

// parseCWTStatusList parses a CWT format status list token.
func (sc *StatusChecker) parseCWTStatusList(data []byte) ([]uint8, error) {
	// Parse the CWT and extract the status list
	claims, err := tokenstatuslist.ParseCWT(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CWT status list: %w", err)
	}

	// Extract the status_list claim (key 65534)
	statusListRaw, ok := claims[65534]
	if !ok {
		return nil, errors.New("status_list claim not found in CWT")
	}

	// Extract lst bytes from the status_list claim
	var lstBytes []byte
	switch sl := statusListRaw.(type) {
	case map[any]any:
		for k, v := range sl {
			// Key 2 is "lst"
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

	// Decompress the status list
	return tokenstatuslist.DecompressStatuses(lstBytes)
}

// parseJWTStatusList parses a JWT format status list token.
func (sc *StatusChecker) parseJWTStatusList(data []byte) ([]uint8, error) {
	tokenString := string(data)

	// If a key function is provided, verify the signature
	if sc.keyFunc != nil {
		token, err := jwt.Parse(tokenString, sc.keyFunc)
		if err != nil {
			return nil, fmt.Errorf("failed to verify JWT: %w", err)
		}
		if !token.Valid {
			return nil, errors.New("invalid JWT token")
		}

		// Extract claims from verified token
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

	// Parse without verification (just extract claims)
	// Split the token to get the payload
	parts := splitJWT(tokenString)
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	// Decode the payload
	payload, err := base64RawURLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the claims
	var claims struct {
		StatusList struct {
			Lst string `json:"lst"`
		} `json:"status_list"`
	}

	if err := parseJSON(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Decode and decompress the status list
	return tokenstatuslist.DecodeAndDecompress(claims.StatusList.Lst)
}

// mapStatusCode maps a raw status code to a CredentialStatus.
func mapStatusCode(code uint8) CredentialStatus {
	switch code {
	case tokenstatuslist.StatusValid:
		return CredentialStatusValid
	case tokenstatuslist.StatusInvalid:
		return CredentialStatusInvalid
	case tokenstatuslist.StatusSuspended:
		return CredentialStatusSuspended
	default:
		return CredentialStatusUnknown
	}
}

// StatusManager manages credential status for an issuer.
type StatusManager struct {
	statusList *tokenstatuslist.StatusList
	nextIndex  int64
	uri        string
}

// NewStatusManager creates a new StatusManager for issuing credentials with status.
func NewStatusManager(uri string, initialSize int) *StatusManager {
	statuses := make([]uint8, initialSize)
	// Initialize all to valid
	for i := range statuses {
		statuses[i] = tokenstatuslist.StatusValid
	}

	return &StatusManager{
		statusList: tokenstatuslist.NewWithConfig(statuses, "", uri),
		nextIndex:  0,
		uri:        uri,
	}
}

// AllocateIndex allocates the next available index for a new credential.
func (sm *StatusManager) AllocateIndex() (int64, error) {
	if sm.nextIndex >= int64(sm.statusList.Len()) {
		return 0, errors.New("status list is full")
	}

	index := sm.nextIndex
	sm.nextIndex++
	return index, nil
}

// GetStatusReference returns a StatusReference for a credential at the given index.
func (sm *StatusManager) GetStatusReference(index int64) *StatusReference {
	return &StatusReference{
		URI:   sm.uri,
		Index: index,
	}
}

// Revoke marks a credential as revoked (invalid).
func (sm *StatusManager) Revoke(index int64) error {
	if index < 0 || index >= int64(sm.statusList.Len()) {
		return errors.New("index out of range")
	}
	return sm.statusList.Set(int(index), tokenstatuslist.StatusInvalid)
}

// Suspend marks a credential as suspended.
func (sm *StatusManager) Suspend(index int64) error {
	if index < 0 || index >= int64(sm.statusList.Len()) {
		return errors.New("index out of range")
	}
	return sm.statusList.Set(int(index), tokenstatuslist.StatusSuspended)
}

// Reinstate marks a suspended credential as valid again.
func (sm *StatusManager) Reinstate(index int64) error {
	if index < 0 || index >= int64(sm.statusList.Len()) {
		return errors.New("index out of range")
	}
	return sm.statusList.Set(int(index), tokenstatuslist.StatusValid)
}

// GetStatus returns the current status of a credential.
func (sm *StatusManager) GetStatus(index int64) (CredentialStatus, error) {
	if index < 0 || index >= int64(sm.statusList.Len()) {
		return CredentialStatusUnknown, errors.New("index out of range")
	}
	code, err := sm.statusList.Get(int(index))
	if err != nil {
		return CredentialStatusUnknown, err
	}
	return mapStatusCode(code), nil
}

// StatusList returns the underlying status list for token generation.
func (sm *StatusManager) StatusList() *tokenstatuslist.StatusList {
	return sm.statusList
}

// VerifierStatusCheck integrates status checking into the verification flow.
type VerifierStatusCheck struct {
	checker *StatusChecker
	enabled bool
}

// NewVerifierStatusCheck creates a new VerifierStatusCheck.
func NewVerifierStatusCheck(checker *StatusChecker) *VerifierStatusCheck {
	return &VerifierStatusCheck{
		checker: checker,
		enabled: true,
	}
}

// SetEnabled enables or disables status checking.
func (vsc *VerifierStatusCheck) SetEnabled(enabled bool) {
	vsc.enabled = enabled
}

// CheckDocumentStatus checks the status of a document if it has a status reference.
func (vsc *VerifierStatusCheck) CheckDocumentStatus(ctx context.Context, doc *Document) (*StatusCheckResult, error) {
	if !vsc.enabled {
		return &StatusCheckResult{
			Status:    CredentialStatusValid,
			CheckedAt: time.Now(),
		}, nil
	}

	// Extract status reference from the document
	ref, err := ExtractStatusReference(doc)
	if err != nil {
		// No status reference found - credential doesn't support revocation
		return nil, nil
	}

	return vsc.checker.CheckStatus(ctx, ref)
}

// ExtractStatusReference extracts the status reference from a Document.
// Returns nil if no status reference is present.
func ExtractStatusReference(doc *Document) (*StatusReference, error) {
	if doc == nil {
		return nil, errors.New("document is nil")
	}

	// Look for status reference in issuer signed items
	for _, items := range doc.IssuerSigned.NameSpaces {
		for _, item := range items {
			if item.ElementIdentifier == "status" {
				// Parse the status element
				ref, ok := parseStatusElement(item.ElementValue)
				if ok {
					return ref, nil
				}
			}
		}
	}

	return nil, errors.New("no status reference found")
}

// parseStatusElement parses a status element value into a StatusReference.
func parseStatusElement(value any) (*StatusReference, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		// Try map[any]any which CBOR might produce
		if mAny, ok := value.(map[any]any); ok {
			m = make(map[string]any)
			for k, v := range mAny {
				if ks, ok := k.(string); ok {
					m[ks] = v
				}
			}
		} else {
			return nil, false
		}
	}

	statusList, ok := m["status_list"].(map[string]any)
	if !ok {
		// Try map[any]any
		if slAny, ok := m["status_list"].(map[any]any); ok {
			statusList = make(map[string]any)
			for k, v := range slAny {
				if ks, ok := k.(string); ok {
					statusList[ks] = v
				}
			}
		} else {
			return nil, false
		}
	}

	uri, ok := statusList["uri"].(string)
	if !ok {
		return nil, false
	}

	var index int64
	switch idx := statusList["idx"].(type) {
	case int64:
		index = idx
	case int:
		index = int64(idx)
	case uint64:
		if idx > math.MaxInt64 {
			return nil, false
		}
		index = int64(idx)
	case float64:
		index = int64(idx)
	default:
		return nil, false
	}

	return &StatusReference{
		URI:   uri,
		Index: index,
	}, true
}

// splitJWT splits a JWT token string into its three parts.
func splitJWT(token string) []string {
	return strings.Split(token, ".")
}

// base64RawURLDecode decodes a base64 raw URL encoded string.
func base64RawURLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// parseJSON parses JSON data into a target struct.
func parseJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
