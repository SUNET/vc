package revocation

import (
	"bytes"
	"context"
	"crypto"
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
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
)

// COSE and CWT identifiers (RFC 8392, draft-ietf-oauth-status-list Section 6).
const (
	cwtHeaderTyp       int64 = 16
	cwtClaimIss              = 1
	cwtClaimSub              = 2
	cwtClaimExp              = 4
	cwtClaimStatusList       = 65534
	cwtClaimTTL              = 65535
	statusListKeyLst         = 2
)

const (
	// maxNumericDate bounds a float date so converting it to int64 cannot overflow.
	maxNumericDate = 1 << 53
	// maxDurationSeconds is the largest seconds value a time.Duration can hold.
	maxDurationSeconds = float64(math.MaxInt64 / int64(time.Second))
)

// StatusListChecker implements the Checker interface using Token Status Lists
// (draft-ietf-oauth-status-list).
type StatusListChecker struct {
	httpClient  *http.Client
	cache       cache.Cache[[]uint8]
	keyResolver KeyResolver
	maxCacheTTL time.Duration
	maxEntries  int64
}

// statusListJWTClaims is the claim set of a Status List Token JWT.
type statusListJWTClaims struct {
	jwt.RegisteredClaims
	TTL        *float64                         `json:"ttl"`
	StatusList *tokenstatuslist.StatusListClaim `json:"status_list"`
}

var (
	statusListJWTClaimNames = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "ttl", "status_list"}
	statusListMemberNames   = []string{"bits", "lst", "aggregation_uri"}
)

// UnmarshalJSON rejects what encoding/json would read differently from a strict JWT parser:
// a repeated claim, a claim spelled with different case such as EXP, and a null or quoted exp, nbf or ttl.
func (c *statusListJWTClaims) UnmarshalJSON(data []byte) error {
	type plain statusListJWTClaims
	if err := json.Unmarshal(data, (*plain)(c)); err != nil {
		return err
	}

	raw, err := decodeUniqueObject(data)
	if err != nil {
		return err
	}
	if err := rejectCaseVariants(raw, statusListJWTClaimNames); err != nil {
		return err
	}

	if sl := raw["status_list"]; len(sl) > 0 {
		members, err := decodeUniqueObject(sl)
		if err != nil {
			return fmt.Errorf("status_list: %w", err)
		}
		if err := rejectCaseVariants(members, statusListMemberNames); err != nil {
			return err
		}
	}

	return requireNumbers(raw, "exp", "nbf", "ttl")
}

// decodeUniqueObject splits a JSON object into its members and fails on a repeated key.
func decodeUniqueObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil {
		return nil, err
	} else if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("must be a JSON object")
	}

	members := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected object key %v", keyTok)
		}
		if _, repeated := members[key]; repeated {
			return nil, fmt.Errorf("claim %q appears more than once", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		members[key] = value
	}
	return members, nil
}

// requireNumbers rejects a present member that is null or a quoted string.
func requireNumbers(members map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		v := bytes.TrimSpace(members[name])
		switch {
		case len(v) == 0:
		case bytes.Equal(v, []byte("null")):
			return fmt.Errorf("%s claim must not be null", name)
		case v[0] == '"':
			return fmt.Errorf("%s claim must be a JSON number", name)
		}
	}
	return nil
}

// rejectCaseVariants fails on a key that matches a known name only after case folding.
func rejectCaseVariants(m map[string]json.RawMessage, known []string) error {
	for key := range m {
		for _, name := range known {
			if key != name && strings.EqualFold(key, name) {
				return fmt.Errorf("claim %q must be spelled %q", key, name)
			}
		}
	}
	return nil
}

// statusListToken is a verified Status List Token reduced to what the checker needs.
type statusListToken struct {
	statuses []uint8
	// ttl is the token's ttl claim, zero when absent.
	ttl time.Duration
	// ttlSet tells an explicit ttl of 0 (do not cache) from an absent ttl.
	ttlSet bool
	// exp is the token's exp claim, zero when absent.
	exp time.Time
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
// The cache must not extend an entry's lifetime on read, or a frequently read
// list outlives its token's exp and ttl. cache.NewMemoryCache and the MongoDB cache
// both meet that.
func WithCache(ch cache.Cache[[]uint8]) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.cache = ch
	}
}

// WithMaxCacheTTL caps how long a status list is cached, even when the token's
// own ttl or exp would allow longer.
func WithMaxCacheTTL(d time.Duration) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.maxCacheTTL = d
	}
}

// WithMaxEntries caps the entries accepted in one status list. Zero or less means
// tokenstatuslist.DefaultMaxEntries. Memory use is about one byte per entry per cached list.
func WithMaxEntries(n int64) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.maxEntries = n
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

	tok, err := c.fetchStatusList(ctx, uri)
	if err != nil {
		return nil, err
	}

	// exp is checked again here: the token may have expired while it was fetched and decompressed.
	ttl, err := c.entryTTL(tok)
	if err != nil {
		return nil, err
	}
	if tok.ttlSet && tok.ttl == 0 {
		return tok.statuses, nil
	}
	if ttl > 0 {
		c.cache.SetWithTTL(ctx, uri, tok.statuses, ttl)
	} else {
		c.cache.Set(ctx, uri, tok.statuses)
	}
	return tok.statuses, nil
}

// entryTTL returns the cache lifetime for a token: the shortest of its ttl
// claim, the time left until exp, and the configured maximum. Zero means use
// the cache's default. A token whose exp has passed is an error.
func (c *StatusListChecker) entryTTL(tok *statusListToken) (time.Duration, error) {
	d := tok.ttl
	if !tok.exp.IsZero() {
		left := time.Until(tok.exp)
		if left <= 0 {
			return 0, errors.New("status list token expired")
		}
		if d <= 0 || left < d {
			d = left
		}
	}
	if c.maxCacheTTL > 0 && (d <= 0 || d > c.maxCacheTTL) {
		d = c.maxCacheTTL
	}
	return d, nil
}

func (c *StatusListChecker) fetchStatusList(ctx context.Context, uri string) (*statusListToken, error) {
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

	// Limit response body to 10 MB to prevent memory exhaustion from
	// a malicious or misconfigured status list endpoint.
	const maxStatusListSize = 10 << 20 // 10 MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusListSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if int64(len(body)) > maxStatusListSize {
		return nil, fmt.Errorf("status list response exceeds maximum size (%d bytes)", maxStatusListSize)
	}

	contentType := resp.Header.Get("Content-Type")
	return c.parseStatusListToken(ctx, uri, body, contentType)
}

func (c *StatusListChecker) parseStatusListToken(ctx context.Context, uri string, data []byte, contentType string) (*statusListToken, error) {
	switch contentType {
	case tokenstatuslist.MediaTypeCWT:
		return c.parseCWTStatusList(ctx, uri, data)
	case tokenstatuslist.MediaTypeJWT:
		return c.parseJWTStatusList(ctx, uri, data)
	default:
		if len(data) > 0 && data[0] == 0xD2 {
			return c.parseCWTStatusList(ctx, uri, data)
		}
		return c.parseJWTStatusList(ctx, uri, data)
	}
}

func (c *StatusListChecker) parseCWTStatusList(ctx context.Context, uri string, data []byte) (*statusListToken, error) {
	parts, err := decodeCWT(data)
	if err != nil {
		return nil, err
	}
	var issuer string
	if raw, present := parts.claims[cwtClaimIss]; present {
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid iss claim in CWT: %T", raw)
		}
		issuer = s
	}

	key, err := c.keyResolver.ResolveKey(ctx, issuer, parts.kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CWT signing key: %w", err)
	}
	if err := verifyCWTSignature(parts.sign1, key); err != nil {
		return nil, err
	}

	// Claims are only trusted after the signature check above.
	return cwtToken(uri, parts.claims, c.maxEntries)
}

// cwtParts is a decoded but not yet verified Status List Token CWT.
type cwtParts struct {
	sign1  *mdoc.COSESign1
	kid    string
	claims map[int]any
}

// decodeCWT splits a COSE_Sign1 Status List Token and checks its typ header.
func decodeCWT(data []byte) (*cwtParts, error) {
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

	protectedBytes, ok := components[0].([]byte)
	if !ok {
		return nil, errors.New("invalid COSE_Sign1 protected header")
	}
	unprotected, ok := components[1].(map[any]any)
	if !ok {
		return nil, errors.New("invalid COSE_Sign1 unprotected header")
	}
	payloadBytes, ok := components[2].([]byte)
	if !ok {
		return nil, errors.New("invalid COSE_Sign1 payload")
	}
	signature, ok := components[3].([]byte)
	if !ok {
		return nil, errors.New("invalid COSE_Sign1 signature")
	}

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
	var kid string
	switch v := headers[mdoc.HeaderKeyID].(type) {
	case nil:
	case string:
		kid = v
	case []byte:
		kid = string(v)
	default:
		return nil, fmt.Errorf("invalid CWT kid header: %T", v)
	}
	if typ, ok := headers[cwtHeaderTyp].(string); !ok || typ != tokenstatuslist.CWTTypHeader {
		return nil, fmt.Errorf("invalid CWT typ header: expected %s", tokenstatuslist.CWTTypHeader)
	}

	var claims map[int]any
	if err := cbor.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode CWT claims: %w", err)
	}

	return &cwtParts{sign1: sign1, kid: kid, claims: claims}, nil
}

// verifyCWTSignature verifies a COSE_Sign1 against the resolved key.
func verifyCWTSignature(sign1 *mdoc.COSESign1, key any) error {
	pubKey, ok := key.(crypto.PublicKey)
	if !ok {
		return fmt.Errorf("resolved key is not a crypto.PublicKey: %T", key)
	}
	// Guard against panics from key/algorithm type mismatches in Verify1,
	// since the token is untrusted input and could specify an algorithm
	// incompatible with the resolved key type.
	var verifyErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				verifyErr = fmt.Errorf("CWT signature verification panic (key/alg mismatch): %v", r)
			}
		}()
		verifyErr = mdoc.Verify1(sign1, nil, pubKey, nil)
	}()
	if verifyErr != nil {
		return fmt.Errorf("CWT signature verification failed: %w", verifyErr)
	}
	return nil
}

// cwtToken turns verified CWT claims into a statusListToken. A present exp or
// ttl that is not a usable number is an error, never silently ignored.
func cwtToken(uri string, claims map[int]any, maxEntries int64) (*statusListToken, error) {
	if sub, ok := claims[cwtClaimSub].(string); !ok || sub != uri {
		return nil, fmt.Errorf("status list token sub %q does not match referenced uri %q", sub, uri)
	}

	tok := &statusListToken{}
	if raw, ok := claims[cwtClaimExp]; ok {
		exp, ok := numericDate(raw)
		if !ok {
			return nil, fmt.Errorf("invalid exp claim in CWT: %v", raw)
		}
		if !exp.After(time.Now()) {
			return nil, errors.New("status list token expired")
		}
		tok.exp = exp
	}
	if raw, ok := claims[cwtClaimTTL]; ok {
		ttl, ok := numericSeconds(raw)
		if !ok {
			return nil, fmt.Errorf("invalid ttl claim in CWT: %v", raw)
		}
		tok.ttl = ttl
		tok.ttlSet = true
	}

	statusListRaw, ok := claims[cwtClaimStatusList]
	if !ok {
		return nil, errors.New("status_list claim not found in CWT")
	}
	lst, bits, err := tokenstatuslist.ParseCWTStatusListClaim(statusListRaw)
	if err != nil {
		return nil, err
	}

	tok.statuses, err = tokenstatuslist.ExpandStatuses(lst, bits, maxEntries)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// cwtInt reads an integer that CBOR may decode as any integer width.
func cwtInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	}
	return 0, false
}

// numericDate reads an RFC 8392 NumericDate: an integer or a float with
// fractional seconds.
func numericDate(v any) (time.Time, bool) {
	if n, ok := cwtInt(v); ok {
		return time.Unix(n, 0), true
	}
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.Abs(f) > maxNumericDate {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*float64(time.Second))), true
}

// numericSeconds reads a non-negative integer or float number of seconds.
func numericSeconds(v any) (time.Duration, bool) {
	var s float64
	if n, ok := cwtInt(v); ok {
		s = float64(n)
	} else if f, ok := v.(float64); ok {
		s = f
	} else {
		return 0, false
	}
	if math.IsNaN(s) || s < 0 || s > maxDurationSeconds {
		return 0, false
	}
	return time.Duration(s * float64(time.Second)), true
}

func (c *StatusListChecker) parseJWTStatusList(ctx context.Context, uri string, data []byte) (*statusListToken, error) {
	tokenString := string(data)

	if c.keyResolver == nil {
		return nil, errors.New("status list JWT signature verification required but no key resolver configured")
	}

	// Build a jwt.Keyfunc that delegates to the generic KeyResolver
	keyFunc := func(token *jwt.Token) (any, error) {
		claims, ok := token.Claims.(*statusListJWTClaims)
		if !ok {
			return nil, errors.New("unexpected status list token claims type")
		}
		if claims.Issuer == "" {
			return nil, errors.New("status list token missing iss claim")
		}
		var kid string
		if raw, present := token.Header["kid"]; present {
			kid, ok = raw.(string)
			if !ok {
				return nil, fmt.Errorf("invalid kid header: %T", raw)
			}
		}
		return c.keyResolver.ResolveKey(ctx, claims.Issuer, kid)
	}

	claims := &statusListJWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, jwt.WithValidMethods([]string{
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

	if typ, ok := token.Header["typ"].(string); !ok || typ != tokenstatuslist.JWTTypHeader {
		return nil, fmt.Errorf("invalid typ header: expected %s", tokenstatuslist.JWTTypHeader)
	}

	if claims.Subject != uri {
		return nil, fmt.Errorf("status list token sub %q does not match referenced uri %q", claims.Subject, uri)
	}

	if claims.StatusList == nil {
		return nil, errors.New("status_list claim not found or invalid")
	}
	if claims.StatusList.Lst == "" {
		return nil, errors.New("lst not found in status_list claim")
	}

	tok := &statusListToken{}
	if claims.ExpiresAt != nil {
		tok.exp = claims.ExpiresAt.Time
	}
	if claims.TTL != nil {
		ttl, ok := numericSeconds(*claims.TTL)
		if !ok {
			return nil, fmt.Errorf("invalid ttl claim: %v", *claims.TTL)
		}
		tok.ttl = ttl
		tok.ttlSet = true
	}

	compressed, err := base64.RawURLEncoding.DecodeString(claims.StatusList.Lst)
	if err != nil {
		return nil, fmt.Errorf("failed to decode lst: %w", err)
	}
	tok.statuses, err = tokenstatuslist.ExpandStatuses(compressed, claims.StatusList.Bits, c.maxEntries)
	if err != nil {
		return nil, err
	}
	return tok, nil
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
