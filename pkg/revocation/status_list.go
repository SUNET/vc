package revocation

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	// fallbackIssuer is the issuer identity used for Status List Tokens
	// that carry no iss claim. Empty means such tokens are refused; see
	// resolveStatusListKey.
	fallbackIssuer string
	// statusListKey is the signing key named directly by configuration,
	// for a service that publishes it nowhere a resolver can follow.
	statusListKey crypto.PublicKey
}

// StatusListCheckerOption configures a StatusListChecker.
type StatusListCheckerOption func(*StatusListChecker)

// WithFallbackIssuer sets the issuer identity to resolve a signing key
// under when a Status List Token carries no iss claim. Without it such a
// token is refused rather than resolved against a guess.
func WithFallbackIssuer(issuer string) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.fallbackIssuer = issuer
	}
}

// WithStatusListKey pins the public key that verifies Status List Tokens
// from the configured status-list issuer, for a service that publishes that
// key nowhere a resolver can reach.
//
// Scoped, not global: it answers for tokens carrying no iss, and for tokens
// whose iss matches WithFallbackIssuer. Everything else still goes to the
// resolver, because a deployment may run vc's own registry alongside an
// external status service and those lists are signed by different keys - an
// unscoped pin made the external key answer for registry tokens too, so
// registry lists stopped verifying, which fail_open would then tolerate.
//
// Within that scope it does take precedence over the resolver: an issuer
// identity whose JWKS does not carry the status-list key resolves to
// nothing, which with fail_open turns a revoked credential into an accepted
// one.
func WithStatusListKey(key crypto.PublicKey) StatusListCheckerOption {
	return func(c *StatusListChecker) {
		c.statusListKey = key
	}
}

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
//
// SD-JWT, JWP and mdoc all present it as the JOSE "status" claim (mdoc via
// MDocDocumentClaims.GetClaims, which surfaces the MSO parameter in that
// shape). W3C VC 2.0 has no such claim, so credentialStatus is tried next.
func (c *StatusListChecker) Extract(claims map[string]any) *Reference {
	if ref := ExtractStatusListReference(claims); ref != nil {
		return ref
	}
	return ExtractCredentialStatusReference(claims)
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
	// The URI travels with the bytes: Section 8.3 requires the token's sub
	// to equal the uri the Referenced Token pointed at, and a parser that
	// cannot see the uri cannot make that check.
	return c.parseStatusListToken(ctx, uri, body, contentType)
}

func (c *StatusListChecker) parseStatusListToken(ctx context.Context, uri string, data []byte, contentType string) ([]uint8, error) {
	// A Content-Type may carry parameters (charset, boundary); compare only
	// the media type itself.
	mediaType := contentType
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))

	switch mediaType {
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

// resolveStatusListKey resolves the key a Status List Token was signed with.
//
// draft-ietf-oauth-status-list Section 5.1 does NOT require an iss claim -
// the REQUIRED claims are sub, iat and status_list - so refusing every
// token without one rejects conforming status services, which is what vc
// used to do.
//
// But a missing iss leaves nothing in the token to resolve a key from. The
// list URI is not a substitute: a service such as siros-status-service
// publishes its status-list signing key separately from the list URL, so
// treating the URI as an issuer identity sends the resolver looking for
// discovery under "<list URI>/.well-known/...", which is not there. It
// would fail anyway - just with an error describing the wrong problem, and
// on a path that looks like it was designed to work.
//
// So the fallback is configuration (WithFallbackIssuer, from
// verifier.revocation.status_list_issuer), and with none configured a token
// without iss is refused. Refusing is the fail-closed answer: an
// unverifiable status list must not be treated as a readable one.
func (c *StatusListChecker) resolveStatusListKey(ctx context.Context, issuer, uri, kid string) (any, error) {
	// The configured key pins, but only for the issuer it was configured
	// for. A deployment may run vc's own registry alongside an external
	// status service - issuer.status_service documents that as supported -
	// and those lists are signed by different keys. An unscoped pin made
	// the external key answer for registry tokens too, so registry lists
	// stopped verifying the moment a key file was configured, which
	// fail_open would then tolerate.
	//
	// Scope: a token with no iss (there is nothing else to go on), or one
	// whose iss is the configured status_list_issuer. Anything else goes to
	// the resolver, which is how registry tokens keep working.
	if c.statusListKey != nil && (issuer == "" || issuer == c.fallbackIssuer) {
		return c.statusListKey, nil
	}
	if issuer == "" {
		issuer = c.fallbackIssuer
	}
	if issuer == "" {
		return nil, fmt.Errorf("status list token for %q carries no iss claim, and neither verifier.revocation.status_list_key_file nor verifier.revocation.status_list_issuer is configured, so its signing key cannot be resolved", uri)
	}
	return c.keyResolver.ResolveKey(ctx, issuer, kid)
}

// checkCWTTypeHeader enforces the statuslist+cwt content type carried in
// COSE protected header 16 (RFC 9596). The header may hold the media type
// as a string or as a registered CoAP Content-Format integer; only the
// string form is defined for this media type, so anything else is refused
// rather than assumed to be equivalent.
func checkCWTTypeHeader(headers map[int64]any) error {
	raw, ok := headers[coseHeaderContentType]
	if !ok {
		return fmt.Errorf("status list CWT has no typ header, expected %q", tokenstatuslist.CWTTypHeader)
	}
	var typ string
	switch v := raw.(type) {
	case string:
		typ = v
	case []byte:
		typ = string(v)
	default:
		return fmt.Errorf("status list CWT typ header has unexpected type %T, expected %q", raw, tokenstatuslist.CWTTypHeader)
	}
	if !strings.EqualFold(typ, tokenstatuslist.CWTTypHeader) {
		return fmt.Errorf("status list CWT has typ %q, expected %q", typ, tokenstatuslist.CWTTypHeader)
	}
	return nil
}

// coseHeaderContentType is COSE protected header label 16, which carries
// the payload's media type (RFC 9596 "typ").
const coseHeaderContentType = 16

// checkSubject enforces Section 8.3: "the sub claim value MUST be equal to
// the uri claim in the status_list object of the Referenced Token".
//
// Without it, ANY status list token the issuer ever signed is accepted for
// ANY uri - so a stale or unrelated list (one where the index in question
// happens to still read VALID) can be served in place of the real one and
// a revoked credential verifies. The signature alone does not bind a token
// to the list it claims to be.
func checkSubject(subject, uri string) error {
	if subject == "" {
		return errors.New("status list token has no sub claim; it cannot be bound to the requested list URI")
	}
	if subject != uri {
		return fmt.Errorf("status list token sub %q does not match the requested status list URI %q", subject, uri)
	}
	return nil
}

func (c *StatusListChecker) parseCWTStatusList(ctx context.Context, uri string, data []byte) ([]uint8, error) {
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

	// Section 6.1 makes the content type mandatory, the same way Section
	// 5.1 does for a JWT's typ. Without this check a different COSE_Sign1
	// object signed by the same trusted key is accepted as a status list
	// if its claims happen to be shaped alike - which is exactly the hole
	// the JWT path closes and this one did not.
	if err := checkCWTTypeHeader(headers); err != nil {
		return nil, err
	}

	// Decode CWT claims to extract issuer
	var claims map[int]any
	if err := cbor.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode CWT claims: %w", err)
	}
	issuer, _ := claims[1].(string)  // CWT claim 1 = iss (OPTIONAL)
	subject, _ := claims[2].(string) // CWT claim 2 = sub (REQUIRED)

	// Bind the token to the list that was asked for BEFORE trusting
	// anything in it.
	if err := checkSubject(subject, uri); err != nil {
		return nil, err
	}

	// Resolve signing key and verify signature
	key, err := c.resolveStatusListKey(ctx, issuer, uri, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CWT signing key: %w", err)
	}
	pubKey, ok := key.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("resolved key is not a crypto.PublicKey: %T", key)
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
		return nil, fmt.Errorf("CWT signature verification failed: %w", verifyErr)
	}

	// The signature is verified; the claims can now be trusted. Expiry is
	// checked here because, unlike the JWT path, nothing else does it.
	if exp, ok := cwtTime(claims[4]); ok && time.Now().After(exp) {
		return nil, fmt.Errorf("status list token expired at %s", exp.Format(time.RFC3339))
	}

	// Extract status list from verified claims
	statusListRaw, ok := claims[65534]
	if !ok {
		return nil, errors.New("status_list claim not found in CWT")
	}

	bits, lstBytes, err := tokenstatuslist.CWTStatusListMembers(statusListRaw)
	if err != nil {
		return nil, err
	}

	return tokenstatuslist.DecompressAndUnpack(lstBytes, bits)
}

// cwtTime reads a CWT NumericDate claim, which a CBOR decoder can hand back
// as any of several integer or float types.
func cwtTime(raw any) (time.Time, bool) {
	switch v := raw.(type) {
	case int64:
		return time.Unix(v, 0), true
	case int:
		return time.Unix(int64(v), 0), true
	case uint64:
		return time.Unix(int64(v), 0), true
	case float64:
		return time.Unix(int64(v), 0), true
	default:
		return time.Time{}, false
	}
}

func (c *StatusListChecker) parseJWTStatusList(ctx context.Context, uri string, data []byte) ([]uint8, error) {
	tokenString := strings.TrimSpace(string(data))

	if c.keyResolver == nil {
		return nil, errors.New("status list JWT signature verification required but no key resolver configured")
	}

	// Build a jwt.Keyfunc that delegates to the generic KeyResolver. iss is
	// OPTIONAL per Section 5.1; see resolveStatusListKey.
	keyFunc := func(token *jwt.Token) (any, error) {
		claims, _ := token.Claims.(jwt.MapClaims)
		issuer, _ := claims["iss"].(string)
		kid, _ := token.Header["kid"].(string)
		return c.resolveStatusListKey(ctx, issuer, uri, kid)
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

	// Section 5.1: the typ header MUST be statuslist+jwt. Without this a
	// token minted for any other purpose by the same issuer - an access
	// token, an attestation - is accepted as a status list.
	if typ, _ := token.Header["typ"].(string); !strings.EqualFold(typ, tokenstatuslist.JWTTypHeader) {
		return nil, fmt.Errorf("status list token has typ %q, expected %q", typ, tokenstatuslist.JWTTypHeader)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to extract JWT claims")
	}

	subject, _ := claims["sub"].(string)
	if err := checkSubject(subject, uri); err != nil {
		return nil, err
	}

	statusListClaim, ok := claims["status_list"].(map[string]any)
	if !ok {
		return nil, errors.New("status_list claim not found or invalid")
	}

	lst, ok := statusListClaim["lst"].(string)
	if !ok {
		return nil, errors.New("lst not found in status_list claim")
	}

	bits, err := jsonBits(statusListClaim["bits"])
	if err != nil {
		return nil, err
	}

	return tokenstatuslist.DecodeDecompressAndUnpack(lst, bits)
}

// jsonBits reads the REQUIRED status_list.bits member. An absent or
// unreadable one is an error, never a fall back to the default width:
// guessing returns another credential's status instead of failing.
func jsonBits(raw any) (int, error) {
	switch v := raw.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("status_list bits %v is not an integer", v)
		}
		return int(v), nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("status_list bits %q is not an integer: %w", v.String(), err)
		}
		return int(i), nil
	case nil:
		return 0, errors.New("status_list claim is missing the required bits member")
	default:
		return 0, fmt.Errorf("status_list bits has unexpected type %T", raw)
	}
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
