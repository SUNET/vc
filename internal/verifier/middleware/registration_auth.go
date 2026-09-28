package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
)

const (
	// RFC 6750 section 3.1 separates these: invalid_request is for a
	// malformed or missing Authorization header, invalid_token for a
	// syntactically valid credential that was rejected. Collapsing them
	// tells a client "your token is bad" when the real answer is "you did
	// not send one".
	errCodeInvalidRequest                        = "invalid_request"
	errCodeInvalidToken                          = "invalid_token"
	errDescInvalidRegistrationAuthorizationToken = "invalid registration authorization token"
	errDescMalformedBearerToken                  = "malformed bearer token in Authorization header"
	errDescRegistrationAuthorizationRequired     = "authorization is required for dynamic client registration"
)

// errNoBearerCredentials marks the case where the request carried nothing
// that was even an attempt at a bearer token: no Authorization header, or one
// using some other scheme entirely.
//
// RFC 6750 section 3 keeps this apart from a bad token, and the difference is
// the whole point of the challenge: a client that sent nothing needs to be
// told authorization exists and takes a Bearer token, which is a 401 carrying
// a bare `WWW-Authenticate: Bearer` and - explicitly - no error code, since
// naming an error would describe a credential that was never presented.
var errNoBearerCredentials = errors.New("no bearer credentials presented")

// jwksFetchTimeout bounds one JWKS fetch. Shorter than the per-request
// verification deadline below, so a slow endpoint fails the fetch rather
// than the request that triggered it.
const jwksFetchTimeout = 5 * time.Second

// RegistrationAuthValidator validates initial access tokens for dynamic client registration.
type RegistrationAuthValidator interface {
	Validate(ctx context.Context, token string) error
}

type registrationAuthError struct {
	status      int
	errorCode   string
	description string
}

func (e *registrationAuthError) Error() string {
	if e.errorCode == "" {
		return e.description
	}

	return e.errorCode + ": " + e.description
}

func unauthorizedRegistrationError(description string) *registrationAuthError {
	return &registrationAuthError{
		status:      http.StatusUnauthorized,
		errorCode:   errCodeInvalidToken,
		description: description,
	}
}

// malformedRequestError is the header-level failure: the Bearer scheme was
// used, but the header cannot be parsed into a token.
//
// 400, not 401, per RFC 6750 section 3.1. The distinction is not cosmetic:
// clients commonly treat 401 as "the token was rejected, refresh and retry",
// and answering that to a request whose Authorization header was unparseable
// sends them into a refresh loop over a request that will never succeed until
// it is corrected. A request that presented no bearer credentials at all is a
// different case again - see missingCredentialsError.
func malformedRequestError(description string) *registrationAuthError {
	return &registrationAuthError{
		status:      http.StatusBadRequest,
		errorCode:   errCodeInvalidRequest,
		description: description,
	}
}

// missingCredentialsError is the answer to a request that presented no bearer
// credentials at all.
//
// 401 with an empty error code, which writeRegistrationAuthError renders as a
// bare `WWW-Authenticate: Bearer` challenge and a body without an `error`
// field. RFC 6750 section 3: "If the request lacks any authentication
// information [...] the resource server SHOULD NOT include an error code or
// other error information." Answering 400 invalid_request here, as an earlier
// version of this middleware did, tells a client that its request was
// malformed when the request was fine and only unauthenticated - so it has no
// way to learn that acquiring a token is what it needs to do.
func missingCredentialsError() *registrationAuthError {
	return &registrationAuthError{
		status:      http.StatusUnauthorized,
		description: errDescRegistrationAuthorizationRequired,
	}
}

// NewRegistrationAuthMiddleware creates middleware for protecting POST /register.
//
// Modes:
//   - open: no auth required
//   - static: expects a fixed bearer token loaded from file
//   - jwt: expects a signed JWT validated against configured issuer/audience/JWKS
//
// Future option (not implemented): external introspection.
func NewRegistrationAuthMiddleware(cfg *model.Cfg, log *logger.Log) (gin.HandlerFunc, error) {
	passThrough := func(c *gin.Context) { c.Next() }
	authCfg := getDynamicRegistrationAuthConfig(cfg)
	if authCfg == nil {
		return passThrough, nil
	}

	mode := strings.ToLower(strings.TrimSpace(authCfg.Mode))
	if mode == "" || mode == "open" {
		return passThrough, nil
	}

	validator, err := buildRegistrationAuthValidator(mode, authCfg)
	if err != nil {
		return nil, err
	}

	if log != nil {
		log.Info("Dynamic registration authorization enabled", "mode", mode)
	}

	return func(c *gin.Context) {
		token, err := extractBearerToken(c.GetHeader("Authorization"))
		if err != nil {
			if errors.Is(err, errNoBearerCredentials) {
				writeRegistrationAuthError(c, missingCredentialsError())
				return
			}

			writeRegistrationAuthError(c, malformedRequestError(errDescMalformedBearerToken))
			return
		}

		if err := validator.Validate(c.Request.Context(), token); err != nil {
			var authErr *registrationAuthError
			if errors.As(err, &authErr) {
				writeRegistrationAuthError(c, authErr)
				return
			}

			writeRegistrationAuthError(c, unauthorizedRegistrationError(errDescInvalidRegistrationAuthorizationToken))
			return
		}

		c.Next()
	}, nil
}

func getDynamicRegistrationAuthConfig(cfg *model.Cfg) *model.DynamicRegistrationAuthConfig {
	if cfg == nil || cfg.Verifier == nil || cfg.Verifier.Outbound.OIDCProvider == nil {
		return nil
	}

	return cfg.Verifier.Outbound.OIDCProvider.DynamicRegistrationAuth
}

func buildRegistrationAuthValidator(mode string, authCfg *model.DynamicRegistrationAuthConfig) (RegistrationAuthValidator, error) {
	switch mode {
	case "static":
		return newStaticBearerValidator(authCfg.StaticBearerTokenFile)
	case "jwt":
		return newJWTBearerValidator(authCfg.JWT)
	case "introspection":
		return nil, fmt.Errorf("verifier OIDC dynamic registration auth mode 'introspection' is not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported verifier OIDC dynamic registration auth mode: %s", mode)
	}
}

func writeRegistrationAuthError(c *gin.Context, authErr *registrationAuthError) {
	// An empty code is the "no credentials presented" case: RFC 6750
	// section 3 says not to name an error there, so the challenge is bare
	// and the body carries only a human-readable description.
	if authErr.errorCode == "" {
		c.Header("WWW-Authenticate", "Bearer")
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.JSON(authErr.status, gin.H{"error_description": authErr.description})
		c.Abort()

		return
	}

	c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=\"%s\"", authErr.errorCode))
	// RFC 6749 section 5.2, and matching what the OIDC endpoints already do
	// (see verifier/httpserver/endpoints_oidc.go): an authorization error is
	// specific to one request's credential, so an intermediary holding on to
	// it could answer a later, differently-credentialled request with a
	// stale refusal.
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(authErr.status, gin.H{
		"error":             authErr.errorCode,
		"error_description": authErr.description,
	})
	c.Abort()
}

// extractBearerToken splits an Authorization header into its two outcomes.
//
// errNoBearerCredentials: nothing was presented under the Bearer scheme - an
// absent or blank header, or one naming a different scheme. The caller answers
// that with a challenge (401), because no credential of ours was rejected.
//
// Any other error: the Bearer scheme was used but the header cannot be parsed
// as one - "Bearer" with nothing after it, or only whitespace. That is a
// defect in the request itself, and the caller answers 400 invalid_request,
// not 401, so a client does not read it as "refresh your token and retry" and
// loop on a request that cannot succeed until it is corrected.
func extractBearerToken(authHeader string) (string, error) {
	trimmed := strings.TrimSpace(authHeader)
	if trimmed == "" {
		return "", errNoBearerCredentials
	}

	scheme, rest, found := strings.Cut(trimmed, " ")
	if !strings.EqualFold(scheme, "bearer") {
		return "", errNoBearerCredentials
	}

	if !found {
		return "", fmt.Errorf("authorization header names the bearer scheme but carries no token")
	}

	token := strings.TrimSpace(rest)
	if token == "" {
		return "", fmt.Errorf("empty bearer token")
	}
	// RFC 6750 section 2.1 gives the credential one syntax, b64token, and
	// anything outside it is not a token that was rejected - it is a header
	// that cannot carry one. `Bearer abc def` is the case that matters:
	// passing it through meant answering 401 invalid_token, telling a client
	// its credential was refused when the real fault is the header it built.
	// Checked here rather than in each validator, so every mode classifies
	// the same header the same way.
	if !isB64Token(token) {
		return "", fmt.Errorf("bearer token contains characters outside RFC 6750 b64token syntax")
	}

	return token, nil
}

// isB64Token reports whether s matches RFC 6750 section 2.1's b64token:
//
//	1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
//
// Deliberately not a base64 decode. The grammar is a character set plus
// optional trailing padding, not a well-formed encoding - issuers mint tokens
// in this alphabet that are not base64 of anything (a JWT is three such
// segments joined by dots), and rejecting those would refuse valid
// credentials.
func isB64Token(s string) bool {
	if s == "" {
		return false
	}

	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}

	for _, r := range body {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~', r == '+', r == '/':
		default:
			return false
		}
	}

	return true
}

// staticBearerValidator holds the expected token as a SHA-256 digest.
//
// subtle.ConstantTimeCompare returns early when the two slices differ in
// length, so comparing raw tokens is not constant-time in the length
// dimension - a caller can learn how long the expected token is by timing.
// Digests are always 32 bytes, so the comparison that matters runs over a
// fixed width regardless of what was presented.
type staticBearerValidator struct {
	tokenDigest [sha256.Size]byte
}

func newStaticBearerValidator(tokenFilePath string) (*staticBearerValidator, error) {
	if strings.TrimSpace(tokenFilePath) == "" {
		return nil, fmt.Errorf("static mode requires dynamic_registration_auth.static_bearer_token_file")
	}

	content, err := os.ReadFile(filepath.Clean(tokenFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read static bearer token file: %w", err)
	}

	token := strings.TrimSpace(string(content))
	if token == "" {
		return nil, fmt.Errorf("static bearer token file is empty")
	}
	// Surrounding whitespace is trimmed above, but whitespace *inside* the
	// value cannot be sent in an Authorization header, so such a file can
	// never match any request. Caught here, where the message can say the
	// file is wrong - left to run, it surfaces later as every registration
	// attempt being rejected, which reads as an auth failure rather than a
	// configuration one.
	if strings.ContainsFunc(token, unicode.IsSpace) {
		return nil, fmt.Errorf("static bearer token file contains whitespace inside the token (expected a single line holding only the token)")
	}

	return &staticBearerValidator{tokenDigest: sha256.Sum256([]byte(token))}, nil
}

func (v *staticBearerValidator) Validate(_ context.Context, token string) error {
	presented := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(presented[:], v.tokenDigest[:]) != 1 {
		return unauthorizedRegistrationError(errDescInvalidRegistrationAuthorizationToken)
	}

	return nil
}

type jwtBearerValidator struct {
	verifier *oidc.IDTokenVerifier
}

// newJWKSHTTPClient builds the client go-oidc fetches the key set with.
//
// It carries its own timeout (see the note at the call site on why the default
// client's absence of one is not survivable here) and refuses to follow a
// redirect to anything but https.
//
// That second part is the other half of requiring https on jwks_uri.
// Validating the configured URL only constrains the first hop, and Go's client
// follows redirects by default - so an endpoint answering 302 to an http://
// location would have the key set fetched in the clear after all, while the
// configuration still read as https and nothing in it looked wrong. The key
// set is what every registration token is judged against, so whoever serves it
// decides which signatures verify.
func newJWKSHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       jwksFetchTimeout,
		CheckRedirect: refuseNonHTTPSRedirect,
	}
}

// refuseNonHTTPSRedirect stops a JWKS fetch from being walked off TLS.
func refuseNonHTTPSRedirect(req *http.Request, _ []*http.Request) error {
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("refusing to follow JWKS redirect to non-HTTPS %q: "+
			"the key set is the trust root for registration tokens and must not be fetched in the clear", req.URL.String())
	}

	return nil
}

func newJWTBearerValidator(cfg *model.DynamicRegistrationJWTAuthConfig) (*jwtBearerValidator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("jwt mode requires dynamic_registration_auth.jwt configuration")
	}

	if strings.TrimSpace(cfg.JWKSURI) == "" || strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Audience) == "" {
		return nil, fmt.Errorf("jwt mode requires jwks_uri, issuer, and audience")
	}

	algs := cfg.AllowedSigningAlgs
	if len(algs) == 0 {
		algs = []string{"RS256", "ES256"}
	}

	// NOTE: Introspection mode is intentionally deferred.
	// JWT mode validates token signature and claims locally against JWKS.
	//
	// The key set gets its own client with a timeout, because the context
	// handed to NewRemoteKeySet is the one its fetches actually use.
	// go-oidc runs the JWKS refresh in a goroutine against that stored
	// context and selects on the caller's context only to return early - so
	// a per-request deadline unblocks the request and leaves the fetch
	// running. With http.DefaultClient, which has no timeout, a stalled
	// JWKS endpoint hangs that goroutine indefinitely; and since the
	// inflight request is only cleared when it finishes, every later
	// verification joins the same dead fetch and times out too.
	//
	// CheckRedirect is the other half of requiring https on jwks_uri.
	// Validating the configured URL only constrains the first hop: Go's
	// client follows redirects by default, so an endpoint that answers
	// 302 to an http:// location would have the key set - the thing every
	// registration token is judged against - fetched in the clear after
	// all, and the config would still read as https. The scheme is
	// therefore enforced on every hop, and the refusal names the
	// destination, because a redirect nobody configured is not obvious
	// from the setting that was.
	keySetCtx := oidc.ClientContext(context.Background(), newJWKSHTTPClient())
	keySet := oidc.NewRemoteKeySet(keySetCtx, cfg.JWKSURI)
	oidcCfg := &oidc.Config{
		ClientID:             cfg.Audience,
		SupportedSigningAlgs: algs,
	}
	// go-oidc has no leeway setting, so skew is applied by moving the clock
	// it reads. That one clock serves both time checks, in opposite
	// directions: a token that expired within the tolerance is still
	// accepted, and go-oidc's fixed five-minute nbf leeway shrinks by the
	// same amount. See ClockSkewSeconds' own doc comment.
	//
	// nil means the key was absent from the config and defaults have not
	// run (this constructor is also called directly from tests); an
	// explicit 0 means the operator turned the tolerance off and must not
	// be treated as absent.
	if cfg.ClockSkewSeconds != nil && *cfg.ClockSkewSeconds > 0 {
		skew := time.Duration(*cfg.ClockSkewSeconds) * time.Second
		oidcCfg.Now = func() time.Time { return time.Now().Add(-skew) }
	}
	verifier := oidc.NewVerifier(cfg.Issuer, keySet, oidcCfg)

	return &jwtBearerValidator{verifier: verifier}, nil
}

func (v *jwtBearerValidator) Validate(ctx context.Context, token string) error {
	verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if _, err := v.verifier.Verify(verifyCtx, token); err != nil {
		return unauthorizedRegistrationError(errDescInvalidRegistrationAuthorizationToken)
	}

	return nil
}
