package sdjwtvc

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SDJWTHandler handles SD-JWT format credentials in OpenID4VP flows.
type SDJWTHandler struct {
	client         *Client
	keyResolver    KeyResolver
	verifyOpts     *VerificationOptions
	trustedIssuers []string
}

// KeyResolver resolves public keys for SD-JWT verification.
// Implementations can fetch keys from JWKS endpoints, local stores, etc.
type KeyResolver interface {
	// ResolveKey resolves a public key for the given issuer and key ID.
	ResolveKey(ctx context.Context, issuer string, keyID string) (crypto.PublicKey, error)
}

// StaticKeyResolver is a simple key resolver that returns a fixed key.
type StaticKeyResolver struct {
	Key crypto.PublicKey
}

// ResolveKey returns the static key regardless of issuer/keyID.
func (r *StaticKeyResolver) ResolveKey(ctx context.Context, issuer string, keyID string) (crypto.PublicKey, error) {
	if r.Key == nil {
		return nil, errors.New("no key configured")
	}
	return r.Key, nil
}

// SDJWTHandlerOption configures an SDJWTHandler.
type SDJWTHandlerOption func(*SDJWTHandler)

// WithSDJWTKeyResolver sets the key resolver for SD-JWT verification.
func WithSDJWTKeyResolver(resolver KeyResolver) SDJWTHandlerOption {
	return func(h *SDJWTHandler) {
		h.keyResolver = resolver
	}
}

// WithSDJWTStaticKey sets a static public key for SD-JWT verification.
func WithSDJWTStaticKey(key crypto.PublicKey) SDJWTHandlerOption {
	return func(h *SDJWTHandler) {
		h.keyResolver = &StaticKeyResolver{Key: key}
	}
}

// WithSDJWTVerificationOptions sets the verification options.
func WithSDJWTVerificationOptions(opts *VerificationOptions) SDJWTHandlerOption {
	return func(h *SDJWTHandler) {
		h.verifyOpts = opts
	}
}

// WithSDJWTTrustedIssuers sets the list of trusted issuers.
func WithSDJWTTrustedIssuers(issuers []string) SDJWTHandlerOption {
	return func(h *SDJWTHandler) {
		h.trustedIssuers = issuers
	}
}

// WithSDJWTRequireKeyBinding requires key binding JWT to be present.
func WithSDJWTRequireKeyBinding(nonce, audience string) SDJWTHandlerOption {
	return func(h *SDJWTHandler) {
		if h.verifyOpts == nil {
			h.verifyOpts = &VerificationOptions{}
		}
		h.verifyOpts.RequireKeyBinding = true
		h.verifyOpts.ExpectedNonce = nonce
		h.verifyOpts.ExpectedAudience = audience
	}
}

// NewSDJWTHandler creates a new SD-JWT handler for OpenID4VP.
func NewSDJWTHandler(opts ...SDJWTHandlerOption) (*SDJWTHandler, error) {
	h := &SDJWTHandler{
		client: New(),
		verifyOpts: &VerificationOptions{
			ValidateTime:     true,
			AllowedClockSkew: 5 * time.Minute,
		},
	}

	for _, opt := range opts {
		opt(h)
	}

	return h, nil
}

// VerifyAndExtract verifies an SD-JWT VP token and extracts the disclosed claims.
func (h *SDJWTHandler) VerifyAndExtract(ctx context.Context, vpToken string) (*SDJWTVerificationResult, error) {
	if vpToken == "" {
		return nil, errors.New("VP token is empty")
	}

	// Parse the token first to extract issuer and key ID
	parsed, err := Token(vpToken).Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
	}

	// Extract issuer for key resolution and trust validation
	issuer, _ := parsed.Claims["iss"].(string)
	if issuer == "" {
		return nil, errors.New("SD-JWT missing issuer claim")
	}

	// Validate trusted issuer if configured
	if len(h.trustedIssuers) > 0 {
		trusted := slices.Contains(h.trustedIssuers, issuer)
		if !trusted {
			return nil, fmt.Errorf("issuer %s is not trusted", issuer)
		}
	}

	// Resolve the public key
	if h.keyResolver == nil {
		return nil, errors.New("no key resolver configured")
	}

	keyID, _ := parsed.Header["kid"].(string)
	publicKey, err := h.keyResolver.ResolveKey(ctx, issuer, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve public key: %w", err)
	}

	// Verify the SD-JWT
	verifyResult, err := h.client.ParseAndVerify(vpToken, publicKey, h.verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("SD-JWT verification failed: %w", err)
	}

	if !verifyResult.Valid {
		errMsgs := make([]string, 0, len(verifyResult.Errors))
		for _, e := range verifyResult.Errors {
			errMsgs = append(errMsgs, e.Error())
		}
		return nil, fmt.Errorf("SD-JWT validation failed: %s", strings.Join(errMsgs, "; "))
	}

	// Build the result
	result := &SDJWTVerificationResult{
		Valid:           true,
		Issuer:          issuer,
		Subject:         getStringClaim(verifyResult.Claims, "sub"),
		VCT:             getStringClaim(verifyResult.Claims, "vct"),
		Claims:          verifyResult.Claims,
		DisclosedClaims: verifyResult.DisclosedClaims,
		KeyBindingValid: verifyResult.KeyBindingValid,
		VCTM:            verifyResult.VCTM,
	}

	// Extract expiration if present
	if exp, ok := verifyResult.Claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		result.ExpiresAt = &expTime
	}

	// Extract issuance time if present
	if iat, ok := verifyResult.Claims["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		result.IssuedAt = &iatTime
	}

	return result, nil
}

// SDJWTVerificationResult contains the result of SD-JWT verification and claim extraction.
type SDJWTVerificationResult struct {
	Valid           bool
	Issuer          string
	Subject         string
	VCT             string // Verifiable Credential Type
	Claims          map[string]any
	DisclosedClaims map[string]any
	KeyBindingValid bool
	ExpiresAt       *time.Time
	IssuedAt        *time.Time
	VCTM            *VCTM
}

// GetClaims returns all claims (both standard and disclosed).
func (r *SDJWTVerificationResult) GetClaims() map[string]any {
	return r.Claims
}

// GetDisclosedClaims returns only the selectively disclosed claims.
func (r *SDJWTVerificationResult) GetDisclosedClaims() map[string]any {
	return r.DisclosedClaims
}

// IsSDJWTFormat checks if the VP token appears to be in SD-JWT format.
func IsSDJWTFormat(vpToken string) bool {
	// SD-JWT format: <JWT>~<disclosure>~...~[<KB-JWT>]
	// Must contain at least one ~ separator and the first part should be a JWT
	parts := strings.Split(vpToken, "~")
	if len(parts) < 2 {
		// Could be a plain JWT, check for JWT structure
		return strings.Count(vpToken, ".") == 2
	}

	// First part should be a JWT (3 dot-separated parts)
	firstPart := parts[0]
	return strings.Count(firstPart, ".") == 2
}

// ExtractSDJWTClaims extracts claims from an SD-JWT VP token without full verification.
// Use this for testing or when verification is handled separately.
func ExtractSDJWTClaims(vpToken string) (map[string]any, error) {
	if vpToken == "" {
		return nil, errors.New("VP token is empty")
	}

	parsed, err := Token(vpToken).Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
	}

	return parsed.Claims, nil
}

// SDJWTClaimMapping provides standard mappings from SD-JWT VC claims to OIDC claims.
// These follow common credential schemas and OIDC standard claims.
var SDJWTClaimMapping = map[string]string{
	// Standard OIDC claims (pass through)
	"sub": "sub",
	"iss": "iss",
	"iat": "iat",
	"exp": "exp",
	"nbf": "nbf",

	// Identity claims
	"family_name":           "family_name",
	"given_name":            "given_name",
	"middle_name":           "middle_name",
	"nickname":              "nickname",
	"preferred_username":    "preferred_username",
	"profile":               "profile",
	"picture":               "picture",
	"website":               "website",
	"email":                 "email",
	"email_verified":        "email_verified",
	"gender":                "gender",
	"birthdate":             "birthdate",
	"zoneinfo":              "zoneinfo",
	"locale":                "locale",
	"phone_number":          "phone_number",
	"phone_number_verified": "phone_number_verified",
	"address":               "address",
	"updated_at":            "updated_at",

	// Common credential claims
	"birth_date":        "birthdate",
	"date_of_birth":     "birthdate",
	"first_name":        "given_name",
	"last_name":         "family_name",
	"full_name":         "name",
	"age_over_18":       "age_over_18",
	"age_over_21":       "age_over_21",
	"nationality":       "nationality",
	"place_of_birth":    "place_of_birth",
	"document_number":   "document_number",
	"issuing_authority": "issuing_authority",
	"issuing_country":   "issuing_country",
	"issue_date":        "iat",
	"expiry_date":       "exp",
}

// MapSDJWTToOIDC maps SD-JWT claims to OIDC claims using the standard mapping.
func MapSDJWTToOIDC(sdJWTClaims map[string]any) map[string]any {
	oidcClaims := make(map[string]any)

	for sdKey, value := range sdJWTClaims {
		// Skip internal SD-JWT claims
		if isInternalSDJWTClaim(sdKey) {
			continue
		}

		// Check if there's a mapping
		if oidcKey, ok := SDJWTClaimMapping[sdKey]; ok {
			oidcClaims[oidcKey] = value
		} else {
			// Pass through unmapped claims
			oidcClaims[sdKey] = value
		}
	}

	return oidcClaims
}

// isInternalSDJWTClaim checks if a claim is an internal SD-JWT claim.
func isInternalSDJWTClaim(claim string) bool {
	internalClaims := []string{
		"_sd",
		"_sd_alg",
		"cnf",
		"vct",
		"status",
	}
	return slices.Contains(internalClaims, claim)
}

// getStringClaim safely extracts a string claim from the claims map.
func getStringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}
