package oauth2

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ClientAssertionClaims holds the validated claims from a client_assertion JWT (RFC 7523 §3).
type ClientAssertionClaims struct {
	Issuer   string
	Subject  string
	Audience string
	JTI      string
	IssuedAt time.Time
	Expiry   time.Time
}

// ClientAssertionVerifier verifies client_assertion JWTs per RFC 7523.
type ClientAssertionVerifier struct {
	// AllowedAlgorithms is the set of permitted signing algorithms (e.g. RS256, ES256).
	AllowedAlgorithms []string
	// TokenEndpoint is the expected audience value (the token endpoint URL).
	TokenEndpoint string
	// MaxLifetime is the maximum allowed lifetime of the assertion (exp - iat).
	// Defaults to 5 minutes if zero.
	MaxLifetime time.Duration
	// JTICheck is called to verify that the jti has not been replayed.
	// Returns an error if the jti was already seen. May be nil to skip replay checks.
	JTICheck func(jti string, exp time.Time) error
	// JWKSCache caches raw JWKS JSON keyed by the client's jwks_uri.
	// When non-nil, avoids fetching the JWKS on every token request.
	// When nil, falls back to fetching the JWKS directly on each call.
	JWKSCache cache.Cache[[]byte]
}

// defaultAllowedAlgorithms is the allowlist of signing algorithms accepted for client assertions.
var defaultAllowedAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}

// Verify verifies a client_assertion JWT against the client's JWKS, validating
// the signature, audience, issuer/subject, expiration, and jti (replay protection).
// Returns the validated claims or an error.
func (v *ClientAssertionVerifier) Verify(ctx context.Context, assertion string, client *Client) (*ClientAssertionClaims, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	if client.JWKSURI == "" {
		return nil, errors.New("client has no jwks_uri configured for assertion verification")
	}
	if v.TokenEndpoint == "" {
		return nil, errors.New("token endpoint (audience) is not configured for assertion verification")
	}

	// Fetch the client's JWKS (with optional cache)
	keySet, err := v.fetchJWKS(ctx, client.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client JWKS from %s: %w", client.JWKSURI, err)
	}

	allowedAlgs := v.AllowedAlgorithms
	if len(allowedAlgs) == 0 {
		allowedAlgs = defaultAllowedAlgorithms
	}

	// Parse and verify the JWT
	token, err := jwt.Parse(assertion, func(token *jwt.Token) (any, error) {
		// Reject "none" algorithm unconditionally
		if token.Method.Alg() == "none" {
			return nil, errors.New("algorithm 'none' is not allowed")
		}

		// Check algorithm allowlist
		alg := token.Method.Alg()
		if !slices.Contains(allowedAlgs, alg) {
			return nil, fmt.Errorf("algorithm %q is not in the allowed set", alg)
		}

		// Find matching key in JWKS by kid (if present in header)
		kid, _ := token.Header["kid"].(string)
		if kid != "" {
			if matchedKey, ok := keySet.LookupKeyID(kid); ok {
				// If the key declares an algorithm, enforce it to avoid algorithm confusion.
				if kAlg, hasAlg := matchedKey.Algorithm(); hasAlg && kAlg.String() != alg {
					return nil, fmt.Errorf("key %q algorithm %q does not match token algorithm %q", kid, kAlg.String(), alg)
				}
				var rawKey crypto.PublicKey
				if err := jwk.Export(matchedKey, &rawKey); err != nil {
					return nil, fmt.Errorf("failed to extract raw key: %w", err)
				}
				return rawKey, nil
			}
		}

		// No kid match — collect all candidate keys and return a VerificationKeySet
		// so the parser can try each key until one verifies.
		var keys []jwt.VerificationKey
		for i := 0; i < keySet.Len(); i++ {
			k, ok := keySet.Key(i)
			if !ok {
				continue
			}
			// If the key declares an algorithm, skip keys that don't match
			if kAlg, hasAlg := k.Algorithm(); hasAlg && kAlg.String() != alg {
				continue
			}
			var rawKey crypto.PublicKey
			if err := jwk.Export(k, &rawKey); err != nil {
				continue
			}
			keys = append(keys, rawKey)
		}
		if len(keys) == 0 {
			return nil, errors.New("no suitable key found in client JWKS")
		}
		return jwt.VerificationKeySet{Keys: keys}, nil
	},
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithAudience(v.TokenEndpoint),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("client assertion verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unexpected claims type")
	}

	// RFC 7523 §3: iss MUST equal sub (both identify the client)
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" {
		return nil, errors.New("client assertion must contain 'iss' and 'sub' claims")
	}
	if iss != sub {
		return nil, fmt.Errorf("client assertion 'iss' (%s) must equal 'sub' (%s) per RFC 7523 §3", iss, sub)
	}

	// Verify jti for replay protection
	jti, _ := claims["jti"].(string)
	if jti == "" && v.JTICheck != nil {
		return nil, errors.New("client assertion must contain 'jti' claim for replay protection")
	}

	// Parse time claims
	expFloat, _ := claims["exp"].(float64)
	iatFloat, okIat := claims["iat"].(float64)
	if !okIat || iatFloat == 0 {
		return nil, errors.New("client assertion must contain a numeric 'iat' claim")
	}
	expTime := time.Unix(int64(expFloat), 0)
	iatTime := time.Unix(int64(iatFloat), 0)
	if expTime.Before(iatTime) {
		return nil, errors.New("client assertion 'exp' must be after 'iat'")
	}
	// Check max lifetime
	maxLifetime := v.MaxLifetime
	if maxLifetime == 0 {
		maxLifetime = 5 * time.Minute
	}

	now := time.Now()
	clockSkew := 30 * time.Second

	// Reject iat in the future (beyond clock skew tolerance)
	if iatTime.After(now.Add(clockSkew)) {
		return nil, errors.New("client assertion 'iat' is in the future")
	}

	// Reject exp too far ahead of now (beyond maxLifetime + clock skew)
	if expTime.After(now.Add(maxLifetime + clockSkew)) {
		return nil, fmt.Errorf("client assertion 'exp' is too far in the future (max %s from now)", maxLifetime)
	}

	if expTime.Sub(iatTime) > maxLifetime {
		return nil, fmt.Errorf("client assertion lifetime exceeds maximum (%s)", maxLifetime)
	}

	// JTI replay check
	if v.JTICheck != nil {
		if err := v.JTICheck(jti, expTime); err != nil {
			return nil, fmt.Errorf("client assertion jti replay detected: %w", err)
		}
	}

	result := &ClientAssertionClaims{
		Issuer:   iss,
		Subject:  sub,
		JTI:      jti,
		Expiry:   expTime,
		IssuedAt: iatTime,
	}
	switch aud := claims["aud"].(type) {
	case string:
		result.Audience = aud
	case []any:
		for _, elem := range aud {
			if s, ok := elem.(string); ok && s == v.TokenEndpoint {
				result.Audience = s
				break
			}
		}
	}

	return result, nil
}

// fetchJWKS retrieves a JWKS keyset, using the cache when available.
func (v *ClientAssertionVerifier) fetchJWKS(ctx context.Context, uri string) (jwk.Set, error) {
	if v.JWKSCache == nil {
		return jwk.Fetch(ctx, uri)
	}

	// Try cache first.
	if raw, ok := v.JWKSCache.Get(ctx, uri); ok {
		set, err := jwk.Parse(raw)
		if err == nil {
			return set, nil
		}
		// Cached data is corrupt – fall through to re-fetch.
	}

	// Fetch from remote.
	set, err := jwk.Fetch(ctx, uri)
	if err != nil {
		return nil, err
	}

	// Serialize and store in cache.
	if raw, err := json.Marshal(set); err == nil {
		v.JWKSCache.Set(ctx, uri, raw)
	}

	return set, nil
}
