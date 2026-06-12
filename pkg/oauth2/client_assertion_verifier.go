package oauth2

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"time"

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
}

// defaultAllowedAlgorithms is the allowlist of signing algorithms accepted for client assertions.
var defaultAllowedAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}

// Verify verifies a client_assertion JWT against the client's JWKS, validating
// the signature, audience, issuer/subject, expiration, and jti (replay protection).
// Returns the validated claims or an error.
func (v *ClientAssertionVerifier) Verify(ctx context.Context, assertion string, client *Client) (*ClientAssertionClaims, error) {
	if client.JWKSURI == "" {
		return nil, errors.New("client has no jwks_uri configured for assertion verification")
	}

	// Fetch the client's JWKS
	keySet, err := jwk.Fetch(ctx, client.JWKSURI)
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
		var matchedKey jwk.Key
		if kid != "" {
			matchedKey, _ = keySet.LookupKeyID(kid)
		}
		if matchedKey == nil {
			// Fall back to first key with matching algorithm
			for i := 0; i < keySet.Len(); i++ {
				k, ok := keySet.Key(i)
				if !ok {
					continue
				}
				kAlg, hasAlg := k.Algorithm()
				if hasAlg && kAlg.String() == alg {
					matchedKey = k
					break
				}
			}
		}
		if matchedKey == nil {
			// Last resort: try first key in set
			if keySet.Len() > 0 {
				k, ok := keySet.Key(0)
				if ok {
					matchedKey = k
				}
			}
		}
		if matchedKey == nil {
			return nil, errors.New("no suitable key found in client JWKS")
		}

		// Extract raw public key
		var rawKey crypto.PublicKey
		if err := jwk.Export(matchedKey, &rawKey); err != nil {
			return nil, fmt.Errorf("failed to extract raw key: %w", err)
		}
		return rawKey, nil
	},
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithAudience(v.TokenEndpoint),
		jwt.WithExpirationRequired(),
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
	if jti == "" {
		return nil, errors.New("client assertion must contain 'jti' claim for replay protection")
	}

	// Parse time claims
	expFloat, _ := claims["exp"].(float64)
	iatFloat, _ := claims["iat"].(float64)
	expTime := time.Unix(int64(expFloat), 0)
	iatTime := time.Unix(int64(iatFloat), 0)

	// Check max lifetime
	maxLifetime := v.MaxLifetime
	if maxLifetime == 0 {
		maxLifetime = 5 * time.Minute
	}
	if iatFloat > 0 && expTime.Sub(iatTime) > maxLifetime {
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
	if aud, ok := claims["aud"].(string); ok {
		result.Audience = aud
	}

	return result, nil
}
