package apiv1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// jwtKeyMaterial holds key material extracted from a JWT header for signature verification and trust evaluation.
type jwtKeyMaterial struct {
	keyType     trust.KeyType
	keyMaterial any
	publicKey   crypto.PublicKey
	issuerID    string
}

// extractJWTClaimsInfo extracts the issuer identifier and credential type from JWT claims.
func extractJWTClaimsInfo(token *jwt.Token) (issuerID, credentialType string) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ""
	}
	if iss, ok := claims["iss"].(string); ok {
		issuerID = iss
	}
	if vct, ok := claims["vct"].(string); ok {
		credentialType = vct
	}
	return issuerID, credentialType
}

// extractJWTKeyMaterial extracts key type, key material, and public key from the JWT header.
// It supports x5c certificate chains, embedded JWKs, DID-based key resolution, and kid/JWKS resolution.
func (c *Client) extractJWTKeyMaterial(ctx context.Context, token *jwt.Token, issuerID, scope, credentialType string) (*jwtKeyMaterial, error) {
	if x5cRaw, ok := token.Header["x5c"]; ok {
		certChain, err := jose.ParseX5CHeader(x5cRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c header: %w", err)
		}
		effectiveIssuerID := issuerID
		if issuerID == "" {
			effectiveIssuerID = certChain[0].Subject.CommonName
		}
		c.log.Debug("Verifying credential signature via x5c",
			"scope", scope, "issuer_id", effectiveIssuerID,
			"credential_type", credentialType, "cert_chain_length", len(certChain))
		return &jwtKeyMaterial{
			keyType: trust.KeyTypeX5C, keyMaterial: certChain,
			publicKey: certChain[0].PublicKey.(crypto.PublicKey), issuerID: effectiveIssuerID,
		}, nil
	}

	if jwkRaw, ok := token.Header["jwk"]; ok {
		jwkMap, ok := jwkRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid jwk header format: expected map, got %T", jwkRaw)
		}
		publicKey, err := jose.ParseJWKToPublicKey(jwkMap)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jwk header: %w", err)
		}
		c.log.Debug("Verifying credential signature via jwk",
			"scope", scope, "issuer_id", issuerID, "credential_type", credentialType)
		return &jwtKeyMaterial{
			keyType: trust.KeyTypeJWK, keyMaterial: jwkMap,
			publicKey: publicKey, issuerID: issuerID,
		}, nil
	}

	if strings.HasPrefix(issuerID, "did:") {
		resolver, ok := c.trustEvaluator.(trust.KeyResolver)
		if !ok {
			c.log.Warn("Issuer is DID but trust evaluator does not support key resolution",
				"scope", scope, "issuer_id", issuerID)
			return nil, fmt.Errorf("cannot resolve DID issuer key: trust evaluator does not support key resolution")
		}
		c.log.Debug("Resolving issuer key via DID",
			"scope", scope, "issuer_id", issuerID, "credential_type", credentialType)
		resolvedKey, err := resolver.ResolveKey(ctx, issuerID)
		if err != nil {
			c.log.Warn("Failed to resolve DID issuer key",
				"scope", scope, "issuer_id", issuerID, "error", err)
			return nil, fmt.Errorf("failed to resolve DID issuer key: %w", err)
		}
		c.log.Debug("Verifying credential signature via resolved DID key",
			"scope", scope, "issuer_id", issuerID, "credential_type", credentialType)
		return &jwtKeyMaterial{
			keyType: trust.KeyTypeJWK, keyMaterial: resolvedKey,
			publicKey: resolvedKey.(crypto.PublicKey), issuerID: issuerID,
		}, nil
	}

	// Fallback: resolve key via issuer JWKS (SD-JWT VC spec §5.3)
	if kidRaw, ok := token.Header["kid"]; ok {
		kid, ok := kidRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid kid header: expected string, got %T", kidRaw)
		}
		if issuerID == "" {
			return nil, fmt.Errorf("cannot resolve JWKS: issuer ID is empty")
		}
		c.log.Debug("Resolving issuer key via JWKS metadata",
			"scope", scope, "issuer_id", issuerID, "kid", kid,
			"credential_type", credentialType)
		publicKey, jwkMap, err := c.jwksResolver.ResolveKeyByKID(ctx, issuerID, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve issuer key from JWKS: %w", err)
		}
		return &jwtKeyMaterial{
			keyType: trust.KeyTypeJWK, keyMaterial: jwkMap,
			publicKey: publicKey, issuerID: issuerID,
		}, nil
	}

	c.log.Warn("Credential missing key material in header and issuer is not resolvable",
		"scope", scope, "issuer_id", issuerID)
	return nil, fmt.Errorf("credential missing x5c, jwk, or kid header and issuer is not a DID")
}

// evaluateIssuerTrust verifies the credential signature and evaluates the trust of the credential issuer.
// For SD-JWT credentials, it extracts the issuer JWT, verifies signature using the key material from the header,
// and evaluates trust against the configured PDP.
func (c *Client) evaluateIssuerTrust(ctx context.Context, vpToken string, scope string) error {
	if c.trustEvaluator == nil {
		c.log.Error(nil, "Trust evaluator not initialized - this should never happen")
		return fmt.Errorf("trust evaluator not initialized")
	}

	// Split the SD-JWT to get the issuer JWT
	parts := strings.Split(vpToken, "~")
	issuerJWT := parts[0]
	if issuerJWT == "" {
		return fmt.Errorf("empty issuer JWT in VP token")
	}

	// Build the algorithm allowlist for signature verification
	allowedAlgs := c.cfg.APIGW.Trust.AllowedSignatureAlgorithms
	allowedSet := buildAllowedAlgorithmSet(allowedAlgs)

	// keyInfo is captured by the keyfunc closure and populated during jwt.Parse.
	var keyInfo *jwtKeyMaterial

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(issuerJWT, func(token *jwt.Token) (any, error) {
		alg := token.Method.Alg()

		// Check algorithm allowlist - "none" is never permitted
		if !allowedSet[alg] {
			return nil, fmt.Errorf("algorithm %q is not in the allowed list", alg)
		}

		// Extract issuer and credential type from claims
		issuerID, credentialType := extractJWTClaimsInfo(token)

		// Extract key material from header (x5c, jwk, DID, or kid/JWKS resolution)
		ki, err := c.extractJWTKeyMaterial(ctx, token, issuerID, scope, credentialType)
		if err != nil {
			return nil, err
		}
		keyInfo = ki

		// Validate the signing method matches the key type
		if err := validateSigningMethodForKey(token, ki.publicKey); err != nil {
			return nil, err
		}

		return ki.publicKey, nil
	})
	if err != nil {
		c.log.Warn("JWT signature verification failed",
			"scope", scope, "error", err)
		return fmt.Errorf("JWT signature verification failed: %w", err)
	}

	// At this point the JWT signature is verified. Extract claims for trust evaluation.
	issuerID := keyInfo.issuerID
	credentialType := ""
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if vct, ok := claims["vct"].(string); ok {
			credentialType = vct
		}
	}

	c.log.Debug("JWT signature verified successfully",
		"scope", scope, "issuer_id", issuerID)

	// Evaluate trust via AuthZEN PDP
	decision, err := c.trustEvaluator.Evaluate(ctx, &trust.EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID:      issuerID,
			KeyType:        keyInfo.keyType,
			Key:            keyInfo.keyMaterial,
			Role:           trust.RoleCredentialIssuer,
			CredentialType: credentialType,
		},
	})
	if err != nil {
		return fmt.Errorf("trust evaluation error: %w", err)
	}

	if !decision.Trusted {
		c.log.Warn("Issuer not trusted",
			"scope", scope, "issuer_id", issuerID,
			"key_type", keyInfo.keyType, "reason", decision.Reason,
			"trust_framework", decision.TrustFramework)
		return fmt.Errorf("issuer not trusted: %s", decision.Reason)
	}

	c.log.Info("Issuer trust verified",
		"scope", scope, "issuer_id", issuerID,
		"key_type", keyInfo.keyType, "trust_framework", decision.TrustFramework)

	return nil
}

// defaultAllowedAlgorithms is the secure default set of allowed JWT signature algorithms.
var defaultAllowedAlgorithms = []string{
	"ES256", "ES384", "ES512",
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"EdDSA",
}

// buildAllowedAlgorithmSet creates a set of allowed algorithms for O(1) lookup.
// The "none" algorithm is NEVER allowed regardless of configuration.
func buildAllowedAlgorithmSet(allowedAlgorithms []string) map[string]bool {
	if len(allowedAlgorithms) == 0 {
		allowedAlgorithms = defaultAllowedAlgorithms
	}
	allowedSet := make(map[string]bool, len(allowedAlgorithms))
	for _, alg := range allowedAlgorithms {
		allowedSet[alg] = true
	}
	delete(allowedSet, "none")
	delete(allowedSet, "None")
	delete(allowedSet, "NONE")
	return allowedSet
}

// validateSigningMethodForKey checks that the JWT signing method is compatible with the provided public key type.
func validateSigningMethodForKey(token *jwt.Token, publicKey crypto.PublicKey) error {
	alg := token.Method.Alg()
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return fmt.Errorf("unexpected signing method %v for ECDSA key", alg)
		}
	case *rsa.PublicKey:
		_, isRS := token.Method.(*jwt.SigningMethodRSA)
		_, isPS := token.Method.(*jwt.SigningMethodRSAPSS)
		if !isRS && !isPS {
			return fmt.Errorf("unexpected signing method %v for RSA key", alg)
		}
	case ed25519.PublicKey:
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return fmt.Errorf("unexpected signing method %v for Ed25519 key", alg)
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", publicKey)
	}
	return nil
}
