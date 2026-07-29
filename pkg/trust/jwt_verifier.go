package trust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// JWTKeyMaterial holds key material extracted from a JWT header for signature verification and trust evaluation.
type JWTKeyMaterial struct {
	KeyType     KeyType
	KeyMaterial any
	PublicKey   crypto.PublicKey
	IssuerID    string
}

// ParseX5CFunc parses an x5c header value into a certificate chain.
type ParseX5CFunc func(x5cRaw any) ([]*x509.Certificate, error)

// ParseJWKFunc parses a JWK map into a public key.
type ParseJWKFunc func(jwkData any) (crypto.PublicKey, error)

// Logger is a minimal logging interface for the JWT trust verifier.
type Logger interface {
	Debug(msg string, args ...any)
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}

// JWTTrustVerifierConfig configures a JWTTrustVerifier.
type JWTTrustVerifierConfig struct {
	TrustEvaluator             TrustEvaluator
	JWKSResolver               *JWKSKeyResolver
	AllowedSignatureAlgorithms []string
	ParseX5C                   ParseX5CFunc
	ParseJWK                   ParseJWKFunc
	Log                        Logger
}

// JWTTrustVerifier verifies JWT credential signatures and evaluates issuer trust.
// It handles key extraction from x5c, jwk, DID, and kid/JWKS headers,
// verifies signatures, and delegates trust decisions to the configured TrustEvaluator.
type JWTTrustVerifier struct {
	trustEvaluator TrustEvaluator
	jwksResolver   *JWKSKeyResolver
	allowedAlgs    []string
	parseX5C       ParseX5CFunc
	parseJWK       ParseJWKFunc
	log            Logger
}

// noopLogger is a Logger that discards all log messages.
type noopLogger struct{}

func (noopLogger) Debug(string, ...any) {}
func (noopLogger) Warn(string, ...any)  {}
func (noopLogger) Info(string, ...any)  {}

// NewJWTTrustVerifier creates a new JWT trust verifier with the given configuration.
func NewJWTTrustVerifier(cfg JWTTrustVerifierConfig) *JWTTrustVerifier {
	log := cfg.Log
	if log == nil {
		log = noopLogger{}
	}
	return &JWTTrustVerifier{
		trustEvaluator: cfg.TrustEvaluator,
		jwksResolver:   cfg.JWKSResolver,
		allowedAlgs:    cfg.AllowedSignatureAlgorithms,
		parseX5C:       cfg.ParseX5C,
		parseJWK:       cfg.ParseJWK,
		log:            log,
	}
}

// EvaluateIssuerTrust verifies the credential signature and evaluates the trust of the credential issuer.
// It splits the SD-JWT VP token, verifies the issuer JWT signature using key material from the header
// (x5c, jwk, DID resolution, or kid/JWKS resolution), and evaluates trust via the configured PDP.
func (v *JWTTrustVerifier) EvaluateIssuerTrust(ctx context.Context, vpToken string, scope string) error {
	if v.trustEvaluator == nil {
		v.log.Warn("Trust evaluator not initialized - this should never happen")
		return fmt.Errorf("trust evaluator not initialized")
	}

	// Split the SD-JWT to get the issuer JWT
	parts := strings.Split(vpToken, "~")
	issuerJWT := parts[0]
	if issuerJWT == "" {
		return fmt.Errorf("empty issuer JWT in VP token")
	}

	// Build the algorithm allowlist for signature verification
	allowedSet := BuildAllowedAlgorithmSet(v.allowedAlgs)

	// keyInfo is captured by the keyfunc closure and populated during jwt.Parse.
	var keyInfo *JWTKeyMaterial

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(issuerJWT, func(token *jwt.Token) (any, error) {
		alg := token.Method.Alg()

		// Check algorithm allowlist - "none" is never permitted
		if !allowedSet[alg] {
			return nil, fmt.Errorf("algorithm %q is not in the allowed list", alg)
		}

		// Extract issuer and credential type from claims
		issuerID, credentialType := ExtractJWTClaimsInfo(token)

		// Extract key material from header (x5c, jwk, DID, or kid/JWKS resolution)
		ki, err := v.extractJWTKeyMaterial(ctx, token, issuerID, scope, credentialType)
		if err != nil {
			return nil, err
		}
		keyInfo = ki

		// Validate the signing method matches the key type
		if err := ValidateSigningMethodForKey(token, ki.PublicKey); err != nil {
			return nil, err
		}

		return ki.PublicKey, nil
	})
	if err != nil {
		v.log.Warn("JWT signature verification failed",
			"scope", scope, "error", err)
		return fmt.Errorf("JWT signature verification failed: %w", err)
	}

	// At this point the JWT signature is verified. Extract claims for trust evaluation.
	issuerID := keyInfo.IssuerID
	credentialType := ""
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if vct, ok := claims["vct"].(string); ok {
			credentialType = vct
		}
	}

	v.log.Debug("JWT signature verified successfully",
		"scope", scope, "issuer_id", issuerID)

	// Evaluate trust via AuthZEN PDP
	decision, err := v.trustEvaluator.Evaluate(ctx, &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID:      issuerID,
			KeyType:        keyInfo.KeyType,
			Key:            keyInfo.KeyMaterial,
			Role:           RoleCredentialIssuer,
			CredentialType: credentialType,
		},
	})
	if err != nil {
		return fmt.Errorf("trust evaluation error: %w", err)
	}

	if !decision.Trusted {
		v.log.Warn("Issuer not trusted",
			"scope", scope, "issuer_id", issuerID,
			"key_type", keyInfo.KeyType, "reason", decision.Reason,
			"trust_framework", decision.TrustFramework)
		return fmt.Errorf("issuer not trusted: %s", decision.Reason)
	}

	v.log.Info("Issuer trust verified",
		"scope", scope, "issuer_id", issuerID,
		"key_type", keyInfo.KeyType, "trust_framework", decision.TrustFramework)

	return nil
}

// extractJWTKeyMaterial extracts key type, key material, and public key from the JWT header.
// It supports x5c certificate chains, embedded JWKs, DID-based key resolution, and kid/JWKS resolution.
func (v *JWTTrustVerifier) extractJWTKeyMaterial(ctx context.Context, token *jwt.Token, issuerID, scope, credentialType string) (*JWTKeyMaterial, error) {
	if x5cRaw, ok := token.Header["x5c"]; ok {
		if v.parseX5C == nil {
			return nil, fmt.Errorf("x5c header present but ParseX5C is not configured")
		}
		certChain, err := v.parseX5C(x5cRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c header: %w", err)
		}
		effectiveIssuerID := issuerID
		if issuerID == "" {
			effectiveIssuerID = certChain[0].Subject.CommonName
		}
		v.log.Debug("Verifying credential signature via x5c",
			"scope", scope, "issuer_id", effectiveIssuerID,
			"credential_type", credentialType, "cert_chain_length", len(certChain))
		return &JWTKeyMaterial{
			KeyType: KeyTypeX5C, KeyMaterial: certChain,
			PublicKey: certChain[0].PublicKey.(crypto.PublicKey), IssuerID: effectiveIssuerID,
		}, nil
	}

	if jwkRaw, ok := token.Header["jwk"]; ok {
		jwkMap, ok := jwkRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid jwk header format: expected map, got %T", jwkRaw)
		}
		if v.parseJWK == nil {
			return nil, fmt.Errorf("jwk header present but ParseJWK is not configured")
		}
		publicKey, err := v.parseJWK(jwkMap)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jwk header: %w", err)
		}
		v.log.Debug("Verifying credential signature via jwk",
			"scope", scope, "issuer_id", issuerID, "credential_type", credentialType)
		return &JWTKeyMaterial{
			KeyType: KeyTypeJWK, KeyMaterial: jwkMap,
			PublicKey: publicKey, IssuerID: issuerID,
		}, nil
	}

	if strings.HasPrefix(issuerID, "did:") {
		resolver, ok := v.trustEvaluator.(KeyResolver)
		if !ok {
			v.log.Warn("Issuer is DID but trust evaluator does not support key resolution",
				"scope", scope, "issuer_id", issuerID)
			return nil, fmt.Errorf("cannot resolve DID issuer key: trust evaluator does not support key resolution")
		}
		v.log.Debug("Resolving issuer key via DID",
			"scope", scope, "issuer_id", issuerID, "credential_type", credentialType)
		resolvedKey, err := resolver.ResolveKey(ctx, issuerID)
		if err != nil {
			v.log.Warn("Failed to resolve DID issuer key",
				"scope", scope, "issuer_id", issuerID, "error", err)
			return nil, fmt.Errorf("failed to resolve DID issuer key: %w", err)
		}
		v.log.Debug("Verifying credential signature via resolved DID key",
			"scope", scope, "issuer_id", issuerID, "credential_type", credentialType)
		return &JWTKeyMaterial{
			KeyType: KeyTypeJWK, KeyMaterial: resolvedKey,
			PublicKey: resolvedKey, IssuerID: issuerID,
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
		if v.jwksResolver == nil {
			return nil, fmt.Errorf("JWKS resolver not configured but kid header present")
		}
		v.log.Debug("Resolving issuer key via JWKS metadata",
			"scope", scope, "issuer_id", issuerID, "kid", kid,
			"credential_type", credentialType)
		publicKey, jwkMap, err := v.jwksResolver.ResolveKeyByKID(ctx, issuerID, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve issuer key from JWKS: %w", err)
		}
		return &JWTKeyMaterial{
			KeyType: KeyTypeJWK, KeyMaterial: jwkMap,
			PublicKey: publicKey, IssuerID: issuerID,
		}, nil
	}

	v.log.Warn("Credential missing key material in header and issuer is not resolvable",
		"scope", scope, "issuer_id", issuerID)
	return nil, fmt.Errorf("credential missing x5c, jwk, or kid header and issuer is not a DID")
}

// ExtractJWTClaimsInfo extracts the issuer identifier and credential type from JWT claims.
func ExtractJWTClaimsInfo(token *jwt.Token) (issuerID, credentialType string) {
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

// DefaultAllowedAlgorithms is the secure default set of allowed JWT signature algorithms.
// These are all considered cryptographically strong as of 2024.
var DefaultAllowedAlgorithms = []string{
	"ES256", "ES384", "ES512", // ECDSA
	"RS256", "RS384", "RS512", // RSA PKCS#1 v1.5
	"PS256", "PS384", "PS512", // RSA-PSS
	"EdDSA", // Ed25519
}

// BuildAllowedAlgorithmSet creates a set of allowed algorithms for O(1) lookup.
// The "none" algorithm is NEVER allowed regardless of configuration.
func BuildAllowedAlgorithmSet(allowedAlgorithms []string) map[string]bool {
	if len(allowedAlgorithms) == 0 {
		allowedAlgorithms = DefaultAllowedAlgorithms
	}
	allowedSet := make(map[string]bool, len(allowedAlgorithms))
	for _, alg := range allowedAlgorithms {
		allowedSet[alg] = true
	}
	// SECURITY: "none" algorithm is NEVER allowed, even if misconfigured
	delete(allowedSet, "none")
	delete(allowedSet, "None")
	delete(allowedSet, "NONE")
	return allowedSet
}

// ValidateSigningMethodForKey checks that the JWT signing method is compatible with the provided public key type.
func ValidateSigningMethodForKey(token *jwt.Token, publicKey crypto.PublicKey) error {
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
