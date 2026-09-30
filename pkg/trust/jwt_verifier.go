package trust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
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

// VerifyJWTSignature parses tokenString and verifies its signature using key
// material resolved from its own header/claims (x5c, embedded jwk, DID-based
// issuer, or kid/JWKS lookup - see extractJWTKeyMaterial), WITHOUT evaluating
// PDP trust. Exposed separately from EvaluateIssuerTrust so callers that need
// a different PDP role or request shape than EvaluateIssuerTrust's hardcoded
// RoleCredentialIssuer/SD-JWT-VP splitting (e.g. WalletAttestationEvaluator,
// which verifies a WIA - a plain JWT, not an SD-JWT VP - and then evaluates
// trust with RoleWalletProvider) can reuse the same verification instead of
// hand-rolling a parallel, easy-to-get-wrong implementation.
//
// issuerID/credentialType for key resolution and logging come from the
// token's own iss/vct claims (ExtractJWTClaimsInfo) - correct for any JWT
// that uses the iss claim conventionally, WIAs included; vct simply stays
// empty for non-SD-JWT-VC tokens like a WIA.
func (v *JWTTrustVerifier) VerifyJWTSignature(ctx context.Context, tokenString, scope string) (*jwt.Token, *JWTKeyMaterial, error) {
	allowedSet := BuildAllowedAlgorithmSet(v.allowedAlgs)

	// keyInfo is captured by the keyfunc closure and populated during jwt.Parse.
	var keyInfo *JWTKeyMaterial

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(tokenString, func(token *jwt.Token) (any, error) {
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
		return nil, nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	return token, keyInfo, nil
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

	token, keyInfo, err := v.VerifyJWTSignature(ctx, issuerJWT, scope)
	if err != nil {
		return err
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
		SubjectID:      issuerID,
		KeyType:        keyInfo.KeyType,
		Key:            keyInfo.KeyMaterial,
		Role:           RoleCredentialIssuer,
		CredentialType: credentialType,
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

// StatusListSignerAction is the AuthZEN action.name used when evaluating
// the signer of a Token Status List. It matches go-wallet-backend's
// trust.StatusListSignerAction so that one go-trust policy governs both
// ends of the same exchange.
const StatusListSignerAction = "status-list-signer"

// StatusListIssuerFallbackAction is the action tried when
// StatusListSignerAction does not produce a trusted decision. It is the
// ordinary credential-issuer policy, and it covers the common deployment
// where the credential issuer signs the status lists for the credentials
// it issued: such a party is already trusted as an issuer, and a
// deployment should not have to name it twice to keep revocation working.
// go-wallet-backend does the same two calls, in the same order.
const StatusListIssuerFallbackAction = string(RoleCredentialIssuer)

// statusListTokenIssuer returns a verified status list token's own iss
// claim, or "" when it carries none.
func statusListTokenIssuer(token *jwt.Token) string {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	issuer, _ := claims["iss"].(string)
	return issuer
}

// statusListSubjectFromURI reduces a status list URL to the origin that
// served it, for use as a trust subject when the token carries no iss.
func statusListSubjectFromURI(listURI string) string {
	u, err := url.Parse(listURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// VerifyStatusListToken verifies a Status List Token's signature using key
// material carried in its OWN header - x5c or jwk, and the same DID and
// kid/JWKS paths every other JWT here uses - and then evaluates trust in
// the signer through go-trust.
//
// A status list decides whether a credential is still valid, so the
// question "may this party say that" is the same trust question asked of
// the credential's issuer, and it has to be answered the same way. Taking
// the key from a configured file or from JWKS discovery alone answers only
// "is this the key I expected", never "is this party trusted to speak for
// these credentials" - and with revocation.fail_open at its default, a
// failure to answer is tolerated.
//
// Two evaluations are made, in order:
//
//  1. "status-list-signer". Being trusted to issue credentials is not the
//     same as being trusted to publish their revocation status: with an
//     external status service the two are different parties signing with
//     different keys, and judging the status service as a credential issuer
//     would deny every legitimate one.
//  2. "credential-issuer", only if the first did not produce a trusted
//     decision. This covers the common case - the credential issuer signing
//     the status lists for its own credentials. That party is already named
//     as an issuer, and a deployment should not have to name it a second
//     time under a different action just to keep revocation working.
//
// go-wallet-backend makes the same two calls in the same order, so one
// policy set covers both ends of the exchange.
//
// Role is left empty on both so GetEffectiveAction uses the explicit action
// rather than composing one from the role.
//
// NOTE FOR DEPLOYMENTS: go-trust falls back to its DEFAULT policy for an
// unknown action name, so a deployment that defines neither action judges
// status list signers by whatever the default says rather than failing
// loudly.
//
// The returned token has a verified signature AND a trusted signer. It is
// distinct from EvaluateIssuerTrust only in that a Status List Token is a
// plain JWT rather than an SD-JWT, so there is nothing to split and no vct
// to read.
func (v *JWTTrustVerifier) VerifyStatusListToken(ctx context.Context, tokenString, listURI string) (*jwt.Token, error) {
	if v.trustEvaluator == nil {
		return nil, fmt.Errorf("trust evaluator not initialized")
	}

	token, keyInfo, err := v.VerifyJWTSignature(ctx, tokenString, listURI)
	if err != nil {
		return nil, err
	}

	// Subject: the token's own iss when it has one, otherwise the origin of
	// the list URI. A status list token need not carry iss (Section 5.1's
	// required claims are sub, iat and status_list), and a policy still has
	// to name something - the origin is what the deployment actually
	// fetched from. Same rule as go-wallet-backend uses.
	//
	// Read from the CLAIMS, not from keyInfo.IssuerID. For an x5c token
	// with no iss, IssuerID is filled in from the leaf certificate's common
	// name (see extractJWTKeyMaterial), so using it here asked the PDP
	// about a CN while the rule above - and the deployment's policy - say
	// the origin. A conforming status service that signs with x5c and omits
	// iss would have been judged as whatever its certificate happened to be
	// named.
	subject := statusListTokenIssuer(token)
	if subject == "" {
		subject = statusListSubjectFromURI(listURI)
	}
	if subject == "" {
		return nil, fmt.Errorf("cannot determine a trust subject for status list %q", listURI)
	}

	decision, action, err := v.evaluateStatusListSigner(ctx, subject, keyInfo, listURI)
	if err != nil {
		return nil, err
	}
	if !decision.Trusted {
		v.log.Warn("Status list signer not trusted",
			"list_uri", listURI, "subject", subject, "action", action,
			"key_type", keyInfo.KeyType, "reason", decision.Reason,
			"trust_framework", decision.TrustFramework)
		return nil, fmt.Errorf("status list %q is signed by an untrusted party: %s", listURI, decision.Reason)
	}

	v.log.Info("Status list signer trust verified",
		"list_uri", listURI, "subject", subject, "action", action,
		"key_type", keyInfo.KeyType, "trust_framework", decision.TrustFramework)

	return token, nil
}

// evaluateStatusListSigner asks the PDP about the status list signer, first
// as a status-list-signer and then, if that is not trusted, as the ordinary
// credential issuer. It returns the decision that was acted on along with
// the action that produced it.
//
// An evaluation ERROR is not a denial - the PDP did not answer - so the
// fallback is tried after one too, and the first error is reported only if
// the fallback also fails to produce an answer. A refusal from the fallback
// is reported as a refusal, not as the earlier transport error, because a
// policy that says no is the more specific fact.
func (v *JWTTrustVerifier) evaluateStatusListSigner(ctx context.Context, subject string, keyInfo *JWTKeyMaterial, listURI string) (*TrustDecision, string, error) {
	evaluate := func(action string) (*TrustDecision, error) {
		return v.trustEvaluator.Evaluate(ctx, &EvaluationRequest{
			SubjectID: subject,
			KeyType:   keyInfo.KeyType,
			Key:       keyInfo.KeyMaterial,
			Action:    action,
		})
	}

	decision, err := evaluate(StatusListSignerAction)
	if err == nil && decision != nil && decision.Trusted {
		return decision, StatusListSignerAction, nil
	}

	v.log.Debug("Status list signer not trusted under status-list-signer, trying credential-issuer",
		"list_uri", listURI, "subject", subject, "error", err)

	fallback, fallbackErr := evaluate(StatusListIssuerFallbackAction)
	if fallbackErr == nil && fallback != nil {
		return fallback, StatusListIssuerFallbackAction, nil
	}

	// Neither action produced an answer. Report the first failure, which is
	// the one about the action this call is really asking about. An
	// evaluator that returns neither a decision nor an error has broken its
	// contract; treat that as a refusal to answer rather than dereferencing
	// the nil it handed back.
	if err == nil {
		err = fallbackErr
	}
	if err == nil {
		err = fmt.Errorf("trust evaluator returned no decision")
	}
	return nil, "", fmt.Errorf("trust evaluation error for status list %q: %w", listURI, err)
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
