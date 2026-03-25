package apiv1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

type VerificationRequestObjectRequest struct {
	ID string `json:"-" form:"id" uri:"id" validate:"required,max=128,printascii"`
	//SessionID string `json:"-"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	// Query by RequestObjectID since that's what the wallet sends via ?id= parameter
	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{
		RequestObjectID: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	// TODO(masv): should requestObjectCache be using cache lib
	requestObject, found := c.openid4vp.RequestObjectCache.Get(authorizationContext.RequestObjectID)
	if !found {
		c.log.Error(nil, "request object not found in cache", "requestObjectID", authorizationContext.RequestObjectID)
		return "", errors.New("request object not found")
	}

	signedJWT, err := requestObject.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", signedJWT)

	return signedJWT, nil
}

type VerificationDirectPostRequest struct {
	Response  string `json:"response"  form:"response"`
	SessionID string `json:"-"` // Set by HTTP layer if same-device flow
}

func (v *VerificationDirectPostRequest) GetKID() (string, error) {
	return jose.ExtractKIDFromCompactJWT(v.Response)
}

type VerificationDirectPostResponse struct {
	// RedirectURI is optional - only included for same-device flows
	// For cross-device flows, the browser is notified via SSE instead
	RedirectURI string `json:"redirect_uri,omitempty"`
}

func (c *Client) VerificationDirectPost(ctx context.Context, req *VerificationDirectPostRequest) (*VerificationDirectPostResponse, error) {
	c.log.Debug("Verification direct-post")

	// Extract KID from JWE header
	kid, err := req.GetKID()
	if err != nil {
		c.log.Error(err, "failed to get KID from request")
		return nil, err
	}

	// Get ephemeral private key from cache
	privateEphemeralJWK, found := c.openid4vp.EphemeralKeyCache.Get(kid)
	if !found {
		c.log.Debug("No ephemeral key found in cache", "kid", kid)
		return nil, errors.New("ephemeral key not found in cache")
	}

	c.log.Debug("Found ephemeral key in cache", "kid", kid)

	// Decrypt JWE response
	decryptedJWE, err := jwe.Decrypt([]byte(req.Response), jwe.WithKey(jwa.ECDH_ES(), privateEphemeralJWK))
	if err != nil {
		c.log.Error(err, "failed to decrypt JWE")
		return nil, err
	}

	// Parse response parameters using openid4vp
	vpResponse := openid4vp.VPResponse{}
	if err := json.Unmarshal(decryptedJWE, &vpResponse); err != nil {
		c.log.Error(err, "failed to unmarshal decrypted JWE")
		return nil, err
	}

	c.log.Debug("directPost", "vpResponse", vpResponse)

	// Get authorization context by state
	authCtx, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: vpResponse.State})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}

	// Generate response code
	responseCode := uuid.NewString()
	callbackURL, err := url.JoinPath(c.cfg.Verifier.PublicURL, "/verification/callback")
	if err != nil {
		c.log.Error(err, "Failed to construct callback URL")
		return nil, fmt.Errorf("failed to construct callback URL: %w", err)
	}
	u, err := url.Parse(callbackURL)
	if err != nil {
		c.log.Error(err, "Failed to parse callback URL")
		return nil, fmt.Errorf("failed to parse callback URL: %w", err)
	}
	q := u.Query()
	q.Set("response_code", responseCode)
	u.RawQuery = q.Encode()
	redirectURI := u.String()
	c.notify.Submit(authCtx.SessionID, map[string]string{"redirect_uri": redirectURI})

	// Process all VP tokens for the requested scopes
	credentialCaches := make([]sdjwtvc.CredentialCache, 0, len(authCtx.Scopes))

	for _, scope := range authCtx.Scopes {
		vpToken, ok := vpResponse.VPToken[scope]
		if !ok {
			c.log.Error(nil, "VP token not found for scope", "scope", scope)
			return nil, fmt.Errorf("VP token not found for scope: %s", scope)
		}

		responseParams := &openid4vp.ResponseParameters{}
		responseParams.State = vpResponse.State
		responseParams.VPToken = vpToken

		// Validate response parameters
		if err := responseParams.Validate(); err != nil {
			c.log.Error(err, "response parameters validation failed", "scope", scope)
			return nil, fmt.Errorf("invalid response for scope %s: %w", scope, err)
		}

		// Detect credential format and process accordingly
		format := detectCredentialFormat(vpToken)
		c.log.Debug("Detected credential format", "scope", scope, "format", format)

		switch format {
		case FormatSDJWT:
			// SD-JWT: Use VPTokenValidator for format validation, then evaluateIssuerTrust for sig+trust
			validator := &openid4vp.VPTokenValidator{
				Nonce:           authCtx.Nonce,
				ClientID:        authCtx.ClientID,
				ValidateFormat:  false, // We do real signature verification in evaluateIssuerTrust
				CheckRevocation: false,
			}

			if err := validator.Validate(responseParams.VPToken); err != nil {
				c.log.Error(err, "VP Token validation failed", "scope", scope)
				return nil, fmt.Errorf("VP Token validation failed for scope %s: %w", scope, err)
			}

			c.log.Debug("VP Token format validated successfully", "scope", scope)

			// Evaluate trust (includes signature verification) via TrustEvaluator
			if err := c.evaluateIssuerTrust(ctx, responseParams.VPToken, scope); err != nil {
				c.log.Error(err, "issuer trust evaluation failed", "scope", scope)
				return nil, fmt.Errorf("issuer trust evaluation failed for scope %s: %w", scope, err)
			}

			// Parse SD-JWT credential
			_, _, _, selectiveDisclosure, _, err := sdjwtvc.Token(responseParams.VPToken).Split()
			if err != nil {
				c.log.Error(err, "failed to split sd-jwt", "scope", scope)
				return nil, err
			}

			// Parse credential claims
			parsed, err := sdjwtvc.Token(responseParams.VPToken).Parse()
			if err != nil {
				c.log.Error(err, "failed to parse sd-jwt credential", "scope", scope)
				return nil, err
			}

			selectiveDisclosureClaims, err := sdjwtvc.ParseSelectiveDisclosure(selectiveDisclosure)
			if err != nil {
				c.log.Error(err, "failed to parse selective disclosures", "scope", scope)
				return nil, err
			}

			// Add to credential cache array
			credentialCaches = append(credentialCaches, sdjwtvc.CredentialCache{
				Credential: parsed.Claims,
				Claims:     selectiveDisclosureClaims,
			})

		case FormatMDoc:
			// mDOC: Use MDocHandler which delegates to TrustEvaluator
			if c.trustEvaluator == nil {
				c.log.Error(nil, "TrustEvaluator required for mDOC verification", "scope", scope)
				return nil, fmt.Errorf("TrustEvaluator not configured for mDOC verification")
			}

			mdocHandler, err := openid4vp.NewMDocHandler(
				openid4vp.WithMDocTrustEvaluator(c.trustEvaluator),
			)
			if err != nil {
				c.log.Error(err, "failed to create mDOC handler", "scope", scope)
				return nil, fmt.Errorf("failed to create mDOC handler for scope %s: %w", scope, err)
			}

			mdocResult, err := mdocHandler.VerifyAndExtract(ctx, vpToken)
			if err != nil {
				c.log.Error(err, "mDOC verification failed", "scope", scope)
				return nil, fmt.Errorf("mDOC verification failed for scope %s: %w", scope, err)
			}

			c.log.Debug("mDOC verified successfully", "scope", scope, "doc_count", len(mdocResult.Documents))

			// Convert mDOC claims to credential cache format
			for docType, docClaims := range mdocResult.Documents {
				// Convert map claims to []Discloser format
				disclosers := mapToDisclosers(docClaims.GetClaims())
				credentialCaches = append(credentialCaches, sdjwtvc.CredentialCache{
					Credential: map[string]any{
						"docType":    docType,
						"namespaces": docClaims.Namespaces,
					},
					Claims: disclosers,
				})
			}

		default:
			c.log.Error(nil, "Unknown credential format", "scope", scope, "format", format)
			return nil, fmt.Errorf("unknown credential format for scope %s", scope)
		}
	}

	// Cache validated credentials
	c.cacheService.Credential.Set(ctx, responseCode, credentialCaches)

	c.log.Debug("Credentials cached", "response_code", responseCode, "count", len(credentialCaches))

	reply := &VerificationDirectPostResponse{}

	// Check if there's an active SSE listener for this session
	// If yes -> cross-device flow: browser is listening, notify via SSE, don't include redirect_uri
	// If no -> same-device flow: no browser listening, include redirect_uri for wallet to follow
	if c.notify.HasListener(authCtx.SessionID) {
		// Cross-device flow: browser is waiting on SSE
		c.log.Debug("Cross-device flow detected (SSE listener active)", "session_id", authCtx.SessionID)
		// Don't include redirect_uri - wallet shows success, browser gets SSE notification
	} else {
		// Same-device flow: no SSE listener, wallet should redirect
		c.log.Debug("Same-device flow detected (no SSE listener)", "session_id", authCtx.SessionID)
		reply.RedirectURI = redirectURI
	}

	return reply, nil
}

type VerificationCallbackRequest struct {
	ResponseCode string `form:"response_code" uri:"response_code"`
}

type VerificationCallbackResponse struct {
	CredentialData []sdjwtvc.CredentialCache `json:"credential_data"`
}

func (c *Client) VerificationCallback(ctx context.Context, req *VerificationCallbackRequest) (*VerificationCallbackResponse, error) {
	c.log.Debug("verificationCallback", "req", req)

	credential, ok := c.cacheService.Credential.Get(ctx, req.ResponseCode)
	if !ok {
		return nil, fmt.Errorf("no item in credential cache matching id %s", req.ResponseCode)
	}

	reply := &VerificationCallbackResponse{
		CredentialData: credential,
	}

	return reply, nil
}

// jwtKeyMaterial holds key material extracted from a JWT header for signature verification and trust evaluation.
type jwtKeyMaterial struct {
	keyType     trust.KeyType
	keyMaterial any
	publicKey   crypto.PublicKey
	issuerID    string // may be updated (e.g., from cert CN fallback)
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
// It supports x5c certificate chains, embedded JWKs, and DID-based key resolution.
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
			publicKey: certChain[0].PublicKey, issuerID: effectiveIssuerID,
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
			publicKey: resolvedKey, issuerID: issuerID,
		}, nil
	}

	// Fallback: resolve key via issuer JWKS (SD-JWT VC spec §5.3)
	// When the issuer is an HTTPS URL and the JWT has a kid header,
	// fetch the issuer's JWT VC Issuer Metadata to obtain the JWKS.
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
// For SD-JWT credentials with x5c header, it extracts the certificate chain, verifies the signature,
// and evaluates trust against the AuthZEN PDP. For credentials with jwk header, it uses the embedded JWK.
// If neither x5c nor jwk header is present but the issuer is a DID, it attempts to resolve
// the key via go-trust's DID resolution. Signature verification happens as part of jwt.Parse.
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
	allowedAlgs := c.cfg.Verifier.Trust.AllowedSignatureAlgorithms
	allowedSet := buildAllowedAlgorithmSet(allowedAlgs)

	// keyInfo is captured by the keyfunc closure and populated during jwt.Parse.
	// The keyfunc inspects the JWT header (x5c/jwk) and claims (iss for DID resolution)
	// to determine which public key to use for signature verification.
	var keyInfo *jwtKeyMaterial

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(issuerJWT, func(token *jwt.Token) (any, error) {
		alg := token.Method.Alg()

		// Check algorithm allowlist - "none" is never permitted
		if !allowedSet[alg] {
			return nil, fmt.Errorf("algorithm %q is not in the allowed list", alg)
		}

		// Extract issuer and credential type from claims (available in keyfunc)
		issuerID, credentialType := extractJWTClaimsInfo(token)

		// Extract key material from header (x5c, jwk, or DID resolution)
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
// These are all considered cryptographically strong as of 2024.
var defaultAllowedAlgorithms = []string{
	"ES256", "ES384", "ES512", // ECDSA
	"RS256", "RS384", "RS512", // RSA PKCS#1 v1.5
	"PS256", "PS384", "PS512", // RSA-PSS
	"EdDSA", // Ed25519
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
	// SECURITY: "none" algorithm is NEVER allowed, even if misconfigured
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

// CredentialFormat represents the format of a verifiable credential.
type CredentialFormat string

const (
	// FormatSDJWT represents SD-JWT Verifiable Credentials (vc+sd-jwt, dc+sd-jwt)
	FormatSDJWT CredentialFormat = "vc+sd-jwt"
	// FormatMDoc represents ISO/IEC 18013-5 mDOC credentials (mso_mdoc)
	FormatMDoc CredentialFormat = "mso_mdoc"
	// FormatUnknown represents an unrecognized format
	FormatUnknown CredentialFormat = "unknown"
)

// detectCredentialFormat determines the credential format from the VP token.
// SD-JWT: contains ~ separators (disclosure markers) and JWT dots
// mDOC: base64url-encoded CBOR (doesn't look like JWT - no dots, or random data without ~)
func detectCredentialFormat(vpToken string) CredentialFormat {
	// SD-JWT format: <issuer-jwt>~<disclosure1>~<disclosure2>~...[~<kb-jwt>]
	// Must contain at least one ~ and the first part must look like a JWT (has 2 dots)
	if strings.Contains(vpToken, "~") {
		parts := strings.Split(vpToken, "~")
		if len(parts) > 0 && strings.Count(parts[0], ".") == 2 {
			return FormatSDJWT
		}
	}

	// Plain JWT without SD (still vc+sd-jwt format per spec, but no disclosures)
	if strings.Count(vpToken, ".") == 2 && !strings.Contains(vpToken, "~") {
		// Could be a plain JWT - check if it's valid base64url
		headerPart := strings.Split(vpToken, ".")[0]
		if _, err := base64.RawURLEncoding.DecodeString(headerPart); err == nil {
			return FormatSDJWT
		}
	}

	// mDOC: base64url-encoded CBOR DeviceResponse
	// Try to decode as base64url - if successful and doesn't look like JWT, assume mDOC
	if !strings.Contains(vpToken, ".") && !strings.Contains(vpToken, "~") {
		if _, err := base64.RawURLEncoding.DecodeString(vpToken); err == nil {
			return FormatMDoc
		}
		// Also try standard base64 (some implementations use this)
		if _, err := base64.StdEncoding.DecodeString(vpToken); err == nil {
			return FormatMDoc
		}
	}

	return FormatUnknown
}

// mapToDisclosers converts a map of claims to []sdjwtvc.Discloser format.
// This is used for mDOC credentials where claims are extracted as a map.
func mapToDisclosers(claims map[string]any) []sdjwtvc.Discloser {
	disclosers := make([]sdjwtvc.Discloser, 0, len(claims))
	for name, value := range claims {
		disclosers = append(disclosers, sdjwtvc.Discloser{
			ClaimName: name,
			Value:     value,
		})
	}
	return disclosers
}
