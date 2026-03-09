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
	"vc/pkg/cache"
	"vc/pkg/jose"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwtvc"
	"vc/pkg/trust"

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
	header := strings.Split(v.Response, ".")[0]
	b, err := base64.RawStdEncoding.DecodeString(header)
	if err != nil {
		return "", err
	}

	var headerMap map[string]any
	if err := json.Unmarshal(b, &headerMap); err != nil {
		return "", err
	}

	kid, ok := headerMap["kid"]
	if !ok {
		return "", errors.New("kid not found in JWT header")
	}

	kidStr, ok := kid.(string)
	if !ok {
		return "", errors.New("kid is not a string")
	}

	return kidStr, nil
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

		// Validate VP Token using VPTokenValidator
		validator := &openid4vp.VPTokenValidator{
			Nonce:           authCtx.Nonce,
			ClientID:        authCtx.ClientID,
			VerifySignature: true,
			CheckRevocation: false,
		}

		if err := validator.Validate(responseParams.VPToken); err != nil {
			c.log.Error(err, "VP Token validation failed", "scope", scope)
			return nil, fmt.Errorf("VP Token validation failed for scope %s: %w", scope, err)
		}

		c.log.Debug("VP Token validated successfully", "scope", scope)

		// Evaluate trust using AuthZEN PDP if configured
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

// evaluateIssuerTrust verifies the credential signature and evaluates the trust of the credential issuer.
// For SD-JWT credentials with x5c header, it extracts the certificate chain, verifies the signature,
// and evaluates trust against the AuthZEN PDP. For credentials with jwk header, it uses the embedded JWK.
// If neither x5c nor jwk header is present but the issuer is a DID, it attempts to resolve
// the key via go-trust's DID resolution. Signature verification happens before trust evaluation.
func (c *Client) evaluateIssuerTrust(ctx context.Context, vpToken string, scope string) error {
	// Check that trust evaluator is configured
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

	// Parse JWT header to check for key material
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(issuerJWT, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}

	// Extract issuer identifier and credential type from claims
	issuerID := ""
	credentialType := ""
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if iss, ok := claims["iss"].(string); ok {
			issuerID = iss
		}
		if vct, ok := claims["vct"].(string); ok {
			credentialType = vct
		}
	}

	// Determine key type and extract key material from header
	var keyType trust.KeyType
	var keyMaterial any
	var publicKey crypto.PublicKey

	if x5cRaw, ok := token.Header["x5c"]; ok {
		// x5c header - certificate chain
		certChain, err := jose.ParseX5CHeader(x5cRaw)
		if err != nil {
			return fmt.Errorf("failed to parse x5c header: %w", err)
		}
		keyType = trust.KeyTypeX5C
		keyMaterial = certChain
		publicKey = certChain[0].PublicKey // Use leaf certificate's public key

		// Fallback to leaf certificate CN for issuer ID
		if issuerID == "" && len(certChain) > 0 {
			issuerID = certChain[0].Subject.CommonName
		}

		c.log.Debug("Verifying credential signature via x5c",
			"scope", scope,
			"issuer_id", issuerID,
			"credential_type", credentialType,
			"cert_chain_length", len(certChain))
	} else if jwkRaw, ok := token.Header["jwk"]; ok {
		// jwk header - embedded JWK
		jwkMap, ok := jwkRaw.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid jwk header format: expected map, got %T", jwkRaw)
		}
		keyType = trust.KeyTypeJWK
		keyMaterial = jwkMap

		// Parse JWK to get public key for signature verification
		publicKey, err = jose.ParseJWKToPublicKey(jwkMap)
		if err != nil {
			return fmt.Errorf("failed to parse jwk header: %w", err)
		}

		c.log.Debug("Verifying credential signature via jwk",
			"scope", scope,
			"issuer_id", issuerID,
			"credential_type", credentialType)
	} else if strings.HasPrefix(issuerID, "did:") {
		// No x5c or jwk header, but issuer is a DID - try to resolve key via go-trust
		resolver, ok := c.trustEvaluator.(trust.KeyResolver)
		if !ok {
			c.log.Warn("Issuer is DID but trust evaluator does not support key resolution",
				"scope", scope,
				"issuer_id", issuerID)
			return fmt.Errorf("cannot resolve DID issuer key: trust evaluator does not support key resolution")
		}

		c.log.Debug("Resolving issuer key via DID",
			"scope", scope,
			"issuer_id", issuerID,
			"credential_type", credentialType)

		resolvedKey, err := resolver.ResolveKey(ctx, issuerID)
		if err != nil {
			c.log.Warn("Failed to resolve DID issuer key",
				"scope", scope,
				"issuer_id", issuerID,
				"error", err)
			return fmt.Errorf("failed to resolve DID issuer key: %w", err)
		}

		keyType = trust.KeyTypeJWK
		keyMaterial = resolvedKey
		publicKey = resolvedKey

		c.log.Debug("Verifying credential signature via resolved DID key",
			"scope", scope,
			"issuer_id", issuerID,
			"credential_type", credentialType)
	} else {
		// No x5c, jwk, or DID - credential lacks key material for trust evaluation
		c.log.Warn("Credential missing x5c or jwk header and issuer is not a DID - cannot evaluate issuer trust",
			"scope", scope,
			"issuer_id", issuerID)
		return fmt.Errorf("credential missing x5c or jwk header and issuer is not a DID")
	}

	// CRITICAL: Verify the JWT signature using the extracted public key
	allowedAlgs := c.cfg.Verifier.Trust.AllowedSignatureAlgorithms
	if err := verifyJWTSignature(issuerJWT, publicKey, allowedAlgs); err != nil {
		c.log.Warn("JWT signature verification failed",
			"scope", scope,
			"issuer_id", issuerID,
			"error", err)
		return fmt.Errorf("JWT signature verification failed: %w", err)
	}

	c.log.Debug("JWT signature verified successfully",
		"scope", scope,
		"issuer_id", issuerID)

	// Evaluate trust via AuthZEN PDP
	decision, err := c.trustEvaluator.Evaluate(ctx, &trust.EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID:      issuerID,
			KeyType:        keyType,
			Key:            keyMaterial,
			Role:           trust.RoleCredentialIssuer,
			CredentialType: credentialType,
		},
	})
	if err != nil {
		return fmt.Errorf("trust evaluation error: %w", err)
	}

	if !decision.Trusted {
		c.log.Warn("Issuer not trusted",
			"scope", scope,
			"issuer_id", issuerID,
			"key_type", keyType,
			"reason", decision.Reason,
			"trust_framework", decision.TrustFramework)
		return fmt.Errorf("issuer not trusted: %s", decision.Reason)
	}

	c.log.Info("Issuer trust verified",
		"scope", scope,
		"issuer_id", issuerID,
		"key_type", keyType,
		"trust_framework", decision.TrustFramework)

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

// verifyJWTSignature verifies the JWT signature using the provided public key.
// allowedAlgorithms restricts which algorithms are accepted. If empty, defaults to defaultAllowedAlgorithms.
// The "none" algorithm is NEVER allowed regardless of configuration.
func verifyJWTSignature(jwtString string, publicKey crypto.PublicKey, allowedAlgorithms []string) error {
	// Use defaults if no algorithms specified
	if len(allowedAlgorithms) == 0 {
		allowedAlgorithms = defaultAllowedAlgorithms
	}

	// Build a set for O(1) lookup
	allowedSet := make(map[string]bool, len(allowedAlgorithms))
	for _, alg := range allowedAlgorithms {
		allowedSet[alg] = true
	}

	// SECURITY: "none" algorithm is NEVER allowed, even if misconfigured
	delete(allowedSet, "none")
	delete(allowedSet, "None")
	delete(allowedSet, "NONE")

	// Parse and verify the JWT with the extracted public key
	_, err := jwt.Parse(jwtString, func(token *jwt.Token) (any, error) {
		alg := token.Method.Alg()

		// Check algorithm whitelist
		if !allowedSet[alg] {
			return nil, fmt.Errorf("algorithm %q is not in the allowed list", alg)
		}

		// Validate the signing method matches the key type
		switch publicKey.(type) {
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %v for ECDSA key", alg)
			}
		case *rsa.PublicKey:
			// RSA can use RS* or PS* algorithms
			_, isRS := token.Method.(*jwt.SigningMethodRSA)
			_, isPS := token.Method.(*jwt.SigningMethodRSAPSS)
			if !isRS && !isPS {
				return nil, fmt.Errorf("unexpected signing method %v for RSA key", alg)
			}
		case ed25519.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method %v for Ed25519 key", alg)
			}
		default:
			return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
		}
		return publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
