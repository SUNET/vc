package apiv1

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/google/uuid"
)

// OAuthPar implements OAuth 2.0 Pushed Authorization Request (PAR)
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-endpoint
//
//	@Summary		Pushed Authorization Request
//	@ID				oauth-par
//	@Description	Handle OAuth2 Pushed Authorization Request (PAR)
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		openid4vci.PARRequest	true	"PAR request"
//	@Success		201		{object}	openid4vci.ParResponse	"Created"
//	@Failure		400		{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/op/par [post]
func (c *Client) OAuthPar(ctx context.Context, req *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	c.log.Debug("OAuthPar", "client_id", req.ClientID, "scope", req.Scope)

	// Statically-configured clients already have their redirect_uri checked
	// against a registered allowlist by Clients.Allow below. Wallet-attestation
	// authenticated clients (the fallback branch further down) have no such
	// allowlist -- attestation proves the wallet's identity, not that its
	// requested redirect_uri is safe -- so without this, an attacker-supplied
	// scheme like "javascript:" or "data:" would be stored as WalletURI and
	// later rendered as a trusted URL on the consent page (endpoints_oauth.go
	// wraps it in template.URL(...) to preserve custom wallet schemes, which
	// also disables html/template's own scheme sanitization). Checking this
	// unconditionally, before either path, closes the gap for both.
	if err := oauth2.ValidateRedirectURIScheme(req.RedirectURI); err != nil {
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest, "invalid redirect_uri", 400, err)
	}

	oauthClient, err := c.cfg.APIGW.Delivery.OpenID4VCI.Clients.Allow(req.ClientID, req.RedirectURI, req.Scope)
	if err != nil {
		// Client not in static map — try wallet attestation via PDP.
		// Standard-compliant: HTTP headers per draft-ietf-oauth-attestation-based-client-auth-04 §3.1
		// Legacy fallback: form body client_assertion (PoP not required)
		attestation := req.ClientAttestation
		popJWT := req.ClientAttestationPoP
		if attestation == "" {
			// Legacy form-body mode — PoP not required
			attestation = req.ClientAssertion
			popJWT = ""
		} else if popJWT == "" {
			// Header mode MUST include PoP (§3.1)
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidClient,
				"OAuth-Client-Attestation-PoP header required when OAuth-Client-Attestation is present", 401)
		}
		if c.walletAttestationEvaluator != nil && attestation != "" {
			result, evalErr := c.walletAttestationEvaluator.EvaluateWithPoP(ctx, attestation, popJWT, c.cfg.APIGW.PublicURL)
			if evalErr != nil {
				c.log.Debug("OAuthPar wallet attestation failed", "client_id", req.ClientID, "error", evalErr)
				return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient, "client validation failed", 401, evalErr)
			}
			if result.Subject != "" && result.Subject != req.ClientID {
				return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidClient,
					"wallet attestation subject does not match client_id", 401)
			}
			// SPOCP tier authorization: check if this attestation tier may request this scope
			if !c.walletAttestationPolicy.Authorize(result.AttestationSource, req.Scope, result.Issuer) {
				c.log.Info("PAR: wallet attestation tier denied by policy",
					"client_id", req.ClientID, "attestation_source", result.AttestationSource,
					"scope", req.Scope, "issuer", result.Issuer)
				return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidScope,
					"attestation tier not authorized for requested scope", 403)
			}
			c.log.Info("PAR: wallet authenticated via attestation",
				"client_id", req.ClientID, "wallet_provider", result.Issuer,
				"attestation_source", result.AttestationSource,
				"trust_framework", result.TrustFramework)
			oauthClient = &oauth2.Client{
				Type:         oauth2.ClientTypePublic,
				RedirectURIs: oauth2.RedirectURIs{req.RedirectURI},
				Scopes:       []string{"*"},
			}
		} else {
			c.log.Debug("OAuthPar client validation failed", "client_id", req.ClientID, "error", err)
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient, "client validation failed", 401, err)
		}
	}

	// Public clients MUST use PKCE (RFC 6749 Section 2.1)
	if oauthClient.Type == oauth2.ClientTypePublic && req.CodeChallenge == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest, "code_challenge is required for public clients", 400)
	}

	c.log.Debug("par")

	requestURI := fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", uuid.NewString())

	c.log.Debug("PAR", "state", req.State)

	host, err := helpers.HostFromURL(c.cfg.APIGW.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
	}

	azt := cache.AuthorizationContext{
		SessionID:            uuid.NewString(),
		Code:                 uuid.NewString(),
		RequestURI:           requestURI,
		Scopes:               []string{req.Scope},
		AuthorizationDetails: req.AuthorizationDetails,
		Forfeited:            false,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		State:                req.State,
		ClientID:             fmt.Sprintf("x509_san_dns:%s", host),
		WalletClientID:       req.ClientID,
		WalletURI:            req.RedirectURI,
		ExpiresAt:            time.Now().Add(60 * time.Second).Unix(),
	}

	azt.Nonce, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	azt.EphemeralEncryptionKeyID, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	azt.VerifierResponseCode, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate response code: %w", err)
	}

	if err := c.cacheService.AuthContext.Save(ctx, &azt); err != nil {
		return nil, err
	}

	reply := &openid4vci.ParResponse{
		RequestURI: requestURI,
		ExpiresIn:  60,
	}

	return reply, nil
}

// OAuthAuthorize handles the OAuth2 authorization endpoint
//
//	@Summary		OAuth2 Authorize
//	@ID				oauth-authorize
//	@Description	Handle OAuth2 authorization request and redirect to consent
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Param			request_uri	query	string	true	"PAR request URI"
//	@Success		302			"Redirect to consent"
//	@Failure		400			{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/authorize [get]
func (c *Client) OAuthAuthorize(ctx context.Context, req *openid4vci.AuthorizeRequest) (*openid4vci.AuthorizationResponse, error) {
	c.log.Debug("Authorize", "req", req)
	host, err := helpers.HostFromURL(c.cfg.APIGW.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
	}

	query := &cache.AuthorizationContext{
		RequestURI: req.RequestURI,
		ClientID:   fmt.Sprintf("x509_san_dns:%s", host),
	}
	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, query)
	c.log.Debug("Get authorization", "query", query, "authorization", authorizationContext)
	if err != nil {
		c.log.Error(err, "get error")
		return nil, err
	}
	c.log.Debug("Authorization", "state", authorizationContext.State)

	if authorizationContext.ExpiresAt > 0 && time.Now().Unix() > authorizationContext.ExpiresAt {
		c.log.Debug("Authorization context expired")
		return nil, oauth2.ErrExpiredRequest
	}

	if authorizationContext.Forfeited {
		c.log.Debug("Authorization already used")
		return nil, errors.New("not allowed")
	}

	var redirectURL string
	if !authorizationContext.Consent {
		redirectURL = "/authorization/consent"
	}

	reply := &openid4vci.AuthorizationResponse{
		RedirectURL:    redirectURL,
		Scope:          authorizationContext.Scopes[0],
		SessionID:      authorizationContext.SessionID,
		ClientID:       authorizationContext.ClientID,
		WalletClientID: authorizationContext.WalletClientID,
	}

	c.log.Debug("Authorize", "authorization", authorizationContext)

	return reply, nil
}

// OAuthToken implements OAuth 2.0 token endpoint for credential issuance
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint
//
//	@Summary		OAuth2 Token
//	@ID				oauth-token
//	@Description	Exchange authorization code for tokens
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		openid4vci.TokenRequest		true	"Token request"
//	@Success		200		{object}	openid4vci.TokenResponse	"Success"
//	@Failure		400		{object}	helpers.ErrorResponse		"Bad Request"
//	@Router			/token [post]
func (c *Client) OAuthToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	start := time.Now()
	c.log.Debug("OAuthToken", "grant_type", req.GrantType)

	// Handle refresh_token grant type separately — it has a different flow
	// that doesn't involve authorization codes.
	if req.GrantType == "refresh_token" {
		return c.handleRefreshTokenGrant(ctx, start, req)
	}

	isPreAuthFlow := req.GrantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code"

	// Resolve the code to look up based on grant type.
	// Field presence is enforced by required_if validation tags on TokenRequest.
	code := req.Code
	if isPreAuthFlow {
		code = req.PreAuthorizedCode
	}

	// When client_assertion is provided (private_key_jwt auth), verify the assertion
	// signature per RFC 7523 and extract client_id from the sub claim.
	clientID := req.ClientID
	if req.ClientAssertion != "" {
		if req.ClientAssertionType == "" {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
				"client_assertion_type is required when client_assertion is provided", 400)
		}
		if req.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
				fmt.Sprintf("unsupported client_assertion_type %q; expected urn:ietf:params:oauth:client-assertion-type:jwt-bearer", req.ClientAssertionType), 400)
		}

		if c.cfg.APIGW.Delivery.OpenID4VCI.AllowUnverifiedClientAssertion {
			// CONFORMANCE TESTING ONLY: accept assertion without signature verification.
			c.log.Warn("accepting unverified client_assertion (allow_unverified_client_assertion is enabled)",
				"client_assertion_type", req.ClientAssertionType)
			sub, err := oauth2.ExtractClientIDFromAssertion(req.ClientAssertion)
			if err != nil {
				c.log.Error(err, "failed to extract client_id from client_assertion")
				return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient,
					"Invalid client assertion", 401, err)
			}
			if clientID != "" && clientID != sub {
				return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidClient,
					"client_id does not match assertion subject", 401)
			}
			clientID = sub
		} else {
			// RFC 7523 full verification path: extract sub for client lookup, then verify signature.
			sub, err := oauth2.ExtractClientIDFromAssertion(req.ClientAssertion)
			if err != nil {
				c.log.Error(err, "failed to extract client_id from client_assertion")
				return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient,
					"Invalid client assertion", 401, err)
			}
			if clientID != "" && clientID != sub {
				return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidClient,
					"client_id does not match assertion subject", 401)
			}
			clientID = sub

			// Look up client to get JWKS URI for signature verification
			oauthClientForVerify, err := c.cfg.APIGW.Delivery.OpenID4VCI.Clients.Get(clientID)
			if err != nil {
				// Client not in static map. If wallet attestation is configured,
				// this client_assertion might actually be a WIA (legacy form-body mode).
				// Don't fail here — let the wallet attestation block below handle it.
				if c.walletAttestationEvaluator != nil {
					c.log.Debug("client not in static map, deferring to wallet attestation",
						"client_id", clientID)
				} else {
					return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient,
						"Client authentication failed", 401, err)
				}
			} else {
				verifier := &oauth2.ClientAssertionVerifier{
					TokenEndpoint: c.cfg.APIGW.Delivery.OpenID4VCI.TokenEndpoint,
					JWKSCache:     c.cacheService.JWKS,
					JTICheck: func(jti string, exp time.Time) error {
						// Scope by clientID to prevent cross-client collisions;
						// use time.Until(exp) as TTL so entries expire with the assertion.
						cacheKey := "client_assertion:" + clientID + ":" + jti
						// Add the same leeway as the JWT verifier to tolerate small clock skews.
						ttl := time.Until(exp.Add(30 * time.Second))
						if ttl <= 0 {
							return errors.New("client_assertion jti has already expired")
						}
						unique, err := c.cacheService.DPopJTI.SetNXWithTTL(ctx, cacheKey, true, ttl)
						if err != nil {
							return fmt.Errorf("jti cache error: %w", err)
						}
						if !unique {
							return errors.New("client_assertion jti already used")
						}
						return nil
					},
				}
				assertionClaims, err := verifier.Verify(ctx, req.ClientAssertion, oauthClientForVerify)
				if err != nil {
					c.log.Error(err, "client_assertion verification failed", "client_id", clientID)
					return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient,
						"Client assertion verification failed", 401, err)
				}
				c.log.Debug("client_assertion verified", "client_id", clientID, "jti", assertionClaims.JTI)
			}
		}
	} else if req.ClientAssertionType != "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"client_assertion_type provided without client_assertion", 400)
	}

	c.log.Debug("OAuthToken", "client_id", clientID, "grant_type", req.GrantType)

	// authorization_code flow requires client identification via client_id or client_assertion (RFC 6749 §4.1.3).
	if !isPreAuthFlow && clientID == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"authorization_code grant requires client_id or client_assertion", 400)
	}

	var oauthClient *oauth2.Client
	if clientID != "" {
		var err error
		oauthClient, err = c.cfg.APIGW.Delivery.OpenID4VCI.Clients.Get(clientID)
		if err != nil {
			// Client not in static map — try wallet attestation via PDP.
			// Standard-compliant: HTTP headers per draft-ietf-oauth-attestation-based-client-auth-04 §3.1
			// Legacy fallback: form body client_assertion (PoP not required)
			attestation := req.ClientAttestation
			popJWT := req.ClientAttestationPoP
			if attestation == "" {
				// Legacy form-body mode — PoP not required
				attestation = req.ClientAssertion
				popJWT = ""
			} else if popJWT == "" {
				// Header mode MUST include PoP (§3.1)
				return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidClient,
					"OAuth-Client-Attestation-PoP header required when OAuth-Client-Attestation is present", 401)
			}
			if c.walletAttestationEvaluator != nil && attestation != "" {
				result, evalErr := c.walletAttestationEvaluator.EvaluateWithPoP(ctx, attestation, popJWT, c.cfg.APIGW.PublicURL)
				if evalErr != nil {
					c.log.Error(evalErr, "wallet attestation failed", "client_id", clientID)
					return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient,
						"Client authentication failed", 401, evalErr)
				}
				if result.Subject != "" && result.Subject != clientID {
					return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidClient,
						"wallet attestation subject does not match client_id", 401)
				}
				// SPOCP tier authorization (nil engine = default open).
				// Re-check against the scope actually bound to this code (not the
				// caller-supplied request), since the code is what was authorized
				// at PAR/offer time. A wildcard here would let a code obtained for
				// a low tier be redeemed as if it were "*"-authorized, and pre-auth
				// codes never go through PAR at all, so a blanket wildcard is wrong.
				codeCtx, codeErr := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{Code: code})
				if codeErr != nil {
					return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidGrant,
						"Authorization code is invalid or has already been used", 400, codeErr)
				}
				codeScope := strings.Join(codeCtx.Scopes, " ")
				if !c.walletAttestationPolicy.Authorize(result.AttestationSource, codeScope, result.Issuer) {
					c.log.Info("Token: wallet attestation tier denied by policy",
						"client_id", clientID, "attestation_source", result.AttestationSource,
						"issuer", result.Issuer)
					return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidScope,
						"attestation tier not authorized for requested scope", 403)
				}
				c.log.Info("Token: wallet authenticated via attestation",
					"client_id", clientID, "wallet_provider", result.Issuer,
					"attestation_source", result.AttestationSource,
					"trust_framework", result.TrustFramework)
				oauthClient = &oauth2.Client{
					Type:         oauth2.ClientTypePublic,
					RedirectURIs: oauth2.RedirectURIs{req.RedirectURI},
					Scopes:       []string{"*"},
				}
			} else {
				c.log.Error(err, "client validation failed")
				return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient,
					"Client authentication failed", 401, err)
			}
		}
	}

	// Public clients (wallets) MUST use PKCE per RFC 6749 Section 2.1 — but only for authorization_code grant
	if !isPreAuthFlow && oauthClient != nil && oauthClient.Type == oauth2.ClientTypePublic && req.CodeVerifier == "" {
		return nil, oauth2.OAuthErrPKCERequired
	}

	// Validate DPoP BEFORE consuming the authorization code (RFC 9449 §4).
	// This ensures a stolen code cannot be consumed without a valid DPoP proof.
	var dpopThumbprint string
	if req.DPOP != "" {
		dpop, dpopErr := oauth2.ValidateAndParseDPoPJWT(req.DPOP)
		if dpopErr != nil {
			c.log.Error(dpopErr, "dpop validation error")
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidDPoPProof,
				dpopErr.Error(), 400, dpopErr)
		}

		dpopThumbprint = dpop.Thumbprint

		unique, err := c.cacheService.DPopJTI.SetNX(ctx, dpop.JTI, true)
		if err != nil {
			c.log.Error(err, "DPoP JTI cache error", "jti", dpop.JTI)
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
				"internal error checking DPoP JTI", 500, err)
		}
		if !unique {
			c.log.Error(nil, "DPoP JTI replay detected", "jti", dpop.JTI)
			return nil, oauth2.OAuthErrJTIReplay
		}

		// Validate HTU matches token endpoint
		if dpop.HTU != c.cfg.APIGW.Delivery.OpenID4VCI.TokenEndpoint {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidDPoPProof,
				fmt.Sprintf("invalid htu: expected %s, got %s", c.cfg.APIGW.Delivery.OpenID4VCI.TokenEndpoint, dpop.HTU), 400)
		}

		// Validate HTM is POST (token endpoint only accepts POST)
		if dpop.HTM != "POST" {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidDPoPProof,
				fmt.Sprintf("invalid htm: expected POST, got %s", dpop.HTM), 400)
		}

		c.log.Debug("DPoP claims", "jti", dpop.JTI, "htu", dpop.HTU, "htm", dpop.HTM)
	} else if !isPreAuthFlow {
		return nil, oauth2.OAuthErrDPoPRequired
	}
	// NOTE: For pre-authorized_code flow, DPoP is optional per OID4VCI §4.1.1.
	// When DPoP is absent, dpopThumbprint remains empty. The credential endpoint
	// (verifyDPoPKeyBinding) skips key-binding verification when the stored
	// thumbprint is empty — see handlers_issuer.go verifyDPoPKeyBinding().
	// Security: the one-time pre-authorized code and (optionally) tx_code provide
	// the primary security mechanism for this flow.
	// TODO: Consider requiring DPoP for pre-auth flow to achieve sender-constrained
	// tokens across all flows (RFC 9449).

	// Verify client_id and redirect_uri BEFORE consuming the authorization code
	// (RFC 6749 §4.1.3). A mismatched client_id must not burn the code, otherwise
	// an attacker with a stolen code could invalidate it for the legitimate client.
	if !isPreAuthFlow {
		preCheck, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{Code: code})
		if err != nil {
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidGrant,
				"Authorization code is invalid or has already been used", 400, err)
		}
		if preCheck.WalletClientID != "" && clientID != preCheck.WalletClientID {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
				"client_id does not match the authorization request", 400)
		}
		if preCheck.WalletURI != "" && req.RedirectURI != preCheck.WalletURI {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
				"redirect_uri does not match the authorization request", 400)
		}
	}

	// Now consume the authorization code (after DPoP and client binding are validated)
	var authorizationContext *cache.AuthorizationContext
	var err error
	if isPreAuthFlow && dpopThumbprint != "" {
		// Pre-authorized codes with DPoP can be redeemed by multiple distinct
		// clients (each identified by a unique DPoP key). This supports the
		// OID4VCI happy-flow-multiple-clients scenario where one credential
		// offer serves multiple wallets.
		authorizationContext, err = c.cacheService.AuthContext.RedeemPreAuthorizedCode(ctx, code, dpopThumbprint)
	} else {
		// Without DPoP, pre-authorized codes are single-use (standard forfeit).
		authorizationContext, err = c.cacheService.AuthContext.ForfeitAuthorizationCode(ctx, &cache.AuthorizationContext{
			Code: code,
		})
	}
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidGrant,
			"Authorization code is invalid or has already been used", 400, err)
	}
	c.log.Debug("Token", "state", authorizationContext.State)

	if authorizationContext.ExpiresAt > 0 && time.Now().Unix() > authorizationContext.ExpiresAt {
		c.log.Debug("Authorization context expired")
		return nil, oauth2.OAuthErrExpiredRequest
	}

	// Verify PKCE code_challenge (skip for pre-authorized code flow)
	if !isPreAuthFlow {
		if err := oauth2.ValidatePKCE(req.CodeVerifier, authorizationContext.CodeChallenge, authorizationContext.CodeChallengeMethod); err != nil {
			c.log.Error(err, "PKCE validation failed")
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidGrant,
				"PKCE validation failed", 400, err)
		}
		c.log.Debug("PKCE validation successful")
	}

	// generating a new access token
	accessToken, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	c.log.Debug("Generated access token", "access_token", accessToken)

	// Bind the public key to the generated access token

	reply := &openid4vci.TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "DPoP",
		ExpiresIn:       3600, // 1 hour
		Scope:           authorizationContext.Scopes[0],
		State:           authorizationContext.State,
		CNonce:          authorizationContext.Nonce,
		CNonceExpiresIn: 3600,
	}

	// Issue a refresh token if the grant type is configured and DPoP is present.
	// Refresh tokens are device-bound (ARF 3.0 §6.6.6.2.2) and require a DPoP
	// thumbprint for sender-constraining. Without DPoP (e.g. pre-auth flow without
	// DPoP), no refresh token is issued to avoid creating bearer refresh tokens.
	var refreshToken string
	if slices.Contains(c.cfg.APIGW.Delivery.OpenID4VCI.GrantTypes, "refresh_token") && dpopThumbprint != "" {
		refreshToken, err = crypto.GenerateSecureToken(0, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to generate refresh token: %w", err)
		}
		reply.RefreshToken = refreshToken
		reply.RefreshTokenExpiresIn = c.cfg.APIGW.Delivery.OpenID4VCI.RefreshTokenDuration
	}

	// Store the c_nonce in the nonce cache so proof verification can find it.
	// For pre-auth flow, this is deferred to child session creation below
	// (each client gets its own nonce).
	if !isPreAuthFlow && c.cacheService.VCINonce != nil {
		c.cacheService.VCINonce.Set(ctx, authorizationContext.Nonce, true)
	}

	// Per OID4VCI 1.0 Section 6.2: authorization_details is REQUIRED in the Token Response when
	// authorization_details was used in the Authorization Request, with credential_identifiers added.
	var responseDetails []openid4vci.AuthorizationDetailsParameter
	if len(authorizationContext.AuthorizationDetails) > 0 {
		responseDetails = make([]openid4vci.AuthorizationDetailsParameter, len(authorizationContext.AuthorizationDetails))
		for i, ad := range authorizationContext.AuthorizationDetails {
			responseDetails[i] = ad
			responseDetails[i].CredentialIdentifiers = []string{uuid.NewString()}
		}
		reply.AuthorizationDetails = responseDetails
		// Do not mutate the shared parent authorizationContext here. The
		// credential_identifiers are persisted per flow below: the pre-auth flow
		// stores them on the independent child session, and the authorization_code
		// flow assigns them before its Update() call. Mutating the parent here
		// would persist implicitly in MemoryStore (shared pointer) but not in
		// MongoStore (no Update), causing HA/non-HA inconsistency and unnecessary
		// overwrites of the shared context across pre-auth clients.
	}

	tokenDoc := &cache.Token{
		AccessToken:    accessToken,
		ExpiresAt:      time.Now().Add(time.Duration(reply.ExpiresIn) * time.Second).Unix(),
		DPoPThumbprint: dpopThumbprint,
	}

	if isPreAuthFlow {
		// Pre-auth flow: create an independent child session for this client.
		// The shared auth context remains intact so other clients can also redeem.
		childSessionID, genErr := crypto.GenerateSecureToken(0, 32)
		if genErr != nil {
			return nil, fmt.Errorf("failed to generate child session ID: %w", genErr)
		}
		// Generate a fresh c_nonce for this child session so each client gets its
		// own nonce. The parent's nonce is shared and would be consumed (GetAndDelete)
		// by the first client to call /credential, breaking subsequent clients.
		childNonce, nonceErr := crypto.GenerateSecureToken(0, 32)
		if nonceErr != nil {
			return nil, fmt.Errorf("failed to generate child c_nonce: %w", nonceErr)
		}
		if c.cacheService.VCINonce != nil {
			c.cacheService.VCINonce.Set(ctx, childNonce, true)
		}
		reply.CNonce = childNonce

		childSession := &cache.AuthorizationContext{
			SessionID:             childSessionID,
			SourceSessionID:      authorizationContext.SessionID,
			Status:               cache.SessionStatusTokenIssued,
			CreatedAt:            time.Now(),
			ExpiresAt:            tokenDoc.ExpiresAt, // Use token TTL, not parent code TTL
			Scopes:               authorizationContext.Scopes,
			Nonce:                childNonce,
			AuthorizationDetails: responseDetails, // Use details with credential_identifiers from token response
			AuthProvider:         authorizationContext.AuthProvider,
			Identifier:           authorizationContext.Identifier,
			DataSource:           authorizationContext.DataSource,
			Token:                tokenDoc,
			RefreshToken:         refreshToken,
		}
		if refreshToken != "" {
			childSession.RefreshTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.APIGW.Delivery.OpenID4VCI.RefreshTokenDuration) * time.Second).Unix()
		}
		if err := c.cacheService.AuthContext.Save(ctx, childSession); err != nil {
			c.log.Error(err, "failed to save child session for pre-auth client")
			return nil, err
		}
	} else {
		// Set the token on the in-memory struct so that Update() persists it
		// alongside any updated AuthorizationDetails (credential_identifiers).
		// Using Update() instead of AddToken() avoids a race where AddToken
		// writes the token and a subsequent Update() overwrites it with nil.
		authorizationContext.Token = tokenDoc
		authorizationContext.RefreshToken = refreshToken
		if refreshToken != "" {
			authorizationContext.RefreshTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.APIGW.Delivery.OpenID4VCI.RefreshTokenDuration) * time.Second).Unix()
		}
		if len(responseDetails) > 0 {
			authorizationContext.AuthorizationDetails = responseDetails
		}
		if err := c.cacheService.AuthContext.Update(ctx, authorizationContext); err != nil {
			c.log.Error(err, "failed to persist token and authorization details")
			return nil, err
		}
	}

	c.log.Debug("OAuthToken complete")

	if c.vciMetrics != nil {
		grantTypeAttr := metric.WithAttributes(attribute.String("grant_type", req.GrantType))
		c.vciMetrics.TokensIssued.Add(ctx, 1, grantTypeAttr)
		c.vciMetrics.TokenLatency.Record(ctx, time.Since(start).Seconds(), grantTypeAttr)
	}

	return reply, nil
}

// OAuthMetadata returns the OAuth2 authorization server metadata
//
//	@Summary		OAuth2 Server Metadata
//	@ID				oauth-metadata
//	@Description	Returns the OAuth2 authorization server metadata (RFC 8414)
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	oauth2.AuthorizationServerMetadata	"Success"
//	@Router			/.well-known/oauth-authorization-server [get]
func (c *Client) OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error) {
	// Shallow-copy to avoid mutating the shared struct concurrently.
	metadata := *c.oauth2Metadata

	// Use cached signed metadata (refreshed by background ticker every 55 min).
	// signed_metadata is OPTIONAL per RFC 8414 — if signing fails
	// (issuer unreachable, not configured, etc.) return unsigned metadata.
	signedMetadata, err := c.getOrSignMetadata(ctx, signedMetadataKeyOAuth2, c.oauth2Metadata, "oauth2-authorization-server", c.oauth2Metadata.Issuer)
	if err != nil {
		c.log.Error(err, "signed_metadata unavailable, serving unsigned metadata")
		metadata.SignedMetadata = ""
	} else {
		metadata.SignedMetadata = signedMetadata
	}

	if err := helpers.Check(ctx, c.cfg, &metadata, c.log); err != nil {
		c.log.Error(err, "metadata check error")
		return nil, err
	}

	return &metadata, nil
}

// JWKSResponse represents a JSON Web Key Set (RFC 7517 §5).
type JWKSResponse = apiv1_issuer.Keys

// JWKS returns the issuer's public signing keys as a JWK Set.
// The keys are fetched from the issuer via gRPC and stripped of any private
// key material before being served.
//
//	@Summary		JWKS
//	@ID				jwks
//	@Description	Returns the JSON Web Key Set for signature verification
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	JWKSResponse	"Success"
//	@Router			/jwks [get]
func (c *Client) JWKS(ctx context.Context) (*JWKSResponse, error) {
	c.log.Debug("JWKS request")

	issuerReply, err := c.issuerClient.JWKS(ctx, &apiv1_issuer.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from issuer: %w", err)
	}

	reply := issuerReply.GetJwks()
	if reply == nil {
		reply = &apiv1_issuer.Keys{}
	}

	// Strip private key material — only public keys are served
	for _, key := range reply.GetKeys() {
		key.D = ""
		key.KeyOps = nil
		key.Ext = false
	}

	return reply, nil
}

// SDJWTVCIssuerMetadataResponse represents JWT VC Issuer Metadata per SD-JWT VC §5.3.
type SDJWTVCIssuerMetadataResponse struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// SDJWTVCIssuerMetadata returns the JWT VC Issuer Metadata per draft-ietf-oauth-sd-jwt-vc §5.3.
// This metadata is served at /.well-known/jwt-vc-issuer and allows verifiers to discover
// the issuer's JWKS endpoint.
//
//	@Summary		SD-JWT VC Issuer Metadata
//	@ID				sdjwtvc-issuer-metadata
//	@Description	Returns the SD-JWT VC issuer metadata
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	SDJWTVCIssuerMetadataResponse	"Success"
//	@Router			/.well-known/jwt-vc-issuer [get]
func (c *Client) SDJWTVCIssuerMetadata(ctx context.Context) (*SDJWTVCIssuerMetadataResponse, error) {
	c.log.Debug("sd-jwt-vc issuer metadata request")

	reply := &SDJWTVCIssuerMetadataResponse{
		Issuer:  c.cfg.APIGW.PublicURL,
		JWKSURI: c.cfg.APIGW.PublicURL + "/jwks",
	}

	return reply, nil
}

type OauthAuthorizationConsentRequest struct {
	// AuthMethod string `json:"-"`
	SessionID string `json:"-"`
}

type OAuthAuthorizationConsentResponse struct {
	RedirectURL       string
	VerifierContextID string `json:"-"`
}

// OAuthAuthorizationConsent handles the authorization consent flow
//
//	@Summary		Authorization Consent
//	@ID				oauth-authorization-consent
//	@Description	Handles the authorization consent flow for credential issuance
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	OAuthAuthorizationConsentResponse	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse				"Bad Request"
//	@Router			/authorization/consent [get]
func (c *Client) OAuthAuthorizationConsent(ctx context.Context, req *OauthAuthorizationConsentRequest) (*OAuthAuthorizationConsentResponse, error) {
	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{SessionID: req.SessionID})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}
	c.log.Debug("Authorization/consent", "state", authorizationContext.State)

	c.log.Debug("OAuthAuthorizationConsent request")

	verifierRequestURI, err := url.JoinPath(c.cfg.APIGW.PublicURL, "/verification/request-object")
	if err != nil {
		c.log.Error(err, "failed to construct request URI URL")
		return nil, err
	}
	requestURL, err := url.Parse(verifierRequestURI)
	if err != nil {
		c.log.Error(err, "failed to parse request URI URL")
		return nil, err
	}

	requestURI := url.Values{
		"id": []string{authorizationContext.VerifierResponseCode},
	}

	requestURL.RawQuery = requestURI.Encode()
	finalRequestURI := requestURL.String()

	walletURL, err := url.Parse(authorizationContext.WalletURI)
	if err != nil {
		c.log.Error(err, "failed to parse wallet URL")
		return nil, err
	}
	values := url.Values{
		"client_id":   []string{authorizationContext.ClientID},
		"request_uri": []string{finalRequestURI},
	}

	walletURL.RawQuery = values.Encode()

	reply := &OAuthAuthorizationConsentResponse{
		RedirectURL:       walletURL.String(),
		VerifierContextID: authorizationContext.VerifierResponseCode,
	}

	c.log.Debug("OAuthAuthorizationConsent response", "redirectURL", reply.RedirectURL)

	return reply, nil
}

type OauthAuthorizationConsentCallbackRequest struct {
	ResponseCode string `json:"response_code" form:"response_code" uri:"response_code"`
}

type OAuthAuthorizationConsentCallbackResponse struct {
	// RedirectURL string `json:"-"`
}

// OAuthAuthorizationConsentCallback handles the consent callback
//
//	@Summary		Authorization Consent Callback
//	@ID				oauth-authorization-consent-callback
//	@Description	Handles the callback after user consents to credential issuance
//	@Tags			OAuth
//	@Produce		json
//	@Success		302	"Redirect"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/authorization/consent/callback [get]
func (c *Client) OAuthAuthorizationConsentCallback(ctx context.Context, req *OauthAuthorizationConsentCallbackRequest) (*OAuthAuthorizationConsentCallbackResponse, error) {
	c.log.Debug("OAuthAuthorizationConsentCallback request", "req", req)
	reply := &OAuthAuthorizationConsentCallbackResponse{}

	return reply, nil
}

// handleRefreshTokenGrant handles the refresh_token grant type per RFC 6749 §6.
// It validates the refresh token, verifies DPoP binding, rotates the refresh token,
// and issues a new access token so the Wallet can request fresh credentials.
func (c *Client) handleRefreshTokenGrant(ctx context.Context, start time.Time, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	c.log.Debug("handleRefreshTokenGrant")

	if req.RefreshToken == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"refresh_token parameter is required for refresh_token grant", 400)
	}

	if !slices.Contains(c.cfg.APIGW.Delivery.OpenID4VCI.GrantTypes, "refresh_token") {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeUnsupportedGrantType,
			"refresh_token grant is not enabled", 400)
	}

	// Validate DPoP proof
	dpop, err := oauth2.ValidateAndParseDPoPJWT(req.DPOP)
	if err != nil {
		c.log.Error(err, "failed to validate DPoP JWT for refresh")
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidDPoPProof,
			err.Error(), 400, err)
	}

	// Validate HTU matches token endpoint
	if dpop.HTU != c.cfg.APIGW.Delivery.OpenID4VCI.TokenEndpoint {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidDPoPProof,
			fmt.Sprintf("invalid htu: expected %s, got %s", c.cfg.APIGW.Delivery.OpenID4VCI.TokenEndpoint, dpop.HTU), 400)
	}

	// Validate HTM is POST (token endpoint only accepts POST)
	if dpop.HTM != "POST" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidDPoPProof,
			fmt.Sprintf("invalid htm: expected POST, got %s", dpop.HTM), 400)
	}

	unique, err := c.cacheService.DPopJTI.SetNX(ctx, dpop.JTI, true)
	if err != nil {
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
			"internal error checking DPoP proof", 500, err)
	}
	if !unique {
		return nil, oauth2.OAuthErrJTIReplay
	}

	// Look up the session by refresh token
	authContext, err := c.cacheService.AuthContext.GetByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		c.log.Error(err, "invalid or expired refresh token")
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
			"invalid or expired refresh token", 400)
	}

	// Verify refresh token has not expired
	if authContext.RefreshTokenExpiresAt > 0 && time.Now().Unix() > authContext.RefreshTokenExpiresAt {
		c.log.Error(nil, "refresh token expired", "expires_at", authContext.RefreshTokenExpiresAt)
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
			"refresh token has expired", 400)
	}

	// Verify DPoP key binding: refresh tokens are sender-constrained and must be
	// bound to the DPoP key used at initial token issuance (ARF 3.0 §6.6.6.2.2).
	// If the stored session is missing the DPoP binding, the refresh token was
	// issued without sender-constraining and must be rejected.
	if authContext.Token == nil || authContext.Token.DPoPThumbprint == "" {
		c.log.Error(nil, "refresh token has no DPoP binding", "session_id", authContext.SessionID)
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
			"refresh token is not bound to a DPoP key", 400)
	}
	if dpop.Thumbprint != authContext.Token.DPoPThumbprint {
		c.log.Error(nil, "DPoP key mismatch on refresh",
			"expected", authContext.Token.DPoPThumbprint,
			"got", dpop.Thumbprint)
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
			"DPoP key does not match the key used at initial token issuance", 400)
	}

	// Generate new access token
	newAccessToken, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Rotate refresh token (one-time use per RFC 6749 §6 recommendation)
	newRefreshToken, err := crypto.GenerateSecureToken(0, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Generate new c_nonce for proof-of-possession in subsequent credential requests
	newNonce, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate c_nonce: %w", err)
	}

	// Store the new nonce
	if c.cacheService.VCINonce != nil {
		c.cacheService.VCINonce.Set(ctx, newNonce, true)
	}

	// Update the session with new tokens atomically. RotateRefreshToken uses a
	// compare-and-swap on the old refresh token value, so a concurrent request
	// using the same token will fail with ErrNoDocuments (→ invalid_grant).
	// Work on a copy to avoid mutating the shared pointer from MemoryStore's cache,
	// which would corrupt the compare-and-swap check.
	oldRefreshToken := authContext.RefreshToken
	rotated := *authContext
	rotated.Token = &cache.Token{
		AccessToken:    newAccessToken,
		ExpiresAt:      time.Now().Add(3600 * time.Second).Unix(),
		DPoPThumbprint: dpop.Thumbprint,
	}
	rotated.RefreshToken = newRefreshToken
	rotated.RefreshTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.APIGW.Delivery.OpenID4VCI.RefreshTokenDuration) * time.Second).Unix()
	rotated.Nonce = newNonce

	if err := c.cacheService.AuthContext.RotateRefreshToken(ctx, oldRefreshToken, &rotated); err != nil {
		if errors.Is(err, cache.ErrNoDocuments) {
			c.log.Error(nil, "refresh token already consumed (concurrent use)", "session_id", authContext.SessionID)
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
				"refresh token has already been used", 400)
		}
		c.log.Error(err, "failed to rotate refresh token")
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
			"internal error during token rotation", 500, err)
	}

	reply := &openid4vci.TokenResponse{
		AccessToken:           newAccessToken,
		TokenType:             "DPoP",
		ExpiresIn:             3600,
		Scope:                 authContext.Scopes[0],
		CNonce:                newNonce,
		CNonceExpiresIn:       3600,
		RefreshToken:          newRefreshToken,
		RefreshTokenExpiresIn: c.cfg.APIGW.Delivery.OpenID4VCI.RefreshTokenDuration,
		AuthorizationDetails:  authContext.AuthorizationDetails,
	}

	if c.vciMetrics != nil {
		grantTypeAttr := metric.WithAttributes(attribute.String("grant_type", "refresh_token"))
		c.vciMetrics.TokensIssued.Add(ctx, 1, grantTypeAttr)
		c.vciMetrics.TokenLatency.Record(ctx, time.Since(start).Seconds(), grantTypeAttr)
	}

	c.log.Debug("refresh token grant complete", "session_id", authContext.SessionID)
	return reply, nil
}


