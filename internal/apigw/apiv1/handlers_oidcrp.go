package apiv1

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/SUNET/vc/internal/apigw/auth_providers/oidcrp"
	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/grpchelpers"
	"github.com/SUNET/vc/pkg/issuance"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
)

// OIDCRPInitiateRequest represents the request to initiate OIDC authentication
type OIDCRPInitiateRequest struct {
	CredentialType string `json:"credential_type" binding:"required"`
}

// OIDCRPInitiateResponse represents the response with authorization URL
type OIDCRPInitiateResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// OIDCRPCallbackRequest represents the OIDC callback parameters
type OIDCRPCallbackRequest struct {
	Code  string `json:"code" binding:"required"`
	State string `json:"state" binding:"required"`
}

// OIDCRPCallbackResponse represents the credential issuance response
type OIDCRPCallbackResponse struct {
	Status          string                            `json:"status"`
	CredentialType  string                            `json:"credential_type"`
	Credential      string                            `json:"credential,omitempty"`
	CredentialOffer *openid4vci.CredentialOfferResult `json:"credential_offer,omitempty"`
	Message         string                            `json:"message"`

	// VCIRedirectURL is set when the callback is part of a VCI consent flow.
	// The httpserver should redirect the browser to this URL instead of returning JSON.
	VCIRedirectURL string `json:"vci_redirect_url,omitempty"`
}

// OIDCRPInitiate initiates OIDC authentication flow
//
//	@Summary		Initiate OIDC Authentication
//	@ID				oidcrp-initiate
//	@Description	Initiates OIDC authentication by generating an OAuth2 authorization URL with PKCE
//	@Tags			OIDCRP
//	@Accept			json
//	@Produce		json
//	@Param			request	body		OIDCRPInitiateRequest	true	"OIDC RP initiate request"
//	@Success		200		{object}	OIDCRPInitiateResponse
//	@Failure		400		{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/oidcrp/initiate [post]
func (c *Client) OIDCRPInitiate(ctx context.Context, req *OIDCRPInitiateRequest, oidcrpService any) (*OIDCRPInitiateResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:OIDCRPInitiate")
	defer span.End()

	c.log.Debug("OIDCRPInitiate", "credential_type", req.CredentialType)

	service, ok := oidcrpService.(*oidcrp.Service)
	if !ok || service == nil {
		return nil, fmt.Errorf("OIDC RP service not available")
	}

	// Look up per-scope OIDC request params
	var oidcParams *model.OIDCRequestParams
	if scopeCfg := c.cfg.APIGW.DataSources.LookupScopePolicyConfig(req.CredentialType); scopeCfg != nil {
		oidcParams = scopeCfg.OIDCRequestParams
	}

	authReq, err := service.InitiateAuth(ctx, req.CredentialType, oidcParams, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply := &OIDCRPInitiateResponse{
		AuthorizationURL: authReq.AuthorizationURL,
		State:            authReq.State,
	}

	return reply, nil
}

// OIDCRPCallback processes OIDC callback and issues credential
//
//	@Summary		OIDC Provider Callback
//	@ID				oidcrp-callback
//	@Description	Receives and processes the authorization code from the OIDC Provider
//	@Tags			OIDCRP
//	@Accept			json
//	@Produce		json
//	@Param			code	query		string	true	"Authorization code"
//	@Param			state	query		string	true	"OAuth2 state parameter"
//	@Success		200		{object}	OIDCRPCallbackResponse
//	@Failure		400		{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/oidcrp/callback [get]
func (c *Client) OIDCRPCallback(ctx context.Context, req *OIDCRPCallbackRequest, oidcrpService any) (*OIDCRPCallbackResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:OIDCRPCallback")
	defer span.End()

	c.log.Debug("OIDCRPCallback", "state", req.State)

	service, ok := oidcrpService.(*oidcrp.Service)
	if !ok || service == nil {
		return nil, fmt.Errorf("OIDC RP service not available")
	}

	c.log.Debug("OIDCRPCallback: processing callback via OIDC RP service")
	// Process the callback via OIDC RP service
	authResp, err := service.ProcessCallback(ctx, req.Code, req.State)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Fetch UserInfo claims and merge with ID token claims (OIDC Core §5.3.2).
	// Many providers return only minimal claims in the ID token; the richer
	// identity attributes are available only via the UserInfo endpoint.
	if authResp.AccessToken != "" {
		userInfoClaims, userInfoErr := service.GetUserInfo(ctx, authResp.AccessToken)
		if userInfoErr != nil {
			c.log.Warn("failed to fetch UserInfo, proceeding with ID token claims only", "error", userInfoErr)
		} else {
			// Verify sub consistency (OIDC Core §5.3.2: MUST be the same)
			if uiSub, ok := userInfoClaims["sub"].(string); ok {
				if idSub, ok := authResp.Claims["sub"].(string); ok && uiSub != idSub {
					return nil, fmt.Errorf("UserInfo sub %q does not match ID token sub %q", uiSub, idSub)
				}
			}
			// Merge: UserInfo claims take precedence per OIDC Core §5.3.2
			maps.Copy(authResp.Claims, userInfoClaims)
		}
	}

	// Retrieve session to get credential type.
	// ProcessCallback already validated the session, but we need it for credential type etc.
	session, err := service.GetSession(ctx, req.State)
	if err != nil {
		span.SetStatus(codes.Error, "session retrieval failed")
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	// Ensure session is cleaned up if any subsequent step fails
	defer func() {
		if err != nil {
			service.DeleteSession(ctx, req.State)
		}
	}()

	// Build transformer from config (nil means passthrough — OIDC claims already use standard names)
	c.log.Debug("OIDCRPCallback: building claim transformer", "credential_type", session.CredentialType)
	transformer := service.BuildTransformer()

	var claims map[string]any
	if transformer != nil {
		c.log.Debug("OIDCRPCallback: transforming claims", "raw_claims_count", len(authResp.Claims))
		// Transform OIDC claims to credential claims
		claims, err = transformer.TransformClaims(authResp.Claims)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	} else {
		// No mapping configured. Raw OIDC claims used to pass through
		// verbatim, which put every ID-token claim into the credential -
		// including ones the credential type never declares. Those can
		// never be selectively disclosed, so a wallet has to present them
		// every time, and the standard ones (iss, aud, exp, iat, nonce)
		// collide with the envelope the issuer fills in at signing.
		claims = c.filterClaimsByCredentialType(session.CredentialType, authResp.Claims)
	}

	// Log the resulting document data for diagnostics.
	claimKeys := make([]string, 0, len(claims))
	for k := range claims {
		claimKeys = append(claimKeys, k)
	}

	c.log.Info("OIDC authentication successful",
		"credential_type", session.CredentialType,
		"claims_count", len(claims),
		"claim_keys", claimKeys,
		"subject", authResp.IDToken.Subject)

	// Evaluate issuance policy (if configured for this scope).
	// This uses SPOCP rules to gate credential issuance on claim values.
	// The raw OIDC claims (pre-transformation) are used for policy evaluation
	// since the rules reference OIDC claim names, not mapped credential claim names.
	if scopeCfg := c.cfg.APIGW.DataSources.LookupScopePolicyConfig(session.CredentialType); scopeCfg != nil && scopeCfg.IssuancePolicy != nil {
		policyEngine, policyErr := issuance.GetPolicyEngine(scopeCfg.IssuancePolicy)
		if policyErr != nil {
			span.SetStatus(codes.Error, policyErr.Error())
			return nil, fmt.Errorf("failed to initialize issuance policy engine: %w", policyErr)
		}
		if policyEngine != nil {
			// Evaluate against the OIDC-provider-asserted claims only. Do NOT
			// fall back to session.DynamicParams here: those are supplied by
			// the caller in the PAR request body (nominally "from the
			// authentic source business system", but nothing here verifies
			// that), not validated by the OP. Letting them silently satisfy a
			// missing OIDC claim would let a caller forge any policy
			// dimension the OP didn't actually assert, defeating the point of
			// gating issuance on the returned token. DynamicParams are still
			// used (legitimately) to template the outgoing OIDC request
			// parameters in resolveOIDCRequestParams - this is a separate,
			// later use of the same data for a security decision.
			policyClaims := maps.Clone(authResp.Claims)
			if policyErr := policyEngine.Evaluate(session.CredentialType, policyClaims, scopeCfg.IssuancePolicy.QueryTemplate); policyErr != nil {
				c.log.Warn("Issuance policy denied credential",
					"credential_type", session.CredentialType,
					"subject", authResp.IDToken.Subject,
					"error", policyErr)
				span.SetStatus(codes.Error, policyErr.Error())
				return nil, fmt.Errorf("credential issuance denied: %w", policyErr)
			}
			c.log.Info("Issuance policy evaluation passed",
				"credential_type", session.CredentialType,
				"subject", authResp.IDToken.Subject)
		}
	}

	// VCI mode: if the OIDC session was initiated from the OpenID4VCI consent flow,
	// store the transformed claims as a document in the VCI session cache and signal
	// the httpserver to redirect back to the consent page.
	if session.VCISessionID != "" {
		c.log.Debug("OIDCRPCallback: VCI mode",
			"vci_session_id", session.VCISessionID,
			"credential_type", session.CredentialType)

		// Check if this credential's data source is external_api — if so,
		// we only need the person identifier from the ID token, not the full claims.
		authCtx, lookupErr := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{SessionID: session.VCISessionID})
		if lookupErr != nil {
			span.SetStatus(codes.Error, "auth context lookup failed")
			return nil, fmt.Errorf("failed to get auth context for VCI session %s: %w", session.VCISessionID, lookupErr)
		}

		if authCtx.DataSource == string(model.DataSourceExternalAPI) {
			// External API: identifier will be resolved by the common
			// ResolveIdentifier call below (authentic_source_person_id or identity mapping).
		} else if authCtx.DataSource == string(model.DataSourceDatastore) {
			// Datastore: use the authenticated identity to look up pre-loaded documents.
			dsCred := c.cfg.APIGW.DataSources.Datastore.Scopes[session.CredentialType]
			if err := c.LookupDatastoreByIdentity(ctx, session.VCISessionID, session.CredentialType, authCtx.AuthenticSource, claims, &dsCred); err != nil {
				span.SetStatus(codes.Error, "datastore lookup failed")
				return nil, fmt.Errorf("OIDC datastore lookup failed: %w", err)
			}
		} else {
			// Assertion: store the transformed claims directly as a document
			doc := &model.CompleteDocument{
				Meta: &model.MetaData{
					AuthenticSource: session.IssuerURL,
				},
				DocumentData: claims,
			}
			docs := map[string]*model.CompleteDocument{
				session.IssuerURL: doc,
			}

			if err := c.StoreVCIDocuments(ctx, session.VCISessionID, docs); err != nil {
				span.SetStatus(codes.Error, "VCI document storage failed")
				return nil, fmt.Errorf("failed to store VCI documents: %w", err)
			}
		}

		// Resolve the authenticated identifier for registry (applies to all flows).
		if authCtx.Identifier == "" {
			var resolveErr error
			// For assertion: pre-transform fallbacks are raw OIDC Claims["sub"] and IDToken.Subject.
			var fallbacks []string
			if v, ok := authResp.Claims["sub"].(string); ok && v != "" {
				fallbacks = append(fallbacks, v)
			}
			if authResp.IDToken != nil && authResp.IDToken.Subject != "" {
				fallbacks = append(fallbacks, authResp.IDToken.Subject)
			}
			authCtx.Identifier, resolveErr = c.ResolveVCIIdentifier(ctx, authCtx, claims, fallbacks...)
			if resolveErr != nil {
				span.SetStatus(codes.Error, "identifier resolution failed")
				return nil, fmt.Errorf("failed to resolve identifier for VCI session %s: %w", session.VCISessionID, resolveErr)
			}
		}
		if updateErr := c.cacheService.AuthContext.Update(ctx, authCtx); updateErr != nil {
			span.SetStatus(codes.Error, "failed to store identifier")
			return nil, fmt.Errorf("failed to update identifier on auth context: %w", updateErr)
		}
		c.log.Info("OIDC callback: identifier resolved",
			"vci_session_id", session.VCISessionID, "identifier", authCtx.Identifier)

		// Clean up OIDC session (clear err so defer doesn't double-delete)
		err = nil
		service.DeleteSession(ctx, req.State)

		reply := &OIDCRPCallbackResponse{
			Status:         "success",
			CredentialType: session.CredentialType,
			VCIRedirectURL: "/authorization/consent/#/credentials",
			Message:        "OIDC authentication successful, continuing VCI flow",
		}

		return reply, nil
	}

	// Standalone mode: generate a credential offer with a pre-authorized code.
	// The actual credential is created later when the wallet redeems the offer
	// via the token + credential endpoints (which provide the wallet's JWK).

	// Generate credential offer for wallet
	credentialOffer, err := openid4vci.NewCredentialOffer(c.cfg.APIGW.Delivery.CredentialOffers.IssuerURL, session.CredentialType, openid4vci.GrantTypePreAuthorizedCode)
	if err != nil {
		span.SetStatus(codes.Error, "credential offer generation failed")
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	// Persist the pre-authorized code in the auth context cache so the wallet
	// can redeem the credential offer via the token endpoint.
	preAuthCode := credentialOffer.ID
	nonce, nonceErr := crypto.GenerateSecureToken(0, 32)
	if nonceErr != nil {
		span.SetStatus(codes.Error, "nonce generation failed")
		return nil, fmt.Errorf("failed to generate nonce: %w", nonceErr)
	}

	identifier, resolveErr := c.ResolveIdentifier(ctx, session.IssuerURL, claims)
	if resolveErr != nil {
		c.log.Debug("standalone OIDC: could not resolve identifier", "error", resolveErr)
	}

	// Resolve the data source for this credential type so that the credential
	// endpoint knows whether the identity is assertion-based (and can skip
	// the identifier requirement).
	credSource, credSourceErr := c.cfg.APIGW.DataSources.ResolveDataSource(session.CredentialType, string(model.AuthProviderOIDC))
	if credSourceErr != nil {
		c.log.Debug("standalone OIDC: could not resolve data source", "error", credSourceErr)
	}

	// Fail fast if we have neither an identifier nor a resolved data source —
	// a credential offer created without either cannot be redeemed.
	if identifier == "" && credSourceErr != nil {
		span.SetStatus(codes.Error, "cannot create credential offer without identifier or data source")
		return nil, fmt.Errorf("failed to resolve data source for credential type %q: %w (identifier error: %v)", session.CredentialType, credSourceErr, resolveErr)
	}

	// Fail fast if the data source requires an identifier but none was resolved.
	if identifier == "" && credSourceErr == nil && credSource.DataSource != model.DataSourceAssertion {
		span.SetStatus(codes.Error, "data source requires identifier but none was resolved")
		return nil, fmt.Errorf("data source %q for credential type %q requires an identifier", credSource.DataSource, session.CredentialType)
	}

	// AuthorizationDetails is intentionally left empty here, matching the same
	// decision already made in handlers_datastore.go's pre-auth code minting:
	// if set, the token endpoint reflects it back with credential_identifiers
	// added, which per OID4VCI spec then forces the wallet to use
	// credential_identifier (not credential_configuration_id) in the
	// credential request. Confirmed against the EUDI reference wallet's
	// pinned eudi-lib-jvm-openid4vci-kt (lpidproto PLAN.md workstream 7):
	// it doesn't build identifier-scoped credential requests, so it aborts
	// with zero issued documents when authorization_details is present.
	// Leaving it empty makes the wallet fall back to credential_configuration_id,
	// which both this library's CredentialRequest.Validate and
	// ResolveCredentialFormatWithAuthDetails already handle as the normal path.
	authCtx := &cache.AuthorizationContext{
		SessionID:    preAuthCode,
		Code:         preAuthCode,
		Status:       "code_issued",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		Scopes:       []string{session.CredentialType},
		Nonce:        nonce,
		AuthProvider: model.AuthProviderOIDC,
		Identifier:   identifier,
	}
	if credSourceErr == nil {
		authCtx.DataSource = string(credSource.DataSource)
	}
	if saveErr := c.cacheService.AuthContext.Save(ctx, authCtx); saveErr != nil {
		span.SetStatus(codes.Error, "pre-auth code persistence failed")
		return nil, fmt.Errorf("failed to store pre-auth code: %w", saveErr)
	}

	// Store document data so the credential endpoint can issue the credential
	// when the wallet redeems the offer.
	doc := &model.CompleteDocument{
		Meta:         &model.MetaData{AuthenticSource: session.IssuerURL},
		DocumentData: claims,
	}
	if err = c.StoreVCIDocuments(ctx, preAuthCode, map[string]*model.CompleteDocument{session.IssuerURL: doc}); err != nil {
		span.SetStatus(codes.Error, "failed to store VCI documents")
		return nil, fmt.Errorf("failed to store VCI documents: %w", err)
	}

	// Clean up session (clear err so defer doesn't double-delete)
	err = nil
	service.DeleteSession(ctx, req.State)

	c.log.Info("Credential offer created via OIDC RP standalone",
		"credential_type", session.CredentialType,
		"offer_id", credentialOffer.ID)

	if c.vciMetrics != nil {
		c.vciMetrics.OffersCreated.Add(ctx, 1, metric.WithAttributes(
			attribute.String("grant_type", "pre-authorized_code"),
			attribute.String("credential_config_id", session.CredentialType),
			attribute.String("source", "oidc_rp"),
		))
	}

	reply := &OIDCRPCallbackResponse{
		Status:          "success",
		CredentialType:  session.CredentialType,
		CredentialOffer: credentialOffer,
		Message:         "OIDC authentication successful, credential offer created",
	}

	return reply, nil
}

// createCredentialViaOIDCRP calls the issuer gRPC service to create a credential
func (c *Client) createCredentialViaOIDCRP(ctx context.Context, credentialType string, documentData []byte, jwk *apiv1_issuer.Jwk) (string, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:createCredentialViaOIDCRP")
	defer span.End()

	// Connect to issuer gRPC service
	conn, err := grpchelpers.NewClientConn(c.cfg.APIGW.IssuerClient)
	if err != nil {
		c.log.Error(err, "Failed to connect to issuer")
		return "", fmt.Errorf("failed to connect to issuer: %w", err)
	}
	defer conn.Close()

	client := apiv1_issuer.NewIssuerServiceClient(conn)

	credMeta := c.cfg.GetCredentialMetadata(credentialType)
	if credMeta == nil {
		return "", fmt.Errorf("unsupported credential type: %s", credentialType)
	}

	// Call the issuer's MakeSDJWT method
	reply, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        credentialType,
		DocumentData: documentData,
		Jwk:          jwk,
		Integrity:    credMeta.GetIntegrity(),
		Vctm:         credMeta.GetVCTMRaw(),
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeSDJWT")
		return "", fmt.Errorf("failed to create credential: %w", err)
	}

	if reply == nil || len(reply.Credentials) == 0 {
		return "", fmt.Errorf("no credential data returned")
	}

	return reply.Credentials[0].Credential, nil
}

// filterClaimsByCredentialType drops claims the credential type does not
// declare, so an assertion-sourced credential carries only what its VCTM or
// MDDL describes.
//
// It is deliberately conservative about not having metadata: when no VCTM or
// MDDL is loaded for the scope there is nothing to filter against, and
// silently emptying the credential would be worse than the over-sharing this
// exists to prevent, so the claims pass through unchanged and the reason is
// logged.
func (c *Client) filterClaimsByCredentialType(credentialType string, claims map[string]any) map[string]any {
	if len(claims) == 0 {
		return claims
	}

	metadata := c.cfg.Common.CredentialMetadata[credentialType]
	if metadata == nil {
		c.log.Warn("assertion claims not filtered: no credential metadata configured for scope",
			"credential_type", credentialType, "claim_count", len(claims))
		return claims
	}

	allowed, loaded := metadata.DeclaredClaimNames()
	if !loaded {
		c.log.Warn("assertion claims not filtered: neither VCTM nor MDDL loaded for scope",
			"credential_type", credentialType, "claim_count", len(claims))
		return claims
	}

	filtered := make(map[string]any, len(claims))
	dropped := make([]string, 0)
	for name, value := range claims {
		if allowed[name] {
			filtered[name] = value
			continue
		}
		dropped = append(dropped, name)
	}

	if len(dropped) > 0 {
		// Named rather than counted: this changes what a credential
		// contains, and an operator upgrading into it should be able to see
		// exactly which claims stopped being issued rather than infer it
		// from missing data.
		sort.Strings(dropped)
		c.log.Info("assertion claims dropped: not declared by the credential type",
			"credential_type", credentialType, "dropped", dropped, "kept", len(filtered))
	}

	return filtered
}
