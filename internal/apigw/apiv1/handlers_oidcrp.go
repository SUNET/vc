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
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/grpchelpers"
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

	authReq, err := service.InitiateAuth(ctx, req.CredentialType)
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

	cc, err := c.newCallbackClaims(session.CredentialType, authResp.Claims, transformer)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// The authenticated claim set. It is deliberately NOT filtered against the
	// credential type: everything below that resolves an identity or looks up a
	// datastore document speaks a different vocabulary (see callbackClaims).
	// Credential content goes through cc.documentData() instead.
	claims := cc.identity

	// Log the authenticated claim set for diagnostics.
	claimKeys := make([]string, 0, len(claims))
	for k := range claims {
		claimKeys = append(claimKeys, k)
	}

	c.log.Info("OIDC authentication successful",
		"credential_type", session.CredentialType,
		"claims_count", len(claims),
		"claim_keys", claimKeys,
		"subject", authResp.IDToken.Subject)

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
			// Assertion: the authenticated claims are the credential's data,
			// so they are stored directly as a document.
			doc, docErr := c.buildOIDCDocument(cc, session.IssuerURL, true)
			if docErr != nil {
				span.SetStatus(codes.Error, "assertion document build failed")
				return nil, docErr
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
		SessionID:     preAuthCode,
		Code:          preAuthCode,
		Status:        "code_issued",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute).Unix(),
		Scopes:        []string{session.CredentialType},
		Nonce:         nonce,
		AuthProvider:  model.AuthProviderOIDC,
		Identifier:    identifier,
		PreAuthorized: true,
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
	//
	// Note that this happens for every data source, not only assertion: a
	// standalone-mode offer stores the callback claims as the document even for
	// a datastore scope, and never consults the datastore. That looks like a
	// separate defect, but it is exactly why the filtering has to apply here
	// too - whatever lands in DocumentData can end up signed into a credential.
	doc, docErr := c.buildOIDCDocument(cc, session.IssuerURL, credSourceErr == nil && credSource.DataSource == model.DataSourceAssertion)
	if docErr != nil {
		span.SetStatus(codes.Error, "document build failed")
		return nil, docErr
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

	// MakeSDJWT allocates a status list entry and embeds the reference in
	// the credential (see internal/issuer/apiv1/handlers.go). This function
	// does NOT record the resulting (status_list_uri, idx) -> subject
	// mapping the way the OpenID4VCI path does, so a credential issued here
	// would carry a status reference that nothing can ever set to INVALID -
	// worse than carrying none, because the reference invites reliance on
	// it, and it burns a slot besides.
	//
	// That is latent rather than live: this function has no callers. The
	// OIDC-RP callback stores documents and hands back a credential offer,
	// and issuance happens afterwards through the ordinary OpenID4VCI path,
	// which does record. It is dead on main too, so this PR does not delete
	// it.
	//
	// Whoever wires it up must call saveCredentialSubjects with the reply's
	// TokenStatusList* fields, and decide what identifier the entry is
	// recorded under - the OIDC-RP subject is not the authentic-source
	// person id issuance uses. See docs/REVOCATION.md.
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

// callbackClaims keeps the two claim vocabularies an OIDC callback produces
// apart. They used to share a single variable, which is issue #712: filtering
// for one of them filtered the other, and identity resolution was left with
// nothing to work with.
//
//   - Identity claims say who authenticated. They feed
//     LookupDatastoreByIdentity, whose claim names come from the operator's
//     auth_claims configuration, and ResolveVCIIdentifier/ResolveIdentifier,
//     which look for authentic_source_person_id or for family_name, given_name
//     and birth_date. Those names are chosen independently of the credential
//     type, so whether the credential type happens to declare them is a
//     coincidence: some do (vctm_pid, mdl.mdoc, pid_mdoc declare family_name,
//     given_name and birth_date), many declare none of them, and
//     authentic_source_person_id is declared by no shipped VCTM or MDDL at
//     all. Filtering this set against the credential type therefore removes
//     claims identity resolution needs.
//   - Document data is what the credential will say. It ends up in
//     CompleteDocument.DocumentData and is signed into the credential, so it
//     must carry only what the credential type declares (issue #623).
type callbackClaims struct {
	c              *Client
	credentialType string

	// identity is the authenticated claim set, run through the configured
	// attribute_mapping if there is one. It is never filtered.
	identity map[string]any

	// filter records whether documentData still has to drop undeclared claims.
	// It is false when a transformer produced the claims: the operator has then
	// already declared exactly which claims the credential gets, and filtering
	// that output on top would overrule their configuration.
	filter bool
}

// newCallbackClaims applies the configured claim transformer, if any, and
// records whether the resulting claims still need filtering before they may
// become credential content.
func (c *Client) newCallbackClaims(credentialType string, raw map[string]any, transformer *oidcrp.ClaimTransformer) (*callbackClaims, error) {
	cc := &callbackClaims{
		c:              c,
		credentialType: credentialType,
		identity:       raw,
		// No mapping configured, so the raw OIDC claims are also the
		// credential's claims and have to be filtered before use as such.
		filter: true,
	}

	if transformer != nil {
		c.log.Debug("OIDCRPCallback: transforming claims", "raw_claims_count", len(raw))
		transformed, err := transformer.TransformClaims(raw)
		if err != nil {
			return nil, err
		}
		cc.identity = transformed
		cc.filter = false
	}

	return cc, nil
}

// documentData returns the claims that may become credential content.
//
// This is the one place the "does this need filtering" decision is made. Every
// site that turns callback claims into a document goes through it, so a site
// added later is a visible call site rather than a silent omission.
//
// The result is always the caller's own to mutate: a caller merging assertion
// defaults into it must not reach the identity claims that identity resolution
// reads afterwards, or a default named sub or authentic_source_person_id would
// come back as an authenticated identifier. Filtering alone does not guarantee
// that - filterClaimsByCredentialType hands its input straight back when there
// is no metadata to filter against, and with a transformer configured there is
// no filtering at all.
func (cc *callbackClaims) documentData() map[string]any {
	claims := cc.identity
	if cc.filter {
		// Raw OIDC claims used to pass through verbatim, which put every
		// ID-token claim into the credential - including ones the credential
		// type never declares. Those can never be selectively disclosed, so a
		// wallet has to present them every time, and the standard ones (iss,
		// aud, exp, iat, nonce) collide with the envelope the issuer fills in
		// at signing.
		claims = cc.c.filterClaimsByCredentialType(cc.credentialType, cc.identity)
	}
	return cloneClaims(claims)
}

// cloneClaims copies the map and slice spine of a claim set, so that a caller
// mutating the copy cannot reach the original. A shallow copy is not enough:
// assertion defaults are dot-notation paths, and MergeDefaults walks into
// nested maps to set one, which would otherwise write straight into a nested
// map the identity claims still share.
//
// Leaf values are not copied. Nothing here replaces a leaf in place, so
// sharing them is safe and keeps this to the structure that is actually walked.
func cloneClaims(claims map[string]any) map[string]any {
	if claims == nil {
		return nil
	}
	out := make(map[string]any, len(claims))
	for name, value := range claims {
		out[name] = cloneClaimValue(value)
	}
	return out
}

func cloneClaimValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return cloneClaims(v)
	case []any:
		out := make([]any, len(v))
		for i, element := range v {
			out[i] = cloneClaimValue(element)
		}
		return out
	default:
		return value
	}
}

// buildOIDCDocument builds the document an OIDC callback stores for later
// issuance. Both the VCI and the standalone path build their document here, so
// that the document-data rule - and only it - applies to both.
//
// mergeAssertionDefaults injects the scope's configured assertion defaults;
// callers pass true only for assertion-sourced issuance, where the
// authentication assertion itself is the credential's data.
func (c *Client) buildOIDCDocument(cc *callbackClaims, authenticSource string, mergeAssertionDefaults bool) (*model.CompleteDocument, error) {
	documentData := cc.documentData()

	if mergeAssertionDefaults {
		defaults, err := c.cfg.APIGW.DataSources.Assertion.Scopes[cc.credentialType].ResolveDefaults(time.Now())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve assertion defaults: %w", err)
		}
		if err := credential.MergeDefaults(documentData, defaults); err != nil {
			return nil, fmt.Errorf("failed to merge assertion defaults: %w", err)
		}
	}

	return &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: authenticSource,
		},
		DocumentData: documentData,
	}, nil
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
