package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/grpchelpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointSAMLMetadata returns the SAML Service Provider metadata XML
//
//	@Summary		Get SAML SP Metadata
//	@Description	Returns the SAML Service Provider metadata XML for IdP configuration
//	@Tags			SAML
//	@Produce		xml
//	@Success		200	{string}	string			"SAML metadata XML"
//	@Failure		500	{object}	map[string]any	"Internal server error"
//	@Router			/saml/metadata [get]
func (s *Service) endpointSAMLMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSAMLMetadata")
	defer span.End()

	if s.authProviders.SAML() == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	metadata, err := s.authProviders.SAML().GetSPMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Return raw XML with proper content type
	c.Header("Content-Type", "application/samlmetadata+xml")
	c.String(http.StatusOK, metadata)
	return nil, nil
}

// SAMLInitiateRequest represents the request to initiate SAML authentication
type SAMLInitiateRequest struct {
	IDPEntityID    string `json:"idp_entity_id" binding:"required"`
	CredentialType string `json:"credential_type" binding:"required"`
}

// SAMLInitiateResponse represents the response with redirect URL
type SAMLInitiateResponse struct {
	RedirectURL string `json:"redirect_url"`
	RequestID   string `json:"request_id"`
}

// endpointSAMLInitiate initiates SAML authentication flow
//
//	@Summary		Initiate SAML Authentication
//	@Description	Initiates SAML authentication by creating an AuthnRequest and returning the IdP redirect URL
//	@Tags			SAML
//	@Accept			json
//	@Produce		json
//	@Param			request	body		SAMLInitiateRequest	true	"SAML initiate request"
//	@Success		200		{object}	SAMLInitiateResponse
//	@Failure		400		{object}	map[string]any	"Bad request"
//	@Failure		500		{object}	map[string]any	"Internal server error"
//	@Router			/saml/initiate [post]
func (s *Service) endpointSAMLInitiate(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSAMLInitiate")
	defer span.End()

	if s.authProviders.SAML() == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	var req SAMLInitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	authReq, err := s.authProviders.SAML().InitiateAuth(ctx, req.IDPEntityID, req.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &SAMLInitiateResponse{
		RedirectURL: authReq.RedirectURL,
		RequestID:   authReq.ID,
	}, nil
}

// endpointSAMLACS handles the SAML Assertion Consumer Service (ACS) endpoint
// This is where the IdP POSTs the SAML response after authentication
//
//	@Summary		SAML Assertion Consumer Service
//	@Description	Receives and processes SAML assertions from the IdP
//	@Tags			SAML
//	@Accept			application/x-www-form-urlencoded
//	@Produce		json
//	@Param			SAMLResponse	formData	string			true	"Base64-encoded SAML Response"
//	@Param			RelayState		formData	string			false	"Relay state from initial request"
//	@Success		200				{object}	map[string]any	"Success with credential claims or offer"
//	@Failure		400				{object}	map[string]any	"Bad request"
//	@Failure		500				{object}	map[string]any	"Internal server error"
//	@Router			/saml/acs [post]
func (s *Service) endpointSAMLACS(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSAMLACS")
	defer span.End()

	if s.authProviders.SAML() == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	// Extract SAML response from POST form data
	samlResponseB64 := c.PostForm("SAMLResponse")
	if samlResponseB64 == "" {
		span.SetStatus(codes.Error, "missing SAMLResponse")
		return nil, fmt.Errorf("SAMLResponse parameter is required")
	}

	relayState := c.PostForm("RelayState")

	// Pass the base64-encoded SAMLResponse directly to ProcessAssertion.
	// The crewjam/saml library handles base64 decoding internally.
	assertion, err := s.authProviders.SAML().ProcessAssertion(ctx, samlResponseB64, relayState)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Retrieve session to get credential type.
	// Ensure session is cleaned up if any subsequent step fails.
	session, err := s.authProviders.SAML().GetSession(ctx, relayState)
	if err != nil {
		span.SetStatus(codes.Error, "session retrieval failed")
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}
	defer func() {
		if err != nil {
			s.authProviders.SAML().DeleteSession(ctx, relayState)
		}
	}()

	// Build transformer from config
	transformer, err := s.authProviders.SAML().BuildTransformer()
	if err != nil {
		span.SetStatus(codes.Error, "transformer creation failed")
		return nil, fmt.Errorf("failed to create transformer: %w", err)
	}

	// Convert SAML attributes (map[string][]string) to map[string]any
	// Take the first value from each attribute array
	samlAttrs := make(map[string]any)
	for key, values := range assertion.Attributes {
		if len(values) > 1 {
			s.log.Warn("SAML attribute has multiple values, using first",
				"attribute", key, "count", len(values))
		}
		if len(values) > 0 {
			samlAttrs[key] = values[0] // Use first value
		}
	}

	// Transform SAML attributes to credential claims using the generic transformer
	claims, err := transformer.TransformClaims(samlAttrs)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	claimKeys := make([]string, 0, len(claims))
	for k := range claims {
		claimKeys = append(claimKeys, k)
	}
	s.log.Info("SAML authentication successful",
		"credential_type", session.CredentialType,
		"claims_count", len(claims),
		"claim_keys", claimKeys)

	// VCI mode: if the SAML session was initiated from the OpenID4VCI consent flow,
	// store the transformed claims as a document in the VCI session cache and redirect
	// back to the consent page, where the standard VCI pipeline will continue.
	if session.VCISessionID != "" {
		s.log.Info("SAML ACS: VCI mode detected",
			"vci_session_id", session.VCISessionID,
			"credential_type", session.CredentialType)

		// Check if this credential's data source is external_api — if so,
		// we only need the person identifier from the assertion, not the full claims.
		authCtx, lookupErr := s.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{SessionID: session.VCISessionID})
		if lookupErr != nil {
			span.SetStatus(codes.Error, "auth context lookup failed")
			return nil, fmt.Errorf("failed to get auth context for VCI session %s: %w", session.VCISessionID, lookupErr)
		}

		if authCtx.DataSource == string(model.DataSourceExternalAPI) {
			// External API: identifier will be resolved by the common
			// ResolveIdentifier call below (authentic_source_person_id or identity mapping).
		} else if authCtx.DataSource == string(model.DataSourceDatastore) {
			// Datastore: use the authenticated identity to look up pre-loaded documents.
			dsCred := s.cfg.APIGW.DataSources.Datastore.Scopes[session.CredentialType]
			if err := s.apiv1.LookupDatastoreByIdentity(ctx, session.VCISessionID, session.CredentialType, claims, &dsCred); err != nil {
				span.SetStatus(codes.Error, "datastore lookup failed")
				return nil, fmt.Errorf("SAML datastore lookup failed: %w", err)
			}
		} else {
			// Assertion: store the transformed claims directly as a document
			doc := &model.CompleteDocument{
				Meta: &model.MetaData{
					AuthenticSource: session.IDPEntityID,
				},
				DocumentData: claims,
			}
			docs := map[string]*model.CompleteDocument{
				session.IDPEntityID: doc,
			}

			if err := s.apiv1.StoreVCIDocuments(ctx, session.VCISessionID, docs); err != nil {
				span.SetStatus(codes.Error, "VCI document storage failed")
				return nil, fmt.Errorf("failed to store VCI documents: %w", err)
			}
		}

		// Resolve the authenticated identifier for registry (applies to all flows).
		if authCtx.Identifier == "" {
			var resolveErr error
			authCtx.Identifier, resolveErr = s.apiv1.ResolveIdentifier(ctx, authCtx.AuthenticSource, claims)
			if resolveErr != nil {
				span.SetStatus(codes.Error, "identifier resolution failed")
				return nil, fmt.Errorf("failed to resolve identifier for VCI session %s: %w", session.VCISessionID, resolveErr)
			}
		}
		if updateErr := s.cacheService.AuthContext.Update(ctx, authCtx); updateErr != nil {
			span.SetStatus(codes.Error, "failed to store identifier")
			return nil, fmt.Errorf("failed to update identifier on auth context: %w", updateErr)
		}
		s.log.Info("SAML ACS: identifier resolved",
			"vci_session_id", session.VCISessionID, "identifier", authCtx.Identifier)

		// Clean up SAML session (clear err so defer doesn't double-delete)
		err = nil
		s.authProviders.SAML().DeleteSession(ctx, relayState)

		// Redirect browser back to the consent page to continue the VCI flow
		c.Redirect(http.StatusFound, "/authorization/consent/#/credentials")
		return nil, nil
	}

	// Standalone mode: create credential directly via issuer gRPC
	// Marshal claims to JSON for the credential
	documentData, err := json.Marshal(claims)
	if err != nil {
		span.SetStatus(codes.Error, "document marshaling failed")
		return nil, fmt.Errorf("failed to marshal document: %w", err)
	}

	// Generate ephemeral JWK for credential binding if not provided
	// In a production scenario, the wallet would provide the JWK
	jwk := session.JWK
	if jwk == nil {
		span.SetStatus(codes.Error, "JWK required for standalone SAML credential binding")
		return nil, fmt.Errorf("wallet must provide a JWK for credential binding in standalone SAML mode")
	}

	// Create credential using the issuer gRPC API
	credential, err := s.createCredentialViaSAML(ctx, session.CredentialType, documentData, jwk)
	if err != nil {
		span.SetStatus(codes.Error, "credential creation failed")
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	// Generate credential offer for wallet
	credentialOffer, err := s.generateCredentialOffer(ctx, session.CredentialType, session.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, "credential offer generation failed")
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	// Clean up SAML session (clear err so defer doesn't double-delete)
	err = nil
	s.authProviders.SAML().DeleteSession(ctx, relayState)

	s.log.Info("Credential issued successfully",
		"credential_type", session.CredentialType,
		"offer_id", credentialOffer["id"])

	response := map[string]any{
		"status":           "success",
		"credential_type":  session.CredentialType,
		"credential":       credential,
		"credential_offer": credentialOffer,
		"message":          "SAML authentication and credential issuance successful",
	}

	return response, nil
}

// createCredentialViaSAML calls the issuer gRPC service to create a credential
// This follows the same pattern as other APIGW handlers that call the issuer
func (s *Service) createCredentialViaSAML(ctx context.Context, credentialType string, documentData []byte, jwk *apiv1_issuer.Jwk) (string, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:createCredentialViaSAML")
	defer span.End()

	// Connect to issuer gRPC service
	conn, err := grpchelpers.NewClientConn(s.cfg.APIGW.IssuerClient)
	if err != nil {
		s.log.Error(err, "Failed to connect to issuer")
		return "", fmt.Errorf("failed to connect to issuer: %w", err)
	}
	defer conn.Close()

	client := apiv1_issuer.NewIssuerServiceClient(conn)

	credMeta := s.cfg.GetCredentialMetadata(credentialType)
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
		s.log.Error(err, "failed to call MakeSDJWT")
		return "", fmt.Errorf("failed to create credential: %w", err)
	}

	if reply == nil || len(reply.Credentials) == 0 {
		return "", fmt.Errorf("no credential data returned")
	}

	// Return the first credential (assuming single credential response)
	return reply.Credentials[0].Credential, nil
}

// generateCredentialOffer creates an OpenID4VCI credential offer
func (s *Service) generateCredentialOffer(ctx context.Context, credentialType string, credentialConfigID string) (map[string]any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:generateCredentialOffer")
	defer span.End()

	// Build credential offer parameters
	// Generate pre-authorized code (fixed-length 32-character string)
	preAuthCode, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-auth code: %w", err)
	}

	params := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           s.cfg.APIGW.Delivery.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{credentialConfigID},
		Grants: map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": preAuthCode,
				"tx_code":             nil, // Optional transaction code
			},
		},
	}

	// Generate credential offer
	offer, err := params.CredentialOffer()
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	// Convert to map for response
	offerData := make(map[string]any)
	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential offer: %w", err)
	}

	if err := json.Unmarshal(offerJSON, &offerData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential offer: %w", err)
	}

	return offerData, nil
}
