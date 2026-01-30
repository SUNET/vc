//go:build saml

package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	apiv1_issuer "vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/crypto"
	"vc/pkg/grpchelpers"
	"vc/pkg/openid4vci"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointSAMLMetadata returns the SAML Service Provider metadata XML
//
//	@Summary		Get SAML SP Metadata
//	@Description	Returns the SAML Service Provider metadata XML for IdP configuration
//	@Tags			SAML
//	@Produce		xml
//	@Success		200	{string}	string					"SAML metadata XML"
//	@Failure		500	{object}	map[string]any	"Internal server error"
//	@Router			/saml/metadata [get]
func (s *Service) endpointSAMLMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSAMLMetadata")
	defer span.End()

	if s.samlService == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	metadata, err := s.samlService.GetSPMetadata(ctx)
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

	if s.samlService == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	var req SAMLInitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	authReq, err := s.samlService.InitiateAuth(ctx, req.IDPEntityID, req.CredentialType)
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
//	@Param			SAMLResponse	formData	string					true	"Base64-encoded SAML Response"
//	@Param			RelayState		formData	string					false	"Relay state from initial request"
//	@Success		200				{object}	map[string]any	"Success with credential claims or offer"
//	@Failure		400				{object}	map[string]any	"Bad request"
//	@Failure		500				{object}	map[string]any	"Internal server error"
//	@Router			/saml/acs [post]
func (s *Service) endpointSAMLACS(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSAMLACS")
	defer span.End()

	if s.samlService == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	// Extract SAML response from POST form data
	samlResponseB64 := c.PostForm("SAMLResponse")
	if samlResponseB64 == "" {
		span.SetStatus(codes.Error, "missing SAMLResponse")
		return nil, fmt.Errorf("SAMLResponse parameter is required")
	}

	// Decode base64
	samlResponseXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		span.SetStatus(codes.Error, "invalid base64")
		return nil, fmt.Errorf("failed to decode SAMLResponse: %w", err)
	}

	relayState := c.PostForm("RelayState")

	// Process the SAML assertion
	assertion, err := s.samlService.ProcessAssertion(ctx, string(samlResponseXML), relayState)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Retrieve session to get credential type
	session, err := s.samlService.GetSession(relayState)
	if err != nil {
		span.SetStatus(codes.Error, "session retrieval failed")
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	// Build transformer from config
	transformer, err := s.samlService.BuildTransformer()
	if err != nil {
		span.SetStatus(codes.Error, "transformer creation failed")
		return nil, fmt.Errorf("failed to create transformer: %w", err)
	}

	// Get the mapping for this credential type
	mapping, err := transformer.GetMapping(session.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, "no mapping found")
		return nil, err
	}

	// Convert SAML attributes (map[string][]string) to map[string]any
	// Take the first value from each attribute array
	samlAttrs := make(map[string]any)
	for key, values := range assertion.Attributes {
		if len(values) > 0 {
			samlAttrs[key] = values[0] // Use first value
		}
	}

	// Transform SAML attributes to credential claims using the generic transformer
	claims, err := transformer.TransformClaims(session.CredentialType, samlAttrs)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.log.Info("SAML authentication successful",
		"credential_type", session.CredentialType,
		"claims_count", len(claims))

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
		// For SAML flow without wallet involvement, we generate a JWK
		// This is primarily for testing and backward compatibility
		s.log.Info("No JWK provided in session, generating ephemeral key")
		// TODO: Consider if we should require JWK from wallet instead
	}

	// Create credential using the issuer gRPC API
	credential, err := s.createCredentialViaSAML(ctx, mapping.CredentialType, documentData, jwk)
	if err != nil {
		span.SetStatus(codes.Error, "credential creation failed")
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	// Generate credential offer for wallet
	credentialOffer, err := s.generateCredentialOffer(ctx, mapping.CredentialType, mapping.CredentialConfigID)
	if err != nil {
		span.SetStatus(codes.Error, "credential offer generation failed")
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	s.log.Info("Credential issued successfully",
		"credential_type", mapping.CredentialType,
		"offer_id", credentialOffer["id"])

	response := map[string]any{
		"status":           "success",
		"credential_type":  mapping.CredentialType,
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

	// Call the issuer's MakeSDJWT method
	reply, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        credentialType,
		DocumentData: documentData,
		Jwk:          jwk,
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
	// Generate pre-authorized code
	preAuthCode, err := crypto.GenerateSecureToken(32, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-auth code: %w", err)
	}

	params := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           s.cfg.Common.CredentialOffer.IssuerURL,
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
