//go:build oidcrp

package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	apiv1_issuer "vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/grpchelpers"
	"vc/pkg/oidcrp"
	"vc/pkg/openid4vci"

	"go.opentelemetry.io/otel/codes"
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
	Status          string                 `json:"status"`
	CredentialType  string                 `json:"credential_type"`
	Credential      string                 `json:"credential"`
	CredentialOffer map[string]any `json:"credential_offer"`
	Message         string                 `json:"message"`
}

// OIDCRPInitiate initiates OIDC authentication flow
func (c *Client) OIDCRPInitiate(ctx context.Context, req *OIDCRPInitiateRequest, oidcrpService any) (*OIDCRPInitiateResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:OIDCRPInitiate")
	defer span.End()

	service, ok := oidcrpService.(*oidcrp.Service)
	if !ok || service == nil {
		return nil, fmt.Errorf("OIDC RP service not available")
	}

	authReq, err := service.InitiateAuth(ctx, req.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &OIDCRPInitiateResponse{
		AuthorizationURL: authReq.AuthorizationURL,
		State:            authReq.State,
	}, nil
}

// OIDCRPCallback processes OIDC callback and issues credential
func (c *Client) OIDCRPCallback(ctx context.Context, req *OIDCRPCallbackRequest, oidcrpService any) (*OIDCRPCallbackResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:OIDCRPCallback")
	defer span.End()

	service, ok := oidcrpService.(*oidcrp.Service)
	if !ok || service == nil {
		return nil, fmt.Errorf("OIDC RP service not available")
	}

	// Process the callback via OIDC RP service
	authResp, err := service.ProcessCallback(ctx, req.Code, req.State)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Retrieve session to get credential type
	session, err := service.GetSession(req.State)
	if err != nil {
		span.SetStatus(codes.Error, "session retrieval failed")
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	// Build transformer from config
	transformer, err := service.BuildTransformer()
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

	// Transform OIDC claims to credential claims
	claims, err := transformer.TransformClaims(session.CredentialType, authResp.Claims)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.log.Info("OIDC authentication successful",
		"credential_type", session.CredentialType,
		"claims_count", len(claims),
		"subject", authResp.IDToken.Subject)

	// Marshal claims to JSON for the credential
	documentData, err := json.Marshal(claims)
	if err != nil {
		span.SetStatus(codes.Error, "document marshaling failed")
		return nil, fmt.Errorf("failed to marshal document: %w", err)
	}

	// Create credential using the issuer gRPC API
	credential, err := c.createCredentialViaOIDCRP(ctx, session.CredentialType, documentData, nil)
	if err != nil {
		span.SetStatus(codes.Error, "credential creation failed")
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	// Generate credential offer for wallet
	credentialOffer, err := c.generateCredentialOfferOIDCRP(ctx, session.CredentialType, mapping.CredentialConfigID)
	if err != nil {
		span.SetStatus(codes.Error, "credential offer generation failed")
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	// Clean up session
	service.DeleteSession(req.State)

	c.log.Info("Credential issued successfully via OIDC RP",
		"credential_type", session.CredentialType,
		"offer_id", credentialOffer["id"])

	return &OIDCRPCallbackResponse{
		Status:          "success",
		CredentialType:  session.CredentialType,
		Credential:      credential,
		CredentialOffer: credentialOffer,
		Message:         "OIDC authentication and credential issuance successful",
	}, nil
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

	// Call the issuer's MakeSDJWT method
	reply, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        credentialType,
		DocumentData: documentData,
		Jwk:          jwk,
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

// generateCredentialOfferOIDCRP creates an OpenID4VCI credential offer
func (c *Client) generateCredentialOfferOIDCRP(ctx context.Context, credentialType string, credentialConfigID string) (map[string]any, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:generateCredentialOfferOIDCRP")
	defer span.End()

	// Generate a unique pre-authorized code
	preAuthCode := fmt.Sprintf("oidcrp_%d", time.Now().UnixNano())

	// Build credential offer parameters
	params := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           c.cfg.APIGW.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{credentialConfigID},
		Grants: map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": preAuthCode,
				"tx_code":             nil,
			},
		},
	}

	// Generate credential offer
	offer, err := params.CredentialOffer()
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	// Convert to map for response
	var offerMap map[string]any
	offerBytes, err := json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal offer: %w", err)
	}
	if err := json.Unmarshal(offerBytes, &offerMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal offer to map: %w", err)
	}

	offerMap["id"] = preAuthCode

	return offerMap, nil
}
