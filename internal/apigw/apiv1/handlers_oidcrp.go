package apiv1

import (
	"context"
	"encoding/json"
	"fmt"

	"vc/internal/apigw/oidcrp"
	apiv1_issuer "vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/crypto"
	"vc/pkg/grpchelpers"
	"vc/pkg/model"
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
	Status          string         `json:"status"`
	CredentialType  string         `json:"credential_type"`
	Credential      string         `json:"credential"`
	CredentialOffer map[string]any `json:"credential_offer"`
	Message         string         `json:"message"`

	// VCIRedirectURL is set when the callback is part of a VCI consent flow.
	// The httpserver should redirect the browser to this URL instead of returning JSON.
	VCIRedirectURL string `json:"vci_redirect_url,omitempty"`
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
			for k, v := range userInfoClaims {
				authResp.Claims[k] = v
			}
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

	// Log the mapping attributes and resulting document data for diagnostics.
	// This helps identify mismatches between credential_mappings and the VCTM claims.
	claimKeys := make([]string, 0, len(claims))
	for k := range claims {
		claimKeys = append(claimKeys, k)
	}
	mappingKeys := make([]string, 0, len(mapping.Attributes))
	for k := range mapping.Attributes {
		mappingKeys = append(mappingKeys, k)
	}

	c.log.Info("OIDC authentication successful",
		"credential_type", session.CredentialType,
		"claims_count", len(claims),
		"claim_keys", claimKeys,
		"mapping_attributes", mappingKeys,
		"subject", authResp.IDToken.Subject)

	// VCI mode: if the OIDC session was initiated from the OpenID4VCI consent flow,
	// store the transformed claims as a document in the VCI session cache and signal
	// the httpserver to redirect back to the consent page.
	if session.VCISessionID != "" {
		c.log.Info("OIDC callback: VCI mode detected, storing document in VCI cache",
			"vci_session_id", session.VCISessionID,
			"credential_type", session.CredentialType)

		doc := &model.CompleteDocument{
			Meta: &model.MetaData{
				AuthenticSource: session.IssuerURL,
			},
			DocumentData:        claims,
			DocumentDataVersion: "1.0.0",
		}
		docs := map[string]*model.CompleteDocument{
			session.IssuerURL: doc,
		}

		if err := c.StoreVCIDocuments(ctx, session.VCISessionID, docs); err != nil {
			span.SetStatus(codes.Error, "VCI document storage failed")
			return nil, fmt.Errorf("failed to store VCI documents: %w", err)
		}

		// Clean up OIDC session (clear err so defer doesn't double-delete)
		err = nil
		service.DeleteSession(ctx, req.State)

		return &OIDCRPCallbackResponse{
			Status:         "success",
			CredentialType: session.CredentialType,
			VCIRedirectURL: "/authorization/consent/#/credentials",
			Message:        "OIDC authentication successful, continuing VCI flow",
		}, nil
	}

	// Standalone mode: create credential directly via issuer gRPC
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

	// Clean up session (clear err so defer doesn't double-delete)
	err = nil
	service.DeleteSession(ctx, req.State)

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

	credentialConstructor := c.cfg.GetCredentialConstructor(credentialType)
	if credentialConstructor == nil {
		return "", fmt.Errorf("unsupported credential type: %s", credentialType)
	}

	// Call the issuer's MakeSDJWT method
	reply, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        credentialType,
		DocumentData: documentData,
		Jwk:          jwk,
		VctUrl:       credentialConstructor.GetVCTURL(),
		Integrity:    credentialConstructor.GetIntegrity(),
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
	preAuthCode, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-auth code: %w", err)
	}

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
