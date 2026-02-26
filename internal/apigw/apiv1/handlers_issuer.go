package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"vc/internal/apigw/db"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/crypto"
	"vc/pkg/helpers"
	"vc/pkg/mdoc"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
)

// VCICredentialOffer implements OpenID4VCI credential offer endpoint
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
func (c *Client) VCICredentialOffer(ctx context.Context, req *openid4vci.CredentialOfferParameters) (*openid4vci.CredentialOfferParameters, error) {
	c.log.Debug("credential offer")
	return nil, nil
}

// VCINonce implements OpenID4VCI nonce endpoint for DPoP proof freshness
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint
func (c *Client) VCINonce(ctx context.Context) (*openid4vci.NonceResponse, error) {
	nonce, err := crypto.GenerateSecureToken(0, 43)
	if err != nil {
		return nil, err
	}
	response := &openid4vci.NonceResponse{
		CNonce: nonce,
	}
	return response, nil
}

// VCICredential implements OpenID4VCI credential issuance endpoint
//
//	@Summary		VCICredential
//	@ID				create-credential
//	@Description	Create credential endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	apiv1_issuer.MakeSDJWTReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		openid4vci.CredentialRequest	true	" "
//	@Router			/credential [post]
func (c *Client) VCICredential(ctx context.Context, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error) {
	jti, err := oauth2.ExtractJTI(req.DPoP)
	if err != nil {
		c.log.Error(err, "failed to extract JTI from DPoP")
		return nil, err
	}

	if _, hasJTI := c.cacheService.DPopJTI.Get(ctx, jti); hasJTI {
		c.log.Error(nil, "DPoP JTI replay detected", "jti", jti)
		return nil, oauth2.ErrJTIReplay
	}

	dpop, err := oauth2.ValidateAndParseDPoPJWT(req.DPoP)
	if err != nil {
		c.log.Error(err, "failed to validate DPoP JWT")
		return nil, err
	}

	c.cacheService.DPopJTI.Set(ctx, jti, true)

	// Validate HTU matches credential endpoint
	if dpop.HTU != c.issuerMetadata.CredentialEndpoint {
		return nil, fmt.Errorf("invalid HTU in DPoP claims: expected %s, got %s", c.issuerMetadata.CredentialEndpoint, dpop.HTU)
	}

	// Validate HTM is POST (credential endpoint only accepts POST)
	if dpop.HTM != "POST" {
		return nil, fmt.Errorf("invalid HTM in DPoP claims: expected POST, got %s", dpop.HTM)
	}

	if !dpop.IsAccessTokenDPoP(req.HashAuthorizeToken()) {
		return nil, errors.New("invalid DPoP token")
	}

	accessToken := strings.TrimPrefix(req.Authorization, "DPoP ")

	authContext, err := c.cacheService.AuthContext.GetWithAccessToken(ctx, accessToken)
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, err
	}

	// Validate credential request against authorization details per OID4VCI 1.0 Section 7.1
	if err := req.Validate(ctx, authContext.AuthorizationDetails); err != nil {
		c.log.Error(err, "credential request validation failed")
		return nil, err
	}

	if len(authContext.Scopes) == 0 {
		c.log.Error(nil, "no scope found in auth context")
		return nil, errors.New("no scope found in auth context")
	}

	document := &model.CompleteDocument{}

	// Retrieve document based on scope configuration from credential constructor
	scope := authContext.Scopes[0]
	credentialConstructor := c.cfg.GetCredentialConstructor(scope)
	if credentialConstructor == nil {
		c.log.Error(nil, "unsupported scope", "scope", scope)
		return nil, errors.New("unsupported scope: " + scope)
	}

	// Determine retrieval strategy based on auth method
	// - "basic": Identity-based authentication → retrieve from datastore
	// - Other methods defined in auth_methods (e.g., "pid_auth"): Session-based → retrieve from cache
	authMethod := credentialConstructor.AuthMethod
	switch authMethod {
	case model.AuthMethodBasic:
		// Basic auth: retrieve from datastore using identity
		document, err = c.datastoreStore.GetDocumentWithIdentity(ctx, &db.GetDocumentQuery{
			Meta: &model.MetaData{
				AuthenticSource: authContext.AuthenticSource,
				VCT:             credentialConstructor.VCTM.VCT,
			},
			Identity: authContext.Identity,
		})
		if err != nil {
			return nil, err
		}

	default:
		// Auth methods from config (e.g., pid_auth): retrieve from session cache
		// These credentials require presenting another credential for authentication
		docs, ok := c.cacheService.Document.Get(ctx, authContext.SessionID)
		if !ok {
			c.log.Error(nil, "no documents found in cache for session", "session_id", authContext.SessionID)
			return nil, errors.New("no documents found for session " + authContext.SessionID)
		}
		for _, doc := range docs {
			document = doc
			break
		}
	}

	documentData, err := json.Marshal(document.DocumentData)
	if err != nil {
		return nil, err
	}

	// Extract JWK from proof (singular) or proofs (plural/batch)
	var jwk *apiv1_issuer.Jwk
	if req.Proof != nil {
		jwk, err = req.Proof.ExtractJWK()
		if err != nil {
			c.log.Error(err, "failed to extract JWK from proof")
			return nil, err
		}
	} else if req.Proofs != nil {
		jwk, err = req.Proofs.ExtractJWK()
		if err != nil {
			c.log.Error(err, "failed to extract JWK from proofs")
			return nil, err
		}
	} else {
		return nil, errors.New("no proof found in credential request")
	}

	// Determine credential format from credential_configuration_id or credential_identifier
	format, err := req.ResolveCredentialFormat(c.issuerMetadata)
	if err != nil {
		c.log.Error(err, "failed to resolve credential format")
		return nil, err
	}

	// Branch based on requested credential format
	switch format {
	case "mso_mdoc":
		return c.issueMDoc(ctx, authContext.Scopes[0], documentData, jwk, document)

	case "vc+sd-jwt", "dc+sd-jwt":
		return c.issueSDJWT(ctx, authContext.Scopes[0], documentData, jwk, document)

	case "ldp_vc", "vc+ld+json":
		// W3C VC 2.0 Data Integrity credential
		return c.issueVC20(ctx, authContext.Scopes[0], documentData, document, req)

	default:
		c.log.Error(nil, "unsupported or missing credential format", "format", format)
		return nil, errors.New("unsupported or missing credential format: " + format)
	}
}

// issueSDJWT issues an SD-JWT credential
func (c *Client) issueSDJWT(ctx context.Context, scope string, documentData []byte, jwk *apiv1_issuer.Jwk, document *model.CompleteDocument) (*openid4vci.CredentialResponse, error) {
	reply, err := c.issuerClient.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        scope,
		DocumentData: documentData,
		Jwk:          jwk,
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeSDJWT")
		return nil, err
	}

	if reply == nil {
		return nil, errors.New("MakeSDJWT reply is nil")
	}

	// Save credential subject info to registry for status management
	if len(document.Identities) > 0 {
		identity := document.Identities[0]
		_, err = c.registryClient.SaveCredentialSubject(ctx, &apiv1_registry.SaveCredentialSubjectRequest{
			FirstName:   identity.GivenName,
			LastName:    identity.FamilyName,
			DateOfBirth: identity.BirthDate,
			Section:     reply.TokenStatusListSection,
			Index:       reply.TokenStatusListIndex,
		})
		if err != nil {
			c.log.Error(err, "failed to save credential subject to registry")
		}
	}

	response := &openid4vci.CredentialResponse{}
	switch len(reply.Credentials) {
	case 0:
		return nil, helpers.ErrNoDocumentFound
	case 1:
		response.Credentials = []openid4vci.Credential{
			{
				Credential: reply.Credentials[0].Credential,
			},
		}
		return response, nil
	default:
		return nil, errors.New("multiple credentials returned from issuer, not supported")
	}
}

// issueMDoc issues an mDL/mDoc credential (ISO 18013-5)
func (c *Client) issueMDoc(ctx context.Context, scope string, documentData []byte, jwk *apiv1_issuer.Jwk, document *model.CompleteDocument) (*openid4vci.CredentialResponse, error) {
	// Convert JWK to COSE key bytes for mDoc
	deviceKeyBytes, err := convertJWKToCOSEKey(jwk)
	if err != nil {
		c.log.Error(err, "failed to convert JWK to COSE key")
		return nil, err
	}

	reply, err := c.issuerClient.MakeMDoc(ctx, &apiv1_issuer.MakeMDocRequest{
		Scope:           scope,
		DocType:         mdoc.DocType, // org.iso.18013.5.1.mDL
		DocumentData:    documentData,
		DevicePublicKey: deviceKeyBytes,
		DeviceKeyFormat: "cose",
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeMDoc")
		return nil, err
	}

	if reply == nil {
		return nil, errors.New("MakeMDoc reply is nil")
	}

	// Save credential subject info to registry for status management
	if len(document.Identities) > 0 && reply.StatusListSection > 0 {
		identity := document.Identities[0]
		_, err = c.registryClient.SaveCredentialSubject(ctx, &apiv1_registry.SaveCredentialSubjectRequest{
			FirstName:   identity.GivenName,
			LastName:    identity.FamilyName,
			DateOfBirth: identity.BirthDate,
			Section:     reply.StatusListSection,
			Index:       reply.StatusListIndex,
		})
		if err != nil {
			c.log.Error(err, "failed to save credential subject to registry")
		}
	}

	// For mDoc, the credential is CBOR bytes - encode as base64 for JSON response
	mdocBase64 := base64.StdEncoding.EncodeToString(reply.Mdoc)

	response := &openid4vci.CredentialResponse{
		Credentials: []openid4vci.Credential{
			{
				Credential: mdocBase64,
			},
		},
	}

	return response, nil
}

// issueVC20 issues a W3C VC 2.0 Data Integrity credential
func (c *Client) issueVC20(ctx context.Context, scope string, documentData []byte, document *model.CompleteDocument, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error) {
	// Extract cryptosuite from credential configuration
	var cryptosuite string
	var mandatoryPointers []string
	var credentialTypes []string

	if req.CredentialConfigurationID != "" && c.issuerMetadata != nil {
		if config, ok := c.issuerMetadata.CredentialConfigurationsSupported[req.CredentialConfigurationID]; ok {
			cryptosuite = config.Cryptosuite
			if config.CredentialDefinition != nil {
				credentialTypes = config.CredentialDefinition.Type
			}
			// Mandatory pointers could be specified in config in future
		}
	}

	// Default cryptosuite if not specified
	if cryptosuite == "" {
		cryptosuite = "ecdsa-rdfc-2019"
	}

	// Default credential types
	if len(credentialTypes) == 0 {
		credentialTypes = []string{"VerifiableCredential"}
	}

	// Extract subject DID from proof if available
	var subjectDID string
	if req.Proof != nil {
		subjectDID = req.Proof.ExtractSubjectDID()
	}

	reply, err := c.issuerClient.MakeVC20(ctx, &apiv1_issuer.MakeVC20Request{
		Scope:             scope,
		DocumentData:      documentData,
		CredentialTypes:   credentialTypes,
		SubjectDid:        subjectDID,
		Cryptosuite:       cryptosuite,
		MandatoryPointers: mandatoryPointers,
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeVC20")
		return nil, err
	}

	if reply == nil {
		return nil, errors.New("MakeVC20 reply is nil")
	}

	// Save credential subject info to registry for status management
	if len(document.Identities) > 0 && reply.StatusListSection > 0 {
		identity := document.Identities[0]
		_, err = c.registryClient.SaveCredentialSubject(ctx, &apiv1_registry.SaveCredentialSubjectRequest{
			FirstName:   identity.GivenName,
			LastName:    identity.FamilyName,
			DateOfBirth: identity.BirthDate,
			Section:     reply.StatusListSection,
			Index:       reply.StatusListIndex,
		})
		if err != nil {
			c.log.Error(err, "failed to save credential subject to registry")
		}
	}

	response := &openid4vci.CredentialResponse{
		Credentials: []openid4vci.Credential{
			{
				// VC20 Data Integrity credentials are JSON-LD, return as-is
				Credential: string(reply.Credential),
			},
		},
	}

	return response, nil
}

// convertJWKToCOSEKey converts a JWK to CBOR-encoded COSE_Key bytes
func convertJWKToCOSEKey(jwk *apiv1_issuer.Jwk) ([]byte, error) {
	if jwk == nil {
		return nil, errors.New("JWK is nil")
	}

	// Decode the X and Y coordinates from base64url
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, errors.New("failed to decode JWK X coordinate")
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, errors.New("failed to decode JWK Y coordinate")
	}

	// Create COSE_Key from JWK
	coseKey, err := mdoc.NewCOSEKeyFromCoordinates(jwk.Kty, jwk.Crv, xBytes, yBytes)
	if err != nil {
		return nil, err
	}

	return coseKey.Bytes()
}

// VCIDeferredCredential implements OpenID4VCI deferred credential endpoint
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin
func (c *Client) VCIDeferredCredential(ctx context.Context, req *openid4vci.DeferredCredentialRequest) (*openid4vci.CredentialResponse, error) {
	c.log.Debug("deferred credential", "req", req)
	// run the same code as VCICredential
	return nil, nil
}

// VCICredentialOfferURI implements OpenID4VCI credential offer URI endpoint
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-14.html#name-sending-credential-offer-by-
func (c *Client) VCICredentialOfferURI(ctx context.Context, req *openid4vci.CredentialOfferURIRequest) (*openid4vci.CredentialOfferParameters, error) {
	c.log.Debug("credential offer uri", "req", req.CredentialOfferUUID)
	doc, err := c.credentialOfferStore.Get(ctx, req.CredentialOfferUUID)
	if err != nil {
		c.log.Debug("failed to marshal document data", "error", err)
		return nil, err
	}

	return &doc.CredentialOfferParameters, nil
}

// VCINotification implements OpenID4VCI notification endpoint
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint
func (c *Client) VCINotification(ctx context.Context, req *openid4vci.NotificationRequest) error {
	c.log.Debug("notification", "req", req)
	return nil
}

// VCIMetadata https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
func (c *Client) VCIMetadata(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	c.log.Debug("metadata request")

	if err := helpers.Check(ctx, c.cfg, c.issuerMetadata, c.log); err != nil {
		c.log.Error(err, "failed to check metadata")
		return nil, err
	}

	if c.pkiSigner != nil {
		metadata, err := c.issuerMetadata.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
		if err != nil {
			c.log.Error(err, "failed to sign metadata")
			return nil, err
		}
		return metadata, nil
	}

	return c.issuerMetadata, nil
}
