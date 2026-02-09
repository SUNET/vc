package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"vc/internal/apigw/db"
	"vc/pkg/cache"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type VerificationRequestObjectRequest struct {
	ID string `form:"id" uri:"id"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	authorizationContext, err := c.authContextCache.Get(ctx, &cache.AuthorizationContext{
		VerifierResponseCode: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	// Get credential constructor to determine auth method
	credentialConstructor := c.cfg.GetCredentialConstructor(authorizationContext.Scopes[0])
	if credentialConstructor == nil {
		c.log.Error(nil, "credential constructor not found for scope", "scope", authorizationContext.Scopes[0])
		return "", errors.New("credential constructor not found for scope: " + authorizationContext.Scopes[0])
	}

	// Get auth method configuration (guaranteed to exist by config validation)
	authMethod := c.cfg.AuthMethods[credentialConstructor.AuthMethod]

	// Get format from credential constructor based on VCT
	// All VCTs in the same auth method should have the same format (validated at config load)
	format := ""
	if len(authMethod.VCTs) > 0 {
		format = c.cfg.GetFormatForVCT(authMethod.VCTs[0])
	}
	if format == "" {
		// Fallback to the format of the credential being issued
		format = credentialConstructor.Format
	}

	// Build DCQL claims from auth method configuration
	claimQueries := make([]openid4vp.ClaimQuery, 0, len(authMethod.Claims))
	for _, claim := range authMethod.Claims {
		claimQueries = append(claimQueries, openid4vp.ClaimQuery{
			Path: []string{claim},
		})
	}

	dcql := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{
			{
				ID:       authorizationContext.Scopes[0],
				Format:   format,
				Multiple: false,
				Meta: openid4vp.MetaQuery{
					VCTValues: authMethod.VCTs,
				},
				TrustedAuthorities:                []openid4vp.TrustedAuthority{},
				RequireCryptographicHolderBinding: false,
				Claims:                            claimQueries,
				ClaimSet:                          []string{},
			},
		},
		CredentialSets: []openid4vp.CredentialSetQuery{
			{
				Options: [][]string{
					{authorizationContext.Scopes[0]},
				},
				Required: false,
				Purpose:  "fetch credential for " + authorizationContext.Scopes[0],
			},
		},
	}

	// Derive VP formats from issuer metadata
	vf := deriveVPFormatsFromMetadata(c.issuerMetadata)

	_, ephemeralPublicJWK, err := c.EphemeralEncryptionKey(authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return "", err
	}

	responseURI, err := url.JoinPath(c.cfg.APIGW.PublicURL, "/verification/direct_post")
	if err != nil {
		return "", fmt.Errorf("failed to construct response URI: %w", err)
	}
	authorizationRequest := openid4vp.RequestObject{
		ResponseURI:  responseURI,
		AUD:          "https://self-issued.me/v2",
		ISS:          authorizationContext.ClientID,
		ClientID:     authorizationContext.ClientID,
		ResponseType: "vp_token",
		ResponseMode: "direct_post.jwt",
		State:        authorizationContext.State,
		Nonce:        authorizationContext.Nonce,
		DCQLQuery:    dcql,
		ClientMetadata: &openid4vp.ClientMetadata{
			VPFormatsSupported: vf,
			JWKS: &openid4vp.Keys{
				Keys: []jwk.Key{ephemeralPublicJWK},
			},
			AuthorizationEncryptedResponseALG: "ECDH-ES",
			AuthorizationEncryptedResponseENC: "A256GCM",
		},
		IAT: time.Now().UTC().Unix(),
	}

	c.log.Debug("Authorization request", "request", authorizationRequest)

	signedJWT, err := authorizationRequest.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", signedJWT)

	return signedJWT, nil
}

type VerificationDirectPostRequest struct {
	Response string `json:"response" form:"response"`
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
	PresentationDuringIssuanceSession string `json:"presentation_during_issuance_session"`
	RedirectURI                       string `json:"redirect_uri"`
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
	privateEphemeralJWK := c.ephemeralEncryptionKeyCache.Get(kid).Value()
	if privateEphemeralJWK == nil {
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

	// Get authorization context
	authCtx, err := c.authContextCache.Get(ctx, &cache.AuthorizationContext{EphemeralEncryptionKeyID: kid})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}

	c.log.Debug("VP Response received", "vp_token_keys", vpResponse.VPToken, "scope", authCtx.Scopes)

	// Extract VP Token from the map using the scope as key
	vpToken, ok := vpResponse.VPToken[authCtx.Scopes[0]]
	if !ok {
		c.log.Error(nil, "VP Token not found for scope", "scope", authCtx.Scopes[0], "available_keys", vpResponse.VPToken)
		return nil, fmt.Errorf("VP Token not found for scope: %s", authCtx.Scopes[0])
	}

	// Prepare response parameters
	responseParams := &openid4vp.ResponseParameters{
		State:   vpResponse.State,
		VPToken: vpToken,
	}

	c.log.Debug("Response parameters prepared", "has_vp_token", responseParams.VPToken != "", "state", responseParams.State)

	// Validate response parameters
	if err := responseParams.Validate(); err != nil {
		c.log.Error(err, "response parameters validation failed")
		return nil, fmt.Errorf("invalid response: %w", err)
	}

	// Validate VP Token using VPTokenValidator
	validator := &openid4vp.VPTokenValidator{
		Nonce:           authCtx.Nonce,
		ClientID:        authCtx.ClientID,
		VerifySignature: true,
		CheckRevocation: false,
		DCQLQuery:       authCtx.DCQLQuery,
	}

	if err := validator.Validate(responseParams.VPToken); err != nil {
		c.log.Error(err, "VP Token validation failed")
		return nil, fmt.Errorf("VP Token validation failed: %w", err)
	}

	c.log.Debug("VP Token validated successfully")

	// Build credential from validated VP Token
	credential, err := responseParams.BuildCredential()
	if err != nil {
		c.log.Error(err, "failed to build credential from response parameters")
		return nil, err
	}

	// Get credential constructor configuration using GetCredentialConstructor
	// This looks up by VCT (primary key) or CommonName (for backward compatibility)
	credentialConstructorCfg := c.cfg.GetCredentialConstructor(authCtx.Scopes[0])
	if credentialConstructorCfg == nil {
		c.log.Error(nil, "credential constructor not found for scope", "scope", authCtx.Scopes[0])
		return nil, errors.New("credential constructor not found for scope: " + authCtx.Scopes[0])
	}

	c.log.Debug("Found credential constructor", "scope", authCtx.Scopes, "vct", credentialConstructorCfg.GetVCT())

	// Extract identity from validated credential
	identity := &model.Identity{}
	if givenName, ok := credential["given_name"].(string); ok {
		identity.GivenName = givenName
	}
	if familyName, ok := credential["family_name"].(string); ok {
		identity.FamilyName = familyName
	}
	if birthdate, ok := credential["birthdate"].(string); ok {
		identity.BirthDate = birthdate
	}

	// Retrieve documents matching the identity
	// Use authorizationContext.VCT which should be set to the VCT value
	c.log.Debug("Querying documents", "vct", credentialConstructorCfg.GetVCT(), "identity", identity)
	documents, err := c.datastoreStore.GetDocumentsWithIdentity(ctx, &db.GetDocumentQuery{
		Meta: &model.MetaData{
			VCT: credentialConstructorCfg.GetVCT(),
		},
		Identity: identity,
	})
	if err != nil {
		c.log.Debug("failed to get document", "error", err)
		return nil, err
	}

	c.log.Debug("Retrieved documents", "count", len(documents))

	if len(documents) == 0 {
		c.log.Error(nil, "no documents found for identity", "identity", identity)
		return nil, errors.New("no documents found for the provided identity")
	}

	// Cache PID documents for session
	c.documentCache.Set(authCtx.SessionID, documents, ttlcache.DefaultTTL)

	c.log.Debug("Documents cached for session", "session_id", authCtx.SessionID)

	callbackURL, err := url.JoinPath(c.cfg.APIGW.PublicURL, "/authorization/consent/callback/")
	if err != nil {
		c.log.Error(nil, "Failed to construct callback URL", "error", err)
		return nil, errors.New("failed to construct callback URL")
	}
	u, err := url.Parse(callbackURL)
	if err != nil {
		c.log.Error(nil, "Failed to parse callback URL", "error", err)
		return nil, errors.New("failed to parse callback URL")
	}
	q := u.Query()
	q.Set("response_code", authCtx.VerifierResponseCode)
	u.RawQuery = q.Encode()

	reply := &VerificationDirectPostResponse{
		RedirectURI: u.String(),
	}
	return reply, nil
}
