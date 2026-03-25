package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type VerificationRequestObjectRequest struct {
	ID string `form:"id" uri:"id" validate:"required,max=128,printascii"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{
		VerifierResponseCode: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	// Match a scope from the authorization context to a known credential constructor
	scope, credentialConstructor, err := c.matchScope(authorizationContext.Scopes)
	if err != nil {
		c.log.Error(err, "no matching scope in authorization context")
		return "", err
	}

	// Get format from the first auth scope (all scopes share the same format).
	// AuthScopes is guaranteed non-empty here because startup validation
	// requires auth_scopes when auth_method is "openid4vp".
	authScope := credentialConstructor.AuthScopes[0]
	format := c.cfg.GetFormatForScope(authScope)

	// Build DCQL claims from credential constructor configuration
	claimQueries := make([]openid4vp.ClaimQuery, 0, len(credentialConstructor.AuthClaims))
	for _, claim := range credentialConstructor.AuthClaims {
		claimQueries = append(claimQueries, openid4vp.ClaimQuery{
			Path: []string{claim},
		})
	}

	// Use the first auth scope as the credential query ID, not the issuing scope.
	// The credential query ID tells the wallet what type of credential we're
	// requesting for authentication. Using the issuing scope (e.g. "ehic")
	// would mislead wallets into selecting the wrong credential.
	dcql := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{
			{
				ID:       authScope,
				Format:   format,
				Multiple: false,
				Meta: openid4vp.MetaQuery{
					VCTValues: c.cfg.VCTIdentifiersForScopes(credentialConstructor.AuthScopes),
				},
				RequireCryptographicHolderBinding: false,
				Claims:                            claimQueries,
			},
		},
		CredentialSets: []openid4vp.CredentialSetQuery{
			{
				Options: [][]string{
					{authScope},
				},
				Required: false,
				Purpose:  "authenticate for " + scope,
			},
		},
	}

	// Persist the DCQL query in the auth context so VerificationDirectPost
	// can use it for VP Token validation later.
	authorizationContext.DCQLQuery = dcql
	if err := c.cacheService.AuthContext.Update(ctx, authorizationContext); err != nil {
		c.log.Error(err, "failed to update authorization context with DCQL query")
		return "", fmt.Errorf("failed to update authorization context: %w", err)
	}

	// Derive VP formats from issuer metadata
	vf := deriveVPFormatsFromMetadata(c.issuerMetadata)

	_, ephemeralPublicJWK, err := c.EphemeralEncryptionKey(ctx, authorizationContext.EphemeralEncryptionKeyID)
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
	return jose.ExtractKIDFromCompactJWT(v.Response)
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
	privateEphemeralJWK, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid)
	if !ok {
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
	authCtx, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{EphemeralEncryptionKeyID: kid})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}

	c.log.Debug("VP Response received", "vp_token_keys", vpResponse.VPToken, "scope", authCtx.Scopes)

	// Match a scope from the authorization context to a known credential constructor
	scope, credentialConstructorCfg, err := c.matchScope(authCtx.Scopes)
	if err != nil {
		c.log.Error(err, "no matching scope in authorization context")
		return nil, err
	}

	// Extract the credential query ID from the persisted DCQL query.
	// The VP Token map is keyed by credential query ID (the auth scope),
	// not by the issuing scope.
	var credQueryID string
	if authCtx.DCQLQuery != nil && len(authCtx.DCQLQuery.Credentials) > 0 {
		credQueryID = authCtx.DCQLQuery.Credentials[0].ID
	}
	if credQueryID == "" {
		c.log.Error(nil, "DCQL credential query ID is empty", "scope", scope)
		return nil, errors.New("DCQL credential query ID is empty")
	}

	// Extract VP Token from the map using the credential query ID
	vpToken, ok := vpResponse.VPToken[credQueryID]
	if !ok {
		c.log.Error(nil, "VP Token not found for credential query", "query_id", credQueryID, "available_keys", vpResponse.VPToken)
		return nil, fmt.Errorf("VP Token not found for credential query: %s", credQueryID)
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
		ValidateFormat:  true,
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

	c.log.Debug("Found credential constructor", "scope", scope, "vct", credentialConstructorCfg.GetVCTURL())

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

	// Retrieve documents matching the identity by scope
	c.log.Debug("Querying documents", "scope", scope, "identity", identity)
	documents, err := c.datastoreStore.GetDocumentsWithIdentity(ctx, &db.GetDocumentQuery{
		Meta: &model.MetaData{
			Scope: scope,
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
	c.cacheService.Document.Set(ctx, authCtx.SessionID, documents)

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
