package apiv1

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
	apiv1_issuer "vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/cache"
	"vc/pkg/crypto"
	"vc/pkg/helpers"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"

	"github.com/google/uuid"
)

// OAuthPar implements OAuth 2.0 Pushed Authorization Request (PAR)
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-endpoint
func (c *Client) OAuthPar(ctx context.Context, req *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	c.log.Debug("OAuthPar", "req", req)
	oauthClient, err := c.cfg.APIGW.OauthServer.Clients.Allow(req.ClientID, req.RedirectURI, req.Scope)
	if err != nil {
		return nil, errors.Join(oauth2.ErrInvalidClient, err)
	}

	// Public clients MUST use PKCE (RFC 6749 Section 2.1)
	if oauthClient.Type == oauth2.ClientTypePublic && req.CodeChallenge == "" {
		return nil, errors.Join(oauth2.ErrInvalidClient, oauth2.ErrPKCERequired)
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

	response := &openid4vci.ParResponse{
		RequestURI: requestURI,
		ExpiresIn:  60,
	}

	return response, nil
}

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

	if authorizationContext.Forfeited {
		c.log.Debug("Authorization already used")
		return nil, errors.New("not allowed")
	}

	var redirectURL string
	if !authorizationContext.Consent {
		redirectURL = "/authorization/consent"
	}

	response := &openid4vci.AuthorizationResponse{
		RedirectURL:    redirectURL,
		Scope:          authorizationContext.Scopes[0],
		SessionID:      authorizationContext.SessionID,
		ClientID:       authorizationContext.ClientID,
		WalletClientID: authorizationContext.WalletClientID,
	}

	c.log.Debug("Authorize", "authorization", authorizationContext)

	return response, nil
}

// OAuthToken implements OAuth 2.0 token endpoint for credential issuance
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint
func (c *Client) OAuthToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	c.log.Debug("OAuthToken", "req", req)

	// Look up the client to enforce type-specific requirements
	oauthClient, err := c.cfg.APIGW.OauthServer.Clients.Get(req.ClientID)
	if err != nil {
		c.log.Error(err, "client validation failed")
		return nil, errors.Join(oauth2.ErrInvalidClient, err)
	}

	// Public clients (wallets) MUST use PKCE per RFC 6749 Section 2.1
	if oauthClient.Type == oauth2.ClientTypePublic && req.CodeVerifier == "" {
		return nil, oauth2.ErrPKCERequired
	}

	authorizationContext, err := c.cacheService.AuthContext.ForfeitAuthorizationCode(ctx, &cache.AuthorizationContext{
		Code: req.Code,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, err
	}
	c.log.Debug("Token", "state", authorizationContext.State)

	// Verify PKCE code_challenge (for all clients that provided one)
	if err := oauth2.ValidatePKCE(req.CodeVerifier, authorizationContext.CodeChallenge, authorizationContext.CodeChallengeMethod); err != nil {
		c.log.Error(err, "PKCE validation failed")
		return nil, fmt.Errorf("PKCE validation failed: %w", err)
	}
	c.log.Debug("PKCE validation successful")

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
		CNonceExpiresIn: 0,
	}

	// Per OID4VCI 1.0 Section 6.2: authorization_details is REQUIRED in the Token Response when
	// authorization_details was used in the Authorization Request, with credential_identifiers added.
	if len(authorizationContext.AuthorizationDetails) > 0 {
		responseDetails := make([]openid4vci.AuthorizationDetailsParameter, len(authorizationContext.AuthorizationDetails))
		for i, ad := range authorizationContext.AuthorizationDetails {
			responseDetails[i] = ad
			responseDetails[i].CredentialIdentifiers = []string{uuid.NewString()}
		}
		reply.AuthorizationDetails = responseDetails
	}

	tokenDoc := &cache.Token{
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(time.Duration(reply.ExpiresIn) * time.Second).Unix(),
	}

	if err := c.cacheService.AuthContext.AddToken(ctx, authorizationContext.Code, tokenDoc); err != nil {
		c.log.Error(err, "failed to add token")
		return nil, err
	}

	jti, err := oauth2.ExtractJTI(req.DPOP)
	if err != nil {
		c.log.Error(err, "failed to extract JTI from DPoP")
		return nil, err
	}

	if _, hasJTI := c.cacheService.DPopJTI.Get(ctx, jti); hasJTI {
		c.log.Error(nil, "DPoP JTI replay detected", "jti", jti)
		return nil, oauth2.ErrJTIReplay
	}

	dpop, err := oauth2.ValidateAndParseDPoPJWT(req.DPOP)
	if err != nil {
		c.log.Error(err, "dpop validation error")
		return nil, err
	}

	c.cacheService.DPopJTI.Set(ctx, jti, true)

	// Validate HTU matches token endpoint
	if dpop.HTU != c.cfg.APIGW.OauthServer.TokenEndpoint {
		return nil, fmt.Errorf("invalid HTU in DPoP claims: expected %s, got %s", c.cfg.APIGW.OauthServer.TokenEndpoint, dpop.HTU)
	}

	// Validate HTM is POST (token endpoint only accepts POST)
	if dpop.HTM != "POST" {
		return nil, fmt.Errorf("invalid HTM in DPoP claims: expected POST, got %s", dpop.HTM)
	}

	c.log.Debug("DPoP claims", "jti", dpop.JTI, "htu", dpop.HTU, "htm", dpop.HTM)

	//c.db.VCAuthColl.Grant(ctx, req.ClientID, req.Code)

	// Check if ClientID and Code match
	// Check if Code have been used
	// Check if Code is expired
	return reply, nil
}

func (c *Client) OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error) {
	c.log.Debug("metadata request")

	signedMetadata, err := c.oauth2Metadata.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		return nil, err
	}

	if err := helpers.Check(ctx, c.cfg, signedMetadata, c.log); err != nil {
		c.log.Error(err, "metadata check error")
		return nil, err
	}

	return signedMetadata, nil
}

// JWKSResponse represents a JSON Web Key Set (RFC 7517 §5).
type JWKSResponse = apiv1_issuer.Keys

// JWKS returns the issuer's public signing keys as a JWK Set.
// The keys are fetched from the issuer via gRPC and stripped of any private
// key material before being served.
func (c *Client) JWKS(ctx context.Context) (*JWKSResponse, error) {
	c.log.Debug("JWKS request")

	reply, err := c.issuerClient.JWKS(ctx, &apiv1_issuer.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from issuer: %w", err)
	}

	jwks := reply.GetJwks()
	if jwks == nil {
		return &apiv1_issuer.Keys{}, nil
	}

	// Strip private key material — only public keys are served
	for _, key := range jwks.GetKeys() {
		key.D = ""
		key.KeyOps = nil
		key.Ext = false
	}

	return jwks, nil
}

// SDJWTVCIssuerMetadataResponse represents JWT VC Issuer Metadata per SD-JWT VC §5.3.
type SDJWTVCIssuerMetadataResponse struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// SDJWTVCIssuerMetadata returns the JWT VC Issuer Metadata per draft-ietf-oauth-sd-jwt-vc §5.3.
// This metadata is served at /.well-known/jwt-vc-issuer and allows verifiers to discover
// the issuer's JWKS endpoint.
func (c *Client) SDJWTVCIssuerMetadata(ctx context.Context) (*SDJWTVCIssuerMetadataResponse, error) {
	c.log.Debug("sd-jwt-vc issuer metadata request")

	return &SDJWTVCIssuerMetadataResponse{
		Issuer:  c.cfg.APIGW.PublicURL,
		JWKSURI: c.cfg.APIGW.PublicURL + "/jwks",
	}, nil
}

type OauthAuthorizationConsentRequest struct {
	//AuthMethod string `json:"-"`
	SessionID string `json:"-"`
}

type OAuthAuthorizationConsentResponse struct {
	RedirectURL       string
	VerifierContextID string `json:"-"`
}

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
	//RedirectURL string `json:"-"`
}

func (c *Client) OAuthAuthorizationConsentCallback(ctx context.Context, req *OauthAuthorizationConsentCallbackRequest) (*OAuthAuthorizationConsentCallbackResponse, error) {
	c.log.Debug("OAuthAuthorizationConsentCallback request", "req", req)
	reply := &OAuthAuthorizationConsentCallbackResponse{}

	return reply, nil
}
