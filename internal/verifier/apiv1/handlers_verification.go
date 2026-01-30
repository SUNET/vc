package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"vc/pkg/jose"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwtvc"

	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

type VerificationRequestObjectRequest struct {
	ID string `form:"id" uri:"id"`
	//SessionID string `json:"-"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	// TODO(masv): should request-object-id be associated with a particular session?
	authorizationContext, err := c.authContextStore.Get(ctx, &model.AuthorizationContext{
		RequestObjectID: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	requestObject, found := c.openid4vp.RequestObjectCache.Get(authorizationContext.RequestObjectID)
	if !found {
		c.log.Error(nil, "request object not found in cache", "requestObjectID", authorizationContext.RequestObjectID)
		return "", errors.New("request object not found")
	}

	signingMethod, _ := jose.GetSigningMethodFromKey(c.verifierSigningKey)
	signedJWT, err := requestObject.Sign(signingMethod, c.verifierSigningKey, c.verifierSigningChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", signedJWT)

	return signedJWT, nil
}

type VerificationDirectPostRequest struct {
	Response  string `json:"response"  form:"response"`
	SessionID string `json:"-"` // Set by HTTP layer if same-device flow
}

func (v *VerificationDirectPostRequest) GetKID() (string, error) {
	fmt.Println("Kid")
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
	// RedirectURI is optional - only included for same-device flows
	// For cross-device flows, the browser is notified via SSE instead
	RedirectURI string `json:"redirect_uri,omitempty"`
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
	privateEphemeralJWK, found := c.openid4vp.EphemeralKeyCache.Get(kid)
	if !found {
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

	c.log.Debug("directPost", "vpResponse", vpResponse)

	// Get authorization context by state
	authCtx, err := c.authContextStore.Get(ctx, &model.AuthorizationContext{State: vpResponse.State})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}

	// Generate response code
	responseCode := uuid.NewString()
	c.notify.Submit(authCtx.SessionID, map[string]string{"redirect_uri": fmt.Sprintf(c.cfg.Verifier.ExternalServerURL+"/verification/callback?response_code=%s", responseCode)})

	// Process all VP tokens for the requested scopes
	credentialCaches := make([]sdjwtvc.CredentialCache, 0, len(authCtx.Scope))

	for _, scope := range authCtx.Scope {
		vpToken, ok := vpResponse.VPToken[scope]
		if !ok {
			c.log.Error(nil, "VP token not found for scope", "scope", scope)
			return nil, fmt.Errorf("VP token not found for scope: %s", scope)
		}

		responseParams := &openid4vp.ResponseParameters{}
		responseParams.State = vpResponse.State
		responseParams.VPToken = vpToken

		// Validate response parameters
		if err := responseParams.Validate(); err != nil {
			c.log.Error(err, "response parameters validation failed", "scope", scope)
			return nil, fmt.Errorf("invalid response for scope %s: %w", scope, err)
		}

		// Validate VP Token using VPTokenValidator
		validator := &openid4vp.VPTokenValidator{
			Nonce:           authCtx.Nonce,
			ClientID:        authCtx.ClientID,
			VerifySignature: true,
			CheckRevocation: false,
		}

		if err := validator.Validate(responseParams.VPToken); err != nil {
			c.log.Error(err, "VP Token validation failed", "scope", scope)
			return nil, fmt.Errorf("VP Token validation failed for scope %s: %w", scope, err)
		}

		c.log.Debug("VP Token validated successfully", "scope", scope)

		// Parse SD-JWT credential
		_, _, _, selectiveDisclosure, _, err := sdjwtvc.Token(responseParams.VPToken).Split()
		if err != nil {
			c.log.Error(err, "failed to split sd-jwt", "scope", scope)
			return nil, err
		}

		// Parse credential claims
		parsed, err := sdjwtvc.Token(responseParams.VPToken).Parse()
		if err != nil {
			c.log.Error(err, "failed to parse sd-jwt credential", "scope", scope)
			return nil, err
		}

		selectiveDisclosureClaims, err := sdjwtvc.ParseSelectiveDisclosure(selectiveDisclosure)
		if err != nil {
			c.log.Error(err, "failed to parse selective disclosures", "scope", scope)
			return nil, err
		}

		// Add to credential cache array
		credentialCaches = append(credentialCaches, sdjwtvc.CredentialCache{
			Credential: parsed.Claims,
			Claims:     selectiveDisclosureClaims,
		})
	}

	// Cache validated credentials
	c.credentialCache.Set(responseCode, credentialCaches, ttlcache.DefaultTTL)

	c.log.Debug("Credentials cached", "response_code", responseCode, "count", len(credentialCaches))

	redirectURI := fmt.Sprintf(c.cfg.Verifier.ExternalServerURL+"/verification/callback?response_code=%s", responseCode)

	reply := &VerificationDirectPostResponse{}

	// Check if there's an active SSE listener for this session
	// If yes -> cross-device flow: browser is listening, notify via SSE, don't include redirect_uri
	// If no -> same-device flow: no browser listening, include redirect_uri for wallet to follow
	if c.notify.HasListener(authCtx.SessionID) {
		// Cross-device flow: browser is waiting on SSE
		c.log.Debug("Cross-device flow detected (SSE listener active)", "session_id", authCtx.SessionID)
		// Don't include redirect_uri - wallet shows success, browser gets SSE notification
	} else {
		// Same-device flow: no SSE listener, wallet should redirect
		c.log.Debug("Same-device flow detected (no SSE listener)", "session_id", authCtx.SessionID)
		reply.RedirectURI = redirectURI
	}

	return reply, nil
}

type VerificationCallbackRequest struct {
	ResponseCode string `form:"response_code" uri:"response_code"`
}

type VerificationCallbackResponse struct {
	CredentialData []sdjwtvc.CredentialCache `json:"credential_data"`
}

func (c *Client) VerificationCallback(ctx context.Context, req *VerificationCallbackRequest) (*VerificationCallbackResponse, error) {
	c.log.Debug("verificationCallback", "req", req)

	if has := c.credentialCache.Has(req.ResponseCode); !has {
		return nil, fmt.Errorf("no item in credential cache matching id %s", req.ResponseCode)
	}

	credential := c.credentialCache.Get(req.ResponseCode).Value()

	reply := &VerificationCallbackResponse{
		CredentialData: credential,
	}

	return reply, nil
}
