package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/pkg/openid4vp"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// performPresentationInteraction answers an
// urn:openid:dcp:ia:openid4vp_presentation challenge and returns the
// openid4vp_response parameter to send back.
//
// The request arrives inside the 403 rather than at a request_uri, in the
// Digital Credentials API shape (signed, so it comes as a "request"
// member holding a JWT). The response goes back to the same Authorization
// Challenge Endpoint instead of to a response_uri, which is the whole of
// what ia_post.jwt means.
func (c *Client) performPresentationInteraction(ctx context.Context, challengeEndpoint string, resp *challengeResponse, vci *config.VCIScenario, result *ScenarioResult) (string, error) {
	step := StepResult{Name: "openid4vp_presentation", StartedAt: time.Now()}
	defer func() {
		step.CompletedAt = time.Now()
		result.Steps = append(result.Steps, step)
	}()

	ro, err := c.parseInteractiveAuthorizationRequest(resp.OpenID4VPRequest)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	// The audience a Key Binding JWT must carry is not the client_id it
	// would be for an ordinary Verifier: OpenID4VCI 1.1 binds it to the
	// Authorization Challenge Endpoint, prefixed, so that a presentation
	// made for one Authorization Server cannot be relayed to another.
	//
	// Which of two readings is right is openid/OpenID4VCI#812 - the
	// normative sentence says the derived Origin, its own example shows
	// the endpoint URL. This wallet follows the sentence, as WE BUILD
	// CS-01 does.
	audience, err := interactiveAuthorizationAudience(challengeEndpoint)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	credentials, err := c.selectCredentialsForRequest(ctx, ro, vci)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	vpToken, err := c.buildIAVPToken(ctx, credentials, ro, audience)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	payload := map[string]any{
		"vp_token": map[string]any{credentialQueryID(ro): []string{vpToken}},
		"state":    ro.State,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	// ia_post.jwt: the response is encrypted to the key the request
	// advertised. Unencrypted ia_post is not attempted even when a server
	// would accept it - the response travels back through this wallet and
	// then through a form parameter, and downgrading it silently would
	// make a test run prove less than it appears to.
	encrypted, err := encryptToRequestKey(ro, raw)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	envelope, err := json.Marshal(map[string]string{"response": encrypted})
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	step.Detail = fmt.Sprintf("audience=%s credentials=%d", audience, len(credentials))
	return string(envelope), nil
}

// parseInteractiveAuthorizationRequest reads the openid4vp_request member.
//
// It carries either a signed request as {"request": "<jwt>"} or the
// parameters inline. Both are accepted: the draft permits either, and a
// test wallet that handled only one would report an issuer's valid choice
// as a failure.
func (c *Client) parseInteractiveAuthorizationRequest(raw json.RawMessage) (*openid4vp.RequestObject, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("the challenge required a presentation but carried no openid4vp_request")
	}

	var signed struct {
		Request string `json:"request"`
	}
	if err := json.Unmarshal(raw, &signed); err == nil && signed.Request != "" {
		// Not verified here: this wallet has no trust anchor for the
		// issuer's request-signing key, and a test wallet that refused
		// everything it could not verify could not be pointed at a new
		// deployment at all. A production wallet MUST verify it - that is
		// what expected_origins and the signature are for.
		claims := jwtv5.MapClaims{}
		if _, _, err := jwtv5.NewParser().ParseUnverified(signed.Request, claims); err != nil {
			return nil, fmt.Errorf("parsing the signed openid4vp_request: %w", err)
		}
		body, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		ro := &openid4vp.RequestObject{}
		if err := json.Unmarshal(body, ro); err != nil {
			return nil, fmt.Errorf("reading the signed openid4vp_request: %w", err)
		}
		return ro, nil
	}

	ro := &openid4vp.RequestObject{}
	if err := json.Unmarshal(raw, ro); err != nil {
		return nil, fmt.Errorf("reading the openid4vp_request: %w", err)
	}
	return ro, nil
}

// interactiveAuthorizationAudience is what a Key Binding JWT presented to
// an Authorization Challenge Endpoint must be addressed to: the "ia:"
// prefix followed by the endpoint's derived Origin (RFC 6454 §4).
func interactiveAuthorizationAudience(challengeEndpoint string) (string, error) {
	origin, err := openid4vp.CanonicalOrigin(challengeEndpoint)
	if err != nil {
		return "", fmt.Errorf("deriving the challenge endpoint origin: %w", err)
	}
	return "ia:" + origin, nil
}

// credentialQueryID is the key the vp_token map is keyed by: the id of
// the DCQL credential query being answered.
func credentialQueryID(ro *openid4vp.RequestObject) string {
	if ro.DCQLQuery != nil && len(ro.DCQLQuery.Credentials) > 0 {
		return ro.DCQLQuery.Credentials[0].ID
	}
	return "credential"
}

// encryptToRequestKey encrypts the response to the key the request
// advertised in client_metadata.jwks, as Section 8.3 of OpenID4VP
// requires for an encrypted response mode.
func encryptToRequestKey(ro *openid4vp.RequestObject, payload []byte) (string, error) {
	if ro.ClientMetadata == nil || ro.ClientMetadata.JWKS == nil || len(ro.ClientMetadata.JWKS.Keys) == 0 {
		return "", fmt.Errorf("the request asked for an encrypted response but advertised no encryption key")
	}

	key := ro.ClientMetadata.JWKS.Keys[0]
	public, err := publicOf(key)
	if err != nil {
		return "", err
	}

	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.ECDH_ES(), public),
		jwe.WithContentEncryption(jwa.A256GCM()))
	if err != nil {
		return "", fmt.Errorf("encrypting the openid4vp response: %w", err)
	}
	return string(encrypted), nil
}

// publicOf returns the public half of an advertised key, which is what it
// should already be - a request that advertised a private key is a server
// bug worth not propagating.
func publicOf(key jwk.Key) (jwk.Key, error) {
	public, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("deriving the public encryption key: %w", err)
	}
	return public, nil
}

// selectCredentialsForRequest picks what to present.
//
// Reuses the VP scenario's selection so that a credential presented to an
// Issuer and one presented to a Verifier are chosen the same way; the
// scenario may name one explicitly.
func (c *Client) selectCredentialsForRequest(ctx context.Context, ro *openid4vp.RequestObject, vci *config.VCIScenario) ([]string, error) {
	scenario := &config.VPScenario{}
	if vci.PresentCredential != "" {
		scenario.SendCredentialIDs = []string{vci.PresentCredential}
	}
	return c.selectCredentials(ctx, scenario, ro)
}

// buildIAVPToken builds the VP token with the Interactive Authorization
// audience rather than the request's client_id.
func (c *Client) buildIAVPToken(ctx context.Context, credentials []string, ro *openid4vp.RequestObject, audience string) (string, error) {
	// buildVPToken binds the Key Binding JWT to ro.ClientID. For this
	// flow the audience is the prefixed challenge endpoint instead, so
	// the request object is copied with that substituted rather than
	// duplicating the token-building logic.
	bound := *ro
	bound.ClientID = audience
	return c.buildVPToken(ctx, credentials, &bound, &config.VPScenario{})
}
