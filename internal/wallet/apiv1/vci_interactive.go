package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/wallet/config"

	"github.com/google/uuid"
)

// The interaction types OpenID4VCI 1.1 defines, under the spellings its
// normative text uses. The change log records an "iae" namespace its own
// normative sections do not apply (openid/OpenID4VCI#811); a wallet that
// has to interoperate either way reads what the server sends it and
// offers what it can actually do.
const (
	interactionOpenID4VPPresentation = "urn:openid:dcp:ia:openid4vp_presentation"
	interactionAuthViaWeb            = "urn:openid:dcp:ia:auth_via_web"
)

// challengeResponse is what the Authorization Challenge Endpoint answers
// with: an authorization code when the exchange is finished, or the next
// interaction when it is not.
type challengeResponse struct {
	AuthorizationCode string `json:"authorization_code"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`

	InteractionTypeRequired string          `json:"interaction_type_required"`
	AuthSession             string          `json:"auth_session"`
	OpenID4VPRequest        json.RawMessage `json:"openid4vp_request"`
	RequestURI              string          `json:"request_uri"`
	ExpiresIn               int             `json:"expires_in"`
}

// doInteractiveAuthorization runs an OpenID4VCI 1.1 Interactive
// Authorization exchange and returns the authorization code it ends with.
//
// The loop is the specification's own shape: ask, be told what interaction
// is required, perform it, ask again. It is bounded because a server that
// keeps asking for interactions is a server this wallet cannot finish with,
// and a test wallet that spins forever reports nothing useful.
func (c *Client) doInteractiveAuthorization(ctx context.Context, meta *oauth2ServerMetadata, vci *config.VCIScenario, flow *vciFlow, result *ScenarioResult) (string, error) {
	endpoint := meta.challengeEndpoint()
	if endpoint == "" {
		return "", fmt.Errorf("issuer does not advertise an authorization challenge endpoint")
	}

	form := url.Values{
		"response_type":               {"code"},
		"client_id":                   {c.cfg.Wallet.ClientID},
		"interaction_types_supported": {strings.Join(c.offeredInteractionTypes(vci), ",")},
	}
	if flow.scope != "" {
		form.Set("scope", flow.scope)
	}
	// Always, and the same value the Token Endpoint will be given. The
	// Authorization Server validates it against what this client is
	// registered with, so omitting it here while sending it there meant
	// the exchange was refused before a challenge was ever issued.
	form.Set("redirect_uri", redirectURIFor(vci))
	if flow.issuerState != "" {
		form.Set("issuer_state", flow.issuerState)
	}

	// PKCE always. The code this exchange ends with is redeemed on a
	// separate connection, and the Security BCP allows only S256.
	verifier := uuid.New().String() + uuid.New().String()
	flow.codeVerifier = verifier
	form.Set("code_challenge", computeS256Challenge(verifier))
	form.Set("code_challenge_method", "S256")

	const maxInteractions = 4
	for attempt := range maxInteractions {
		step := StepResult{Name: fmt.Sprintf("authorization_challenge_%d", attempt+1), StartedAt: time.Now()}
		resp, err := c.postChallenge(ctx, endpoint, form)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			return "", err
		}

		if resp.AuthorizationCode != "" {
			step.Detail = "authorization_code received"
			result.Steps = append(result.Steps, step)
			return resp.AuthorizationCode, nil
		}

		if resp.Error != "insufficient_authorization" {
			step.Error = fmt.Sprintf("%s: %s", resp.Error, resp.ErrorDescription)
			result.Steps = append(result.Steps, step)
			return "", fmt.Errorf("authorization challenge refused: %s", resp.Error)
		}

		step.Detail = fmt.Sprintf("interaction_type_required=%s", resp.InteractionTypeRequired)
		result.Steps = append(result.Steps, step)

		// The next request continues this exchange rather than starting a
		// new one, so it carries auth_session and nothing else from
		// before it.
		form = url.Values{}
		if resp.AuthSession != "" {
			form.Set("auth_session", resp.AuthSession)
		}

		switch resp.InteractionTypeRequired {
		case interactionOpenID4VPPresentation:
			encoded, err := c.performPresentationInteraction(ctx, endpoint, &resp, vci, result)
			if err != nil {
				return "", err
			}
			form.Set("openid4vp_response", encoded)

		case interactionAuthViaWeb:
			// A browser leg this wallet cannot perform: RFC 8252 §8.12
			// requires an external user-agent, and driving one is not
			// something a headless test wallet should pretend to do. The
			// request_uri is reported so a scenario can assert the issuer
			// offered it correctly.
			return "", fmt.Errorf("issuer requires %s, which this wallet does not perform (request_uri=%s, expires_in=%d)",
				resp.InteractionTypeRequired, resp.RequestURI, resp.ExpiresIn)

		default:
			return "", fmt.Errorf("issuer requires interaction type %q, which this wallet did not offer",
				resp.InteractionTypeRequired)
		}

		// PKCE travels with the exchange, not with each request; the
		// code_verifier is presented at the Token Endpoint.
	}

	return "", fmt.Errorf("authorization challenge did not finish within %d interactions", maxInteractions)
}

// offeredInteractionTypes is what this wallet claims it can perform.
//
// The default is the one it actually implements. A scenario may override
// it to drive an issuer's missing_interaction_type path, which has no
// other way to be reached.
func (c *Client) offeredInteractionTypes(vci *config.VCIScenario) []string {
	if len(vci.InteractionTypes) > 0 {
		return vci.InteractionTypes
	}
	return []string{interactionOpenID4VPPresentation}
}

// postChallenge sends one Authorization Challenge Request.
//
// Both the success and the interaction-required answers are JSON bodies
// that this wallet has to read, so the HTTP status is not what decides:
// a 403 carrying insufficient_authorization is the flow working.
func (c *Client) postChallenge(ctx context.Context, endpoint string, form url.Values) (challengeResponse, error) {
	var parsed challengeResponse

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return parsed, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// The exchange is bound to this key: OpenID4VCI 1.1 requires
	// auth_session to be associated with the DPoP public key wherever
	// DPoP-bound codes or tokens are used, and they always are here.
	proof, err := c.createDPoPProof(http.MethodPost, endpoint, "")
	if err != nil {
		return parsed, fmt.Errorf("creating DPoP proof for the challenge endpoint: %w", err)
	}
	req.Header.Set("DPoP", proof)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return parsed, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return parsed, fmt.Errorf("decoding authorization challenge response (HTTP %d): %w", resp.StatusCode, err)
	}
	return parsed, nil
}

// ErrInvalidTXCode is the Transaction Code error OpenID4VCI 1.1 added.
//
// A sentinel because the whole value of the new code is that a wallet can
// act differently on it: 1.0 answered invalid_grant for both a mistyped
// code and an offer that is already finished, so the Holder was told the
// same thing whether or not trying again could work.
var ErrInvalidTXCode = errors.New("invalid_tx_code")
