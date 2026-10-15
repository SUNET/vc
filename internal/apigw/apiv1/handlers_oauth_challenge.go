package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

// AuthorizationChallengeRequest is a request to the Authorization Challenge
// Endpoint: draft-ietf-oauth-first-party-apps §5.1, plus the parameters
// OpenID4VCI 1.1 adds for Interactive Authorization.
//
// One struct for both shapes the endpoint takes. The initial request
// describes the authorization being asked for; every later one carries
// auth_session and whatever the interaction the server asked for produces.
// AuthSession is what tells them apart.
type AuthorizationChallengeRequest struct {
	// ResponseType is REQUIRED on the initial request and MUST be "code"
	// (draft-ietf-oauth-first-party-apps §5.1).
	ResponseType string `json:"response_type" form:"response_type"`

	ClientID    string `json:"client_id" form:"client_id"`
	Scope       string `json:"scope" form:"scope"`
	RedirectURI string `json:"redirect_uri" form:"redirect_uri"`

	CodeChallenge       string `json:"code_challenge" form:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method" form:"code_challenge_method"`

	// InteractionTypesSupported is the comma-separated list of interaction
	// type URNs the Wallet implements (OpenID4VCI 1.1, Initial Request).
	// REQUIRED on the initial request; the order carries no meaning.
	InteractionTypesSupported string `json:"interaction_types_supported" form:"interaction_types_supported"`

	// AuthSession ties this request to an exchange already under way. Its
	// presence is what makes a request an intermediate one.
	AuthSession string `json:"auth_session" form:"auth_session"`

	// OpenID4VPResponse is the JSON-encoded OpenID4VP Authorization
	// Response - or Authorization Error Response - answering a Require
	// Presentation interaction.
	OpenID4VPResponse string `json:"openid4vp_response" form:"openid4vp_response"`

	// ClientAssertion is the legacy form-body carrier for a Wallet
	// Attestation, accepted without a PoP where the headers are absent.
	ClientAssertion string `json:"client_assertion" form:"client_assertion"`

	// Lifted from headers by the transport layer, which is the only way
	// they are ever set.
	//
	// header:"-" matters: gin's header binder falls back to the FIELD NAME
	// when a struct has no header tag, and "DPOP" happens to canonicalise
	// to the same key as the DPoP header - so without it one of these
	// three arrives by coincidence and the other two do not, and a
	// transport layer that stopped lifting them would look like it still
	// worked.
	ClientAttestation    string `json:"-" form:"-" header:"-"`
	ClientAttestationPoP string `json:"-" form:"-" header:"-"`
	DPOP                 string `json:"-" form:"-" header:"-"`
}

// AuthorizationChallengeResponse is the Authorization Code Response of
// draft-ietf-oauth-first-party-apps §5.2.1: the end of a successful
// exchange, redeemed at the Token Endpoint like any other code.
type AuthorizationChallengeResponse struct {
	AuthorizationCode string `json:"authorization_code"`
}

// AuthorizationChallengeError is an Authorization Challenge Endpoint error
// response. It is a distinct type from oauth2.OAuthError because the
// Interaction Required Response carries three members beyond the OAuth 2.0
// pair, and they are the entire content of the message that drives the flow
// forward - a generic error renderer would drop them.
//
// The member carrying the error code is "error". OpenID4VCI 1.1's prose for
// the Interaction Required Response says "error_code", which neither its own
// examples nor draft-ietf-oauth-first-party-apps use; reported as part of
// WE BUILD CS-01.
type AuthorizationChallengeError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`

	// InteractionTypeRequired names the interaction the Wallet must now
	// perform. Always one of the types the Wallet said it supports.
	InteractionTypeRequired string `json:"interaction_type_required,omitempty"`

	// AuthSession is the handle the Wallet must send back.
	AuthSession string `json:"auth_session,omitempty"`

	// OpenID4VPRequest is the Require Presentation interaction's payload:
	// an OpenID4VP Authorization Request in the Digital Credentials API
	// shape. Raw JSON because it is produced by openid4vp, not by this
	// package, and must reach the Wallet byte for byte.
	OpenID4VPRequest json.RawMessage `json:"openid4vp_request,omitempty"`

	// HTTPStatus is the status the transport layer must answer with: 403
	// for an Interaction Required Response, and whatever the error calls
	// for otherwise.
	HTTPStatus int `json:"-"`

	// Cause is what actually went wrong, for the log. Never serialised:
	// the reasons distinguished here are not the caller's to probe.
	Cause error `json:"-"`
}

func (e *AuthorizationChallengeError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorCode + ": " + e.ErrorDescription
	}
	return e.ErrorCode
}

// Unwrap exposes the cause to errors.Is and errors.As without putting it
// anywhere a caller can read.
func (e *AuthorizationChallengeError) Unwrap() error { return e.Cause }

// The error codes this endpoint answers with beyond the OAuth 2.0 set.
const (
	// errInsufficientAuthorization is the Interaction Required Response's
	// code (draft-ietf-oauth-first-party-apps §5.2.2).
	errInsufficientAuthorization = "insufficient_authorization"

	// errMissingInteractionType says the Wallet's
	// interaction_types_supported does not include a type this server
	// needs to finish the authorization (OpenID4VCI 1.1, Authorization
	// Challenge Error Response).
	errMissingInteractionType = "missing_interaction_type"

	// errInvalidSession says the auth_session is unknown, expired or
	// revoked (draft-ietf-oauth-first-party-apps §5.2.2).
	//
	// Not invalid_grant, which is the Token Endpoint's code for a spent
	// authorization code. A wallet reading this endpoint's contract looks
	// for invalid_session to decide that its exchange is over and a new
	// challenge is needed; told invalid_grant instead, it has no defined
	// way to recognise the condition.
	errInvalidSession = "invalid_session"
)

// invalidSession is the answer to an auth_session this endpoint cannot
// continue. The cause is carried for the log and never for the wallet:
// "no such handle", "already claimed" and "expired" must not be
// distinguishable from outside, or the endpoint becomes an oracle for
// which auth_session values exist.
func invalidSession(cause error) *AuthorizationChallengeError {
	return &AuthorizationChallengeError{
		ErrorCode:        errInvalidSession,
		ErrorDescription: "auth_session is invalid or has expired",
		HTTPStatus:       400,
		Cause:            cause,
	}
}

// OAuthAuthorizationChallenge is the Authorization Challenge Endpoint.
//
// It is an alternative front door to /op/par + /authorize: instead of
// sending the user to a browser, the Wallet asks for authorization, is told
// what further interaction is required, performs it, and asks again, until
// it is handed an authorization code. This build implements one interaction
// type, urn:openid:dcp:ia:openid4vp_presentation - the Wallet presents a
// Credential and the Issuer, acting as a Verifier, consumes it through the
// same pipeline the browser-mediated flow uses.
//
// Errors carrying the interaction come back as *AuthorizationChallengeError,
// which the transport layer renders itself; everything else is an ordinary
// oauth2.OAuthError.
func (c *Client) OAuthAuthorizationChallenge(ctx context.Context, req *AuthorizationChallengeRequest) (*AuthorizationChallengeResponse, error) {
	ia := &c.cfg.APIGW.Delivery.InteractiveAuthorization
	if !ia.Enabled() {
		// Not configured means the endpoint is not advertised, so nothing
		// conformant reaches it. 404 rather than an OAuth error: there is
		// no Authorization Server here to have refused anything.
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"interactive authorization is not enabled on this server", 404)
	}

	if req.AuthSession != "" {
		return c.authorizationChallengeIntermediate(ctx, ia, req)
	}
	return c.authorizationChallengeInitial(ctx, ia, req)
}

// authorizationChallengeInitial handles the first request of an exchange: it
// authenticates the Wallet, works out which interaction the requested scope
// needs, and answers with an Interaction Required Response.
//
// It never returns an authorization code. Every scope this endpoint serves
// needs the Holder to be established first, and a code handed out before
// that would authorize an issuance nobody authenticated.
func (c *Client) authorizationChallengeInitial(ctx context.Context, ia *model.InteractiveAuthorization, req *AuthorizationChallengeRequest) (*AuthorizationChallengeResponse, error) {
	if req.ResponseType != "code" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			`response_type must be "code"`, 400)
	}
	if req.Scope == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"scope is required", 400)
	}
	if req.InteractionTypesSupported == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"interaction_types_supported is required", 400)
	}

	oauthClient, err := c.authenticateOAuthClient(ctx, &walletClientAuth{
		ClientID:             req.ClientID,
		RedirectURI:          req.RedirectURI,
		RedirectOptional:     true,
		Scope:                req.Scope,
		ClientAttestation:    req.ClientAttestation,
		ClientAttestationPoP: req.ClientAttestationPoP,
		ClientAssertion:      req.ClientAssertion,
		LogPrefix:            "CHALLENGE",
	})
	if err != nil {
		return nil, err
	}

	// PKCE on a public client, for the same reason the Token Endpoint
	// insists on it: the code this exchange ends with is redeemed over a
	// channel this endpoint cannot see.
	if oauthClient != nil && oauthClient.Type == oauth2.ClientTypePublic && req.CodeChallenge == "" {
		return nil, oauth2.OAuthErrPKCERequired
	}

	// S256 and nothing else, checked HERE because this is the only place
	// that can: oauth2.ValidatePKCE derives the challenge with
	// CreateCodeChallenge, which treats every method it does not recognise
	// as plain. So an unsupported - or empty - method stored now becomes a
	// plain comparison at redemption, where the challenge is its own
	// verifier and PKCE protects nothing. The metadata this server
	// publishes advertises S256 alone, and the Security BCP forbids plain
	// for a public client, so there is nothing to accept here but S256.
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "S256" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"code_challenge_method must be S256", 400)
	}

	// Which interaction this scope needs is a property of how the scope is
	// sourced, not of what the Wallet offered: a scope whose Holder is
	// established by a presentation needs openid4vp_presentation, and one
	// behind SAML or OIDC needs a web step. Decide first, then check the
	// Wallet can do it - so a Wallet that cannot is told which type is
	// missing rather than which it should have sent.
	required, err := c.interactionTypeForScope(ia, req.Scope)
	if err != nil {
		return nil, err
	}
	if !interactionTypeOffered(req.InteractionTypesSupported, required) {
		return nil, &AuthorizationChallengeError{
			ErrorCode: errMissingInteractionType,
			ErrorDescription: fmt.Sprintf(
				"interaction_types_supported in the request is missing the required interaction type %q", required),
			HTTPStatus: 400,
		}
	}

	source, err := c.openID4VPCredentialSource(req.Scope)
	if err != nil {
		return nil, err
	}

	// DPoP is REQUIRED, not merely honoured when offered.
	//
	// OpenID4VCI 1.1 §5.2 says the auth_session MUST be associated with
	// the DPoP public key where DPoP-bound codes or access tokens are in
	// use - and they always are here, because this server's Token Endpoint
	// refuses an authorization_code request without a proof. So an
	// exchange opened without one could never be redeemed anyway, and in
	// the meantime its auth_session would be a bearer handle: anyone who
	// learned it could continue the exchange under their own key.
	if req.DPOP == "" {
		return nil, oauth2.OAuthErrDPoPRequired
	}
	dpopThumbprint, err := c.dpopProofThumbprint(ctx, req.DPOP, ia.ChallengeEndpoint(c.cfg.APIGW.PublicURL))
	if err != nil {
		return nil, err
	}

	authCtx, err := c.newChallengeAuthContext(ia, req, source)
	if err != nil {
		return nil, err
	}
	authCtx.AuthSessionDPoPThumbprint = dpopThumbprint

	dcql, err := c.issuanceAuthDCQL(req.Scope)
	if err != nil {
		return nil, err
	}
	authCtx.DCQLQuery = dcql

	if err := c.cacheService.AuthContext.Save(ctx, authCtx); err != nil {
		return nil, err
	}

	presentationRequest, err := c.interactiveAuthorizationRequest(ctx, ia, authCtx, dcql)
	if err != nil {
		return nil, err
	}

	c.log.Info("CHALLENGE: interaction required",
		"client_id", req.ClientID, "scope", req.Scope,
		"interaction_type_required", required, "session_id", authCtx.SessionID)

	return nil, &AuthorizationChallengeError{
		ErrorCode:               errInsufficientAuthorization,
		InteractionTypeRequired: required,
		AuthSession:             authCtx.AuthSession,
		OpenID4VPRequest:        presentationRequest,
		HTTPStatus:              403,
	}
}

// authorizationChallengeIntermediate handles every request after the first:
// it finds the exchange the auth_session names, consumes whatever the
// interaction produced, and - when that leaves the Holder established -
// hands back the authorization code.
func (c *Client) authorizationChallengeIntermediate(ctx context.Context, ia *model.InteractiveAuthorization, req *AuthorizationChallengeRequest) (*AuthorizationChallengeResponse, error) {
	authCtx, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{AuthSession: req.AuthSession})
	switch {
	case errors.Is(err, cache.ErrNoDocuments), err == nil && authCtx == nil:
		// Unknown and expired are deliberately indistinguishable: telling
		// the two apart turns the endpoint into an oracle for which
		// auth_session values exist.
		return nil, invalidSession(err)
	case err != nil:
		// A store that would not answer is OURS. Reported as a bad
		// session it would tell a wallet to abandon an exchange that is
		// still perfectly good, and a wallet cannot retry what it has
		// been told is dead - so the one outage becomes a lost issuance
		// rather than a slow one.
		return nil, c.authSessionStoreFailure(err, "resolve")
	}
	if authCtx.ExpiresAt > 0 && time.Now().Unix() > authCtx.ExpiresAt {
		return nil, invalidSession(nil)
	}

	// §5.1: a client_id sent alongside an auth_session MUST identify the
	// same client the session was opened for.
	if req.ClientID != "" && req.ClientID != authCtx.WalletClientID {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"client_id does not match the client this auth_session was issued to", 400)
	}

	// The other half of the association made in the initial request. Every
	// exchange is opened with a key, so every continuation needs one - and
	// the same one.
	//
	// The guard on a recorded thumbprint is not a tolerance for exchanges
	// opened without a key: there are none. It is for a context reaching
	// this endpoint that never went through the initial request at all,
	// which must not pass a binding check by having nothing to check.
	if req.DPOP == "" {
		return nil, oauth2.OAuthErrDPoPRequired
	}
	if authCtx.AuthSessionDPoPThumbprint == "" {
		c.log.Error(nil, "CHALLENGE: auth_session resolved a context with no DPoP binding",
			"session_id", authCtx.SessionID)
		return nil, invalidSession(nil)
	}
	thumbprint, err := c.dpopProofThumbprint(ctx, req.DPOP, ia.ChallengeEndpoint(c.cfg.APIGW.PublicURL))
	if err != nil {
		return nil, err
	}
	if thumbprint != authCtx.AuthSessionDPoPThumbprint {
		c.log.Error(nil, "CHALLENGE: DPoP key does not match the one this auth_session is bound to",
			"session_id", authCtx.SessionID)
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidDPoPProof,
			"DPoP key does not match the key this auth_session is bound to", 400)
	}

	if req.OpenID4VPResponse == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response is required", 400)
	}

	// Claim the handle before anything is done with the presentation.
	//
	// Everything above this line is a check on the request; below it the
	// presentation is decrypted, verified and turned into a session with
	// documents attached. Claiming in between is what makes one exchange
	// yield one authorization code: a second request carrying the same
	// auth_session - sequential or concurrent - finds nothing to claim.
	//
	// A failed presentation therefore costs the wallet its exchange and it
	// has to ask for a new challenge. That is deliberate: the nonce is
	// bound to this exchange, so there is no second presentation to make
	// against it, and leaving the handle alive would let an attacker who
	// learned it grind presentations at the endpoint.
	claimed, err := c.cacheService.AuthContext.ClaimAuthSession(ctx, req.AuthSession)
	switch {
	case errors.Is(err, cache.ErrNoDocuments):
		// Nothing left to claim: a concurrent or repeated request took
		// the handle first, which is the one-shot rule working.
		return nil, invalidSession(err)
	case err != nil:
		return nil, c.authSessionStoreFailure(err, "claim")
	}
	authCtx = claimed

	vpResponse, err := c.decodeInteractiveAuthorizationResponse(ctx, authCtx, req.OpenID4VPResponse)
	if err != nil {
		return nil, err
	}

	audience, err := ia.PresentationAudience(c.cfg.APIGW.PublicURL)
	if err != nil {
		return nil, err
	}

	if _, err := c.issuanceAuthPipeline()(ctx, authCtx, vpResponse, issuanceAuthBinding{
		Audience:      audience,
		ExpectedState: authCtx.State,
		// mdoc needs the OpenID4VCI Interactive Authorization handover,
		// which this build does not produce. Left nil so that an mdoc
		// presentation is refused by name rather than verified against the
		// browser flow's session transcript, which would not be the
		// transcript this Wallet signed over.
		MdocSessionTranscript: nil,

		// The whole exchange exists to establish WHO is asking for an
		// issuance, so a check that cannot tell the Holder from someone
		// holding a copy of their credential would not do its job. See
		// issuanceAuthBinding.VerifyHolderBinding.
		VerifyHolderBinding: true,
	}); err != nil {
		return nil, c.interactiveAuthorizationFailure(err)
	}

	c.log.Info("CHALLENGE: authorization complete", "session_id", authCtx.SessionID, "scopes", authCtx.Scopes)

	return &AuthorizationChallengeResponse{AuthorizationCode: authCtx.Code}, nil
}

// newChallengeAuthContext builds the authorization context one Interactive
// Authorization exchange runs on. It is the same context the browser flow
// builds at PAR time - same code, same PKCE binding, same ephemeral key -
// with an auth_session on it instead of a request_uri.
func (c *Client) newChallengeAuthContext(ia *model.InteractiveAuthorization, req *AuthorizationChallengeRequest, source model.CredentialSource) (*cache.AuthorizationContext, error) {
	host, err := helpers.HostFromURL(c.cfg.APIGW.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
	}

	authCtx := &cache.AuthorizationContext{
		SessionID:           uuid.NewString(),
		Code:                uuid.NewString(),
		Scopes:              []string{req.Scope},
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ClientID:            fmt.Sprintf("x509_san_dns:%s", host),
		WalletClientID:      req.ClientID,
		WalletURI:           req.RedirectURI,
		AuthProvider:        model.AuthProviderOpenID4VP,
		DataSource:          string(source.DataSource),
		RemoteName:          source.RemoteName,
		AuthenticSource:     source.AuthenticSource,
		ExpiresAt:           time.Now().Add(ia.AuthSessionTTL()).Unix(),

		// Answerable here and nowhere else. See the field's own comment:
		// the browser-mediated endpoint resolves a context by the same
		// ephemeral key id and does not verify holder binding.
		InteractiveAuthorization: true,
	}

	// 256 bits, which is what the draft's own security considerations ask
	// of a value that is the only thing tying the next request to this
	// exchange.
	if authCtx.AuthSession, err = crypto.GenerateSecureToken(32, 0); err != nil {
		return nil, fmt.Errorf("failed to generate auth_session: %w", err)
	}

	// The exchange mints its own state rather than echoing one the wallet
	// sent: draft-ietf-oauth-first-party-apps defines no state parameter on
	// the Authorization Challenge Request, so there is none to echo - and
	// a request built without one could not be answered at all, because
	// openid4vp.VPResponse refuses a response whose state is missing.
	//
	// It is checked on the way back (issuanceAuthBinding.ExpectedState),
	// which is the half that makes it worth having.
	if authCtx.State, err = crypto.GenerateSecureToken(0, 32); err != nil {
		return nil, fmt.Errorf("failed to generate presentation state: %w", err)
	}
	if authCtx.Nonce, err = crypto.GenerateSecureToken(0, 32); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	if authCtx.EphemeralEncryptionKeyID, err = crypto.GenerateSecureToken(0, 32); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	return authCtx, nil
}

// interactiveAuthorizationRequest builds and signs the OpenID4VP
// Authorization Request that goes into the Interaction Required Response's
// openid4vp_request member.
//
// Signed, and therefore carrying expected_origins. OpenID4VCI 1.1 allows an
// unsigned request here, but the signature plus the origin is what lets the
// Wallet see that the request comes from the server that issued the
// challenge - the defence the draft names against one Authorization Server
// relaying another's challenge to collect Credentials it was not shown.
func (c *Client) interactiveAuthorizationRequest(ctx context.Context, ia *model.InteractiveAuthorization, authCtx *cache.AuthorizationContext, dcql *openid4vp.DCQL) (json.RawMessage, error) {
	base, err := c.buildIssuanceAuthRequestObject(ctx, authCtx, dcql)
	if err != nil {
		return nil, err
	}

	origin, err := ia.ChallengeEndpointOrigin(c.cfg.APIGW.PublicURL)
	if err != nil {
		return nil, err
	}

	signed, err := base.WithInteractiveAuthorization(ia.ResponseMode(), origin).Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		c.log.Error(err, "failed to sign interactive authorization request")
		return nil, err
	}

	return json.Marshal(map[string]string{"request": signed})
}

// decodeInteractiveAuthorizationResponse reads the openid4vp_response
// parameter: a JSON object holding either an OpenID4VP Authorization
// Response or an Authorization Error Response.
func (c *Client) decodeInteractiveAuthorizationResponse(ctx context.Context, authCtx *cache.AuthorizationContext, raw string) (*openid4vp.VPResponse, error) {
	var envelope struct {
		Response         string          `json:"response"`
		Error            string          `json:"error"`
		ErrorDescription string          `json:"error_description"`
		VPToken          json.RawMessage `json:"vp_token"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response is not a JSON object", 400, err)
	}

	// The Wallet refused, or could not answer. Its reason is the useful
	// one, so it is passed through rather than replaced with ours.
	if envelope.Error != "" {
		c.log.Info("CHALLENGE: wallet returned an OpenID4VP error",
			"session_id", authCtx.SessionID, "error", envelope.Error)
		return nil, &AuthorizationChallengeError{
			ErrorCode:        envelope.Error,
			ErrorDescription: envelope.ErrorDescription,
			HTTPStatus:       400,
		}
	}

	// The request asked for an encrypted response mode, so an unencrypted
	// one is refused rather than accepted as a convenience: taking it
	// would let anything that can reach this endpoint strip the encryption
	// the Wallet was told to apply.
	if envelope.Response == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response must carry an encrypted response", 400)
	}

	// The key this exchange's request was signed around. Its absence is a
	// cache that lost it, not a wallet that did anything wrong, so it is
	// server_error - and typed, because an untyped error here would leave
	// this endpoint through RegEndpoint's generic envelope instead of the
	// OAuth error response every other answer uses.
	privateEphemeralJWK, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, authCtx.EphemeralEncryptionKeyID)
	if !ok {
		err := fmt.Errorf("ephemeral key %q is not in the cache", authCtx.EphemeralEncryptionKeyID)
		c.log.Error(err, "CHALLENGE: cannot decrypt the response without the key the request was built with",
			"session_id", authCtx.SessionID)
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
			"interactive authorization could not be completed", 500, err)
	}

	decrypted, err := jwe.Decrypt([]byte(envelope.Response), jwe.WithKey(jwa.ECDH_ES(), privateEphemeralJWK))
	if err != nil {
		c.log.Error(err, "CHALLENGE: failed to decrypt openid4vp_response")
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response could not be decrypted", 400, err)
	}

	vpResponse := &openid4vp.VPResponse{}
	if err := json.Unmarshal(decrypted, vpResponse); err != nil {
		c.log.Error(err, "CHALLENGE: failed to unmarshal decrypted openid4vp_response")
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response is not an OpenID4VP Authorization Response", 400, err)
	}

	return vpResponse, nil
}

// authSessionStoreFailure is the answer to an authorization-context store
// that would not answer, as distinct from one that answered "no such
// handle". Both are failures of the same call; only one is the wallet's
// problem, and only one is worth retrying.
func (c *Client) authSessionStoreFailure(err error, op string) error {
	c.log.Error(err, "CHALLENGE: the authorization context store failed", "operation", op)
	return oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
		"interactive authorization could not be completed", 500, err)
}

// interactiveAuthorizationFailure turns a presentation failure into the
// answer this endpoint is contracted to give.
//
// Everything here is JSON with an "error" member, so an untyped error
// would reach the wallet through the generic envelope as a 500 - telling a
// wallet whose presentation simply did not verify that the server broke,
// and inviting it to retry something that can never succeed.
//
// Three cases, in the order they are decided:
//
//   - an error that already knows what it is passes through;
//   - one the pipeline marked as ours becomes server_error, because it is;
//   - everything else is invalid_grant. The presentation is the grant
//     material at this endpoint, so a presentation that did not satisfy the
//     request is precisely an invalid grant.
//
// The cause is wrapped in every case and never put in the description: the
// wallet is told its presentation was not accepted, and the reason goes to
// the log, because the reasons here distinguish "this credential is not
// trusted" from "no documents for this person" and that difference is not
// the caller's to probe.
func (c *Client) interactiveAuthorizationFailure(err error) error {
	var oauthErr *oauth2.OAuthError
	if errors.As(err, &oauthErr) {
		return err
	}

	if errors.Is(err, ErrIssuanceAuthServerFault) {
		c.log.Error(err, "CHALLENGE: interactive authorization failed on the server side")
		return oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
			"interactive authorization could not be completed", 500, err)
	}

	c.log.Info("CHALLENGE: presentation did not satisfy the request", "reason", err)
	return oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidGrant,
		"the presentation did not satisfy the authorization request", 400, err)
}

// issuanceAuthDCQL builds the DCQL query the Wallet must satisfy for scope.
func (c *Client) issuanceAuthDCQL(scope string) (*openid4vp.DCQL, error) {
	vpAuth := c.cfg.GetOpenID4VPAuth(scope)
	if vpAuth == nil {
		return nil, fmt.Errorf("scope %q is not configured for openid4vp authentication", scope)
	}
	return buildIssuanceAuthDCQL(vpAuth, c.cfg)
}

// openID4VPCredentialSource finds the data source that backs scope through
// an OpenID4VP presentation. It is the Selector's choice made explicit:
// Interactive Authorization is presentation-based by construction, so the
// openid4vp source is the one this exchange runs on and a scope without one
// cannot be served here at all.
func (c *Client) openID4VPCredentialSource(scope string) (model.CredentialSource, error) {
	sources, err := c.cfg.LookupCredentialSources(scope)
	if err != nil {
		return model.CredentialSource{}, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidScope,
			fmt.Sprintf("scope %q is not configured", scope), 400, err)
	}
	for _, source := range sources {
		if source.AuthProvider == model.AuthProviderOpenID4VP {
			return source, nil
		}
	}
	return model.CredentialSource{}, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidScope,
		fmt.Sprintf("scope %q is not authenticated by an openid4vp presentation", scope), 400,
		errScopeNotPresentationBacked)
}

// errScopeNotPresentationBacked marks the one lookup failure that is about
// the INTERACTION rather than the scope: a scope this server knows, whose
// Holder is established some other way.
//
// The distinction is the whole of the difference between the two errors
// this endpoint can give. A scope it has never heard of is invalid_scope,
// and no interaction would help. A scope it knows but authenticates in a
// browser is missing_interaction_type, naming the interaction a wallet
// would need - and telling a wallet that about a scope that does not exist
// invites it to implement auth_via_web and come back to the same refusal.
var errScopeNotPresentationBacked = errors.New("scope is not backed by an openid4vp presentation")

// interactionTypeForScope names the interaction this server needs in order
// to authorize an issuance of scope.
//
// A scope backed by an OpenID4VP source needs a presentation. Anything else
// is established in a browser, which is auth_via_web - named here, and
// refused, rather than silently unsupported, so that a Wallet that offered
// it learns the server is the side that cannot.
func (c *Client) interactionTypeForScope(ia *model.InteractiveAuthorization, scope string) (string, error) {
	if _, err := c.openID4VPCredentialSource(scope); err != nil {
		if !errors.Is(err, errScopeNotPresentationBacked) {
			// The scope itself is the problem - it is not configured
			// here at all - and invalid_scope is what says so.
			return "", err
		}
		return "", &AuthorizationChallengeError{
			ErrorCode: errMissingInteractionType,
			ErrorDescription: fmt.Sprintf("scope %q requires the %s interaction, which this server does not implement",
				scope, ia.InteractionType(model.InteractionAuthViaWeb)),
			HTTPStatus: 400,
		}
	}

	suffix := model.InteractionOpenID4VPPresentation
	if !ia.Offers(suffix) {
		return "", &AuthorizationChallengeError{
			ErrorCode: errMissingInteractionType,
			ErrorDescription: fmt.Sprintf("this server is not configured to offer the %s interaction",
				ia.InteractionType(suffix)),
			HTTPStatus: 400,
		}
	}
	return ia.InteractionType(suffix), nil
}

// interactionTypeOffered reports whether the Wallet's comma-separated
// interaction_types_supported names required.
//
// Whitespace around a value is tolerated. The parameter is comma-separated
// rather than the space-separated form OAuth usually uses for lists, which
// is easy to get wrong on the sending side, and an interaction type URN can
// contain neither a comma nor a space - so splitting on both cannot merge
// two values or split one.
func interactionTypeOffered(supported, required string) bool {
	for _, field := range strings.FieldsFunc(supported, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		if field == required {
			return true
		}
	}
	return false
}
