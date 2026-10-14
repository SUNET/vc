package apiv1

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
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

	// IssuerState is the handle from an issuer-initiated Credential Offer
	// (OpenID4VCI 1.0 §5.1.1), naming an issuance this server already
	// prepared.
	//
	// Neither draft-ietf-oauth-first-party-apps §5.1 nor the OpenID4VCI
	// 1.1 Interactive Authorization text lists it here: as written, the
	// mechanism is wallet-initiated only, and an Issuer that has already
	// authenticated the user elsewhere has no way to say so. First-party
	// apps explicitly allows extension parameters, and OpenID4VCI defines
	// this one for the Authorization Endpoint, so it is accepted here
	// under the same meaning - reported as openid/OpenID4VCI#815, which
	// also covers the two properties this endpoint gives it that 1.0 does
	// not state: single use, and not coexisting with auth_session.
	IssuerState string `json:"issuer_state" form:"issuer_state"`

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

	// RequestURI is the Authorization via Web interaction's payload: the
	// Wallet builds an authorization request from it (RFC 9126 §4) and
	// opens that in a browser.
	//
	// It takes the place of auth_session for this interaction rather than
	// accompanying it - the request_uri is itself what associates the
	// browser leg with this exchange, and the draft says the response MUST
	// omit auth_session when it is present.
	RequestURI string `json:"request_uri,omitempty"`

	// ExpiresIn bounds the request_uri's life, in seconds.
	ExpiresIn int `json:"expires_in,omitempty"`

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
// being redirected to a browser and finding out there, the Wallet asks for
// authorization, is told what further interaction is required, performs
// it, and asks again, until it is handed an authorization code.
//
// Both interaction types OpenID4VCI 1.1 defines are implemented:
//
//   - urn:openid:dcp:ia:openid4vp_presentation - the Wallet presents a
//     Credential and the Issuer, acting as a Verifier, consumes it through
//     the same pipeline the browser-mediated flow uses. The exchange
//     continues at this endpoint, carrying an auth_session.
//   - urn:openid:dcp:ia:auth_via_web - the Wallet is handed a request_uri
//     and opens a browser with it, which is this server's ordinary PAR
//     flow reached through the challenge endpoint. There is no
//     auth_session and no second request here; the browser leg finishes
//     the authorization and redirects back with the code.
//
// Which of the two a scope requires follows from how the scope is sourced
// - see interactionTypeForScope - not from what the Wallet offered.
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

	// The two handles are mutually exclusive, so a request carrying both
	// is refused rather than resolved by precedence.
	//
	// Preferring auth_session silently accepted an ambiguous request and
	// left the supplied issuer_state live - a prepared issuance still
	// waiting to be claimed, named by a caller who believed it had just
	// been used. A wallet that sends both has a bug, and the useful answer
	// says so at the point it can still be found.
	if req.AuthSession != "" && req.IssuerState != "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"auth_session and issuer_state are mutually exclusive; send one", 400)
	}

	if req.AuthSession != "" {
		return c.authorizationChallengeIntermediate(ctx, ia, req)
	}
	if req.IssuerState != "" {
		return c.authorizationChallengePrepared(ctx, ia, req)
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

	// The same check /op/par makes, for the same reason and in the same
	// place: before either path, and before anything stores the value.
	//
	// A wallet authenticated by attestation has no redirect_uri allowlist
	// to be checked against, so whatever it sends is what gets recorded as
	// WalletURI. The auth_via_web interaction then carries that context
	// into the browser leg, where the consent page renders it as a
	// template.URL - which deliberately disables html/template's own
	// scheme sanitisation, so that custom wallet schemes survive. A
	// "javascript:" value therefore becomes script execution in the
	// APIGW's own origin once the user consents.
	if err := oauth2.ValidateRedirectURIScheme(req.RedirectURI); err != nil {
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest, "invalid redirect_uri", 400, err)
	}

	oauthClient, err := c.authenticateOAuthClient(ctx, &walletClientAuth{
		ClientID:             req.ClientID,
		RedirectURI:          req.RedirectURI,
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

	// A Wallet that OFFERS auth_via_web must send a code_challenge,
	// whichever interaction this server then picks.
	//
	// Checked on what the Wallet advertised rather than on what the server
	// selected, because that is where the draft puts it and because the
	// alternative has a hole: a confidential client listing both
	// interactions and asking for a presentation-backed scope never
	// reaches requireWebInteraction, so the rule there never ran and the
	// exchange was accepted with no PKCE at all. The Wallet has told us it
	// is prepared to be sent into a browser; the code is redeemed over a
	// channel this endpoint cannot see either way.
	if req.CodeChallenge == "" &&
		interactionTypeOffered(req.InteractionTypesSupported, ia.InteractionType(model.InteractionAuthViaWeb)) {
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
	required, source, err := c.interactionTypeForScope(ia, req.Scope)
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

	if required == ia.InteractionType(model.InteractionAuthViaWeb) {
		return nil, c.requireWebInteraction(ctx, ia, req, required, dpopThumbprint, source)
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

	vpResponse, privateEphemeralJWK, err := c.decodeInteractiveAuthorizationResponse(ctx, authCtx, req.OpenID4VPResponse)
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
		// mdoc binds to the OpenID4VCI Interactive Authorization handover,
		// which is a different transcript from either of the browser
		// flow's - see interactiveAuthorizationSessionTranscript.
		MdocSessionTranscript: c.interactiveAuthorizationSessionTranscript(ia, authCtx, privateEphemeralJWK),

		// The whole exchange exists to establish WHO is asking for an
		// issuance, so a check that cannot tell the Holder from someone
		// holding a copy of their credential would not do its job. See
		// issuanceAuthBinding.VerifyHolderBinding.
		VerifyHolderBinding: true,
	}); err != nil {
		return nil, c.interactiveAuthorizationFailure(err)
	}

	// The auth_session's life ends here; the authorization code's begins.
	//
	// Both are kept in one ExpiresAt, and the Token Endpoint checks that
	// same field - so without this the code a wallet is about to be handed
	// expires whenever the EXCHANGE was going to, however long the
	// presentation actually took. A holder who spent two minutes choosing
	// a credential on a 300-second exchange gets a code with a hundred
	// seconds on it, and at the configured maximum the code and the
	// context expire together.
	//
	// This is the same handover /authorize makes for the browser leg, at
	// the moment the short deadline has done its job, and through the same
	// never-shortening ExtendExpiry - so a presentation that finished
	// early cannot pull the deadline in.
	codeExpiresAt := codeDeadlineWithin(authCtx.CreatedAt)
	if err := c.cacheService.AuthContext.ExtendExpiry(ctx,
		&cache.AuthorizationContext{SessionID: authCtx.SessionID}, codeExpiresAt); err != nil {
		c.log.Error(err, "CHALLENGE: failed to start the authorization code's lifetime",
			"session_id", authCtx.SessionID)
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
			"interactive authorization could not be completed", 500, err)
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
func (c *Client) decodeInteractiveAuthorizationResponse(ctx context.Context, authCtx *cache.AuthorizationContext, raw string) (*openid4vp.VPResponse, jwk.Key, error) {
	var envelope struct {
		Response         string          `json:"response"`
		Error            string          `json:"error"`
		ErrorDescription string          `json:"error_description"`
		VPToken          json.RawMessage `json:"vp_token"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return nil, nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response is not a JSON object", 400, err)
	}

	// The Wallet refused, or could not answer. Its reason is the useful
	// one, so it is passed through rather than replaced with ours.
	if envelope.Error != "" {
		c.log.Info("CHALLENGE: wallet returned an OpenID4VP error",
			"session_id", authCtx.SessionID, "error", envelope.Error)
		return nil, nil, &AuthorizationChallengeError{
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
		return nil, nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
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
		return nil, nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
			"interactive authorization could not be completed", 500, err)
	}

	if err := validateInteractiveAuthorizationJWE([]byte(envelope.Response)); err != nil {
		c.log.Error(err, "CHALLENGE: openid4vp_response is not the JWE this request asked for",
			"session_id", authCtx.SessionID)
		return nil, nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response is not encrypted the way the request required", 400, err)
	}

	decrypted, err := jwe.Decrypt([]byte(envelope.Response), jwe.WithKey(jwa.ECDH_ES(), privateEphemeralJWK))
	if err != nil {
		c.log.Error(err, "CHALLENGE: failed to decrypt openid4vp_response")
		return nil, nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response could not be decrypted", 400, err)
	}

	vpResponse := &openid4vp.VPResponse{}
	if err := json.Unmarshal(decrypted, vpResponse); err != nil {
		c.log.Error(err, "CHALLENGE: failed to unmarshal decrypted openid4vp_response")
		return nil, nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest,
			"openid4vp_response is not an OpenID4VP Authorization Response", 400, err)
	}

	return vpResponse, privateEphemeralJWK, nil
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

// interactiveAuthorizationSessionTranscript builds the mdoc
// SessionTranscript a presentation answering this challenge must have been
// signed over (OpenID4VCI 1.1, Interactive Authorization Binding for
// mso_mdoc).
//
// It binds to three things, and each is doing work: the Authorization
// Challenge Endpoint, which is what stops one Authorization Server
// relaying another's challenge; the request nonce, which stops a
// presentation from another exchange being replayed into this one; and the
// thumbprint of the key the response is encrypted to, which does not
// prevent a third party re-encrypting the response but makes it
// detectable.
//
// The endpoint goes in as the plain URL. The same value wears an "ia:"
// prefix when it is an SD-JWT VC audience - there to keep that audience
// out of an ordinary Verifier's namespace - and the draft says explicitly
// that the handover must NOT carry it.
//
// A closure rather than a value because it is only needed when an mdoc
// actually turns up, and deriving the ephemeral public key to thumbprint
// it is not free.
func (c *Client) interactiveAuthorizationSessionTranscript(ia *model.InteractiveAuthorization, authCtx *cache.AuthorizationContext, privateEphemeralJWK jwk.Key) func() ([]byte, error) {
	return func() ([]byte, error) {
		endpoint := ia.ChallengeEndpoint(c.cfg.APIGW.PublicURL)

		ephemeralPublicJWK, err := privateEphemeralJWK.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("derive ephemeral public key: %w", err)
		}
		thumbprint, err := ephemeralPublicJWK.Thumbprint(stdcrypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("compute ephemeral JWK thumbprint: %w", err)
		}

		return mdoc.BuildOID4VCIIAESessionTranscript(ia.HandoverLabel(), endpoint, authCtx.Nonce, thumbprint)
	}
}

// webInteractionTTLSeconds bounds a request_uri's life, matching what
// /op/par hands out for the same artefact - it is the same artefact,
// redeemed at the same endpoint, so it is the same constant.
//
// It bounds the request_uri and nothing else: /authorize extends the
// context to authorizationCodeTTL when it consumes the request_uri, so the
// authorization code this interaction eventually produces is not confined
// to the seconds the wallet had to open a browser.
const webInteractionTTLSeconds = int(requestURITTL / time.Second)

// requireWebInteraction answers an initial request for a scope whose
// Holder is established in a browser.
//
// The Wallet is handed a request_uri and builds an authorization request
// from it (RFC 9126 §4), exactly as it would from /op/par - and that is
// the point: this interaction is the Pushed Authorization Request this
// server already implements, reached through the challenge endpoint
// instead of a separate one. The browser leg, the consent screen and the
// redirect back to the Wallet are unchanged.
//
// It returns NO auth_session, which the draft requires: the request_uri
// is itself what associates the browser leg with this exchange, and two
// handles for one association is one more than can be kept consistent.
//
// There is no intermediate request afterwards either. The draft provides
// for one - the Authorization Server may redirect back with auth_session
// rather than code when the authorization is not yet complete - but this
// server's browser flow finishes the authorization, so it redirects with
// code and the exchange is over. A deployment that grew a second step
// would need the auth_session branch and the code_verifier check that
// goes with it; this returns a code, so PKCE is enforced where it already
// is, at the Token Endpoint.
func (c *Client) requireWebInteraction(ctx context.Context, ia *model.InteractiveAuthorization, req *AuthorizationChallengeRequest, required, dpopThumbprint string, source model.CredentialSource) error {
	// The draft says a Wallet listing auth_via_web includes
	// code_challenge and code_challenge_method in the initial request. It
	// is not optional here for the same reason it is not optional at PAR:
	// the code this produces is redeemed over a channel this endpoint
	// cannot see, and the browser leg in between is the part an attacker
	// can reach.
	if req.CodeChallenge == "" {
		return oauth2.OAuthErrPKCERequired
	}

	authCtx, err := c.newChallengeAuthContext(ia, req, source)
	if err != nil {
		return err
	}

	// The handle this interaction is associated by, instead of an
	// auth_session.
	authCtx.AuthSession = ""

	// The presentation state goes with it. newChallengeAuthContext mints
	// one so an OpenID4VP response has something to echo, and this
	// interaction has no OpenID4VP response: nothing ever tells the Wallet
	// the value, and nothing ever checks it. Left on the context it would
	// be echoed back as `state` in the Token Response - a random value the
	// Wallet never sent, which a Wallet correlating its own OAuth state
	// is entitled to reject. The browser flow leaves this empty when the
	// Wallet sends no state, and so does this.
	authCtx.State = ""
	authCtx.AuthSessionDPoPThumbprint = dpopThumbprint
	authCtx.RequestURI = fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", uuid.NewString())
	authCtx.ExpiresAt = time.Now().Add(requestURITTL).Unix()

	if err := c.cacheService.AuthContext.Save(ctx, authCtx); err != nil {
		return err
	}

	c.log.Info("CHALLENGE: web interaction required",
		"client_id", req.ClientID, "scope", req.Scope,
		"interaction_type_required", required, "session_id", authCtx.SessionID)

	return &AuthorizationChallengeError{
		ErrorCode:               errInsufficientAuthorization,
		InteractionTypeRequired: required,
		RequestURI:              authCtx.RequestURI,
		ExpiresIn:               webInteractionTTLSeconds,
		HTTPStatus:              403,
	}
}

// issuanceAuthDCQL builds the DCQL query the Wallet must satisfy for scope.
func (c *Client) issuanceAuthDCQL(scope string) (*openid4vp.DCQL, error) {
	vpAuth := c.cfg.GetOpenID4VPAuth(scope)
	if vpAuth == nil {
		return nil, fmt.Errorf("scope %q is not configured for openid4vp authentication", scope)
	}
	return buildIssuanceAuthDCQL(vpAuth, c.cfg)
}

// interactionTypeForScope names the interaction this server needs in order
// to authorize an issuance of scope, and the credential source it will run
// on.
//
// It asks the same question /authorize answers, through the same Selector:
// a scope can be backed by several sources, and which one serves it is a
// property of what this deployment actually has running, not of what the
// configuration lists. Deciding it any other way here - "is there an
// openid4vp source anywhere in the list" was the first attempt - makes the
// challenge endpoint demand a presentation for a scope the browser flow
// would have served with OIDC, and auth_via_web then becomes unreachable
// for exactly the deployments that configured both.
//
// A scope the Selector resolves to openid4vp needs the presentation
// interaction; SAML and OIDC are established in a browser, which is what
// auth_via_web is for; a pre-authorised scope is neither, and a Wallet
// cannot initiate that flow at all - which /op/par also refuses.
func (c *Client) interactionTypeForScope(ia *model.InteractiveAuthorization, scope string) (string, model.CredentialSource, error) {
	// Fail closed rather than guess. Without the Selector this endpoint
	// cannot know which provider the browser flow would pick, and the
	// guess it would otherwise make is the bug described above.
	if c.authProviderSelector == nil {
		c.log.Error(nil, "CHALLENGE: no auth provider selector wired; cannot determine the required interaction")
		return "", model.CredentialSource{}, oauth2.NewOAuthError(oauth2.ErrCodeServerError,
			"this server cannot determine the required interaction for the requested scope", 500)
	}

	provider, source, err := c.authProviderSelector.Select(scope, &c.cfg.APIGW.DataSources)
	if err != nil {
		return "", model.CredentialSource{}, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidScope,
			fmt.Sprintf("scope %q has no usable authentication configured", scope), 400, err)
	}

	var suffix string
	switch provider {
	case model.AuthProviderOpenID4VP:
		suffix = model.InteractionOpenID4VPPresentation
	case model.AuthProviderSAML, model.AuthProviderOIDC:
		suffix = model.InteractionAuthViaWeb
	case model.AuthProviderPreAuth:
		return "", model.CredentialSource{}, oauth2.NewOAuthError(oauth2.ErrCodeInvalidScope,
			"scope is issuable only via pre-authorized credential offer", 400)
	default:
		return "", model.CredentialSource{}, oauth2.NewOAuthError(oauth2.ErrCodeInvalidScope,
			fmt.Sprintf("scope %q resolves to auth provider %q, which this endpoint cannot serve", scope, provider), 400)
	}

	if !ia.Offers(suffix) {
		return "", model.CredentialSource{}, &AuthorizationChallengeError{
			ErrorCode: errMissingInteractionType,
			ErrorDescription: fmt.Sprintf("this server is not configured to offer the %s interaction",
				ia.InteractionType(suffix)),
			HTTPStatus: 400,
		}
	}
	return ia.InteractionType(suffix), source, nil
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

// authorizationChallengePrepared opens an exchange against an issuance
// this server already prepared for a known Holder - see PrepareIssuance.
//
// It differs from an ordinary initial request in what it takes from the
// wallet and what it refuses to take. The scope, the data source and the
// identity rule come from the prepared issuance, because the Issuer
// decided those when it authenticated the user and let them choose; a
// wallet that sent its own would be asking to be issued something other
// than what was prepared. What the wallet still supplies is its own half:
// client authentication, PKCE, the DPoP key the exchange binds to, and
// the interaction types it can perform.
func (c *Client) authorizationChallengePrepared(ctx context.Context, ia *model.InteractiveAuthorization, req *AuthorizationChallengeRequest) (*AuthorizationChallengeResponse, error) {
	if req.ResponseType != "code" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest, `response_type must be "code"`, 400)
	}
	if req.InteractionTypesSupported == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"interaction_types_supported is required", 400)
	}

	// Read, not claimed.
	//
	// The issuer_state is the Issuer's handle on an issuance nobody has
	// taken, and taking it is irreversible: a prepared issuance is the
	// product of a user authenticating at a portal and choosing what to be
	// issued, and nothing re-prepares it. So everything that can refuse
	// this request - client authentication, PKCE, the DPoP proof,
	// building and signing the request object - happens while the handle
	// is still resolvable, and it is claimed at the bottom, once there is
	// nothing left that can fail. A malformed request carrying a handle
	// somebody photographed off a screen must not be able to destroy the
	// issuance it names.
	//
	// The claim at the bottom is what makes it one-shot: two wallets
	// scanning the same offer both reach it, and exactly one wins.
	authCtx, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{IssuerState: req.IssuerState})
	if err != nil || authCtx == nil {
		// Unknown and expired are one answer, for the same reason they are
		// at the intermediate request: otherwise the endpoint reports
		// which issuer_state values exist.
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
			"issuer_state is invalid or has expired", 400)
	}
	if authCtx.ExpiresAt > 0 && time.Now().Unix() > authCtx.ExpiresAt {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
			"issuer_state is invalid or has expired", 400)
	}

	// The prepared issuance names the scope; a wallet asking for a
	// different one is refused rather than quietly served the prepared
	// one, so that a mismatch is visible to whoever wrote the wallet.
	scope := authCtx.Scopes[0]
	if req.Scope != "" && req.Scope != scope {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidScope,
			"scope does not match the issuance this issuer_state was prepared for", 400)
	}

	oauthClient, err := c.authenticateOAuthClient(ctx, &walletClientAuth{
		ClientID:             req.ClientID,
		RedirectURI:          req.RedirectURI,
		Scope:                scope,
		ClientAttestation:    req.ClientAttestation,
		ClientAttestationPoP: req.ClientAttestationPoP,
		ClientAssertion:      req.ClientAssertion,
		LogPrefix:            "CHALLENGE",
	})
	if err != nil {
		return nil, err
	}
	if oauthClient != nil && oauthClient.Type == oauth2.ClientTypePublic && req.CodeChallenge == "" {
		return nil, oauth2.OAuthErrPKCERequired
	}
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "S256" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest,
			"code_challenge_method must be S256", 400)
	}

	// The source is not taken from here: a prepared issuance recorded its
	// own at preparation time, and that is the one this exchange runs on.
	required, _, err := c.interactionTypeForScope(ia, scope)
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

	if req.DPOP == "" {
		return nil, oauth2.OAuthErrDPoPRequired
	}
	dpopThumbprint, err := c.dpopProofThumbprint(ctx, req.DPOP, ia.ChallengeEndpoint(c.cfg.APIGW.PublicURL))
	if err != nil {
		return nil, err
	}

	// From here the exchange is the wallet's, identified by auth_session.
	authSession, err := crypto.GenerateSecureToken(32, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth_session: %w", err)
	}

	dcql, err := c.issuanceAuthDCQL(scope)
	if err != nil {
		return nil, err
	}

	// Built BEFORE the handle is claimed, and against the context as read:
	// signing can fail, and a signing failure that had already consumed
	// the issuer_state would destroy the issuance over a server-side
	// problem the wallet did nothing to cause. Nothing below this line
	// reads a field the claim changes - the state, nonce and ephemeral key
	// were all minted at preparation time.
	authCtx.DCQLQuery = dcql
	presentationRequest, err := c.interactiveAuthorizationRequest(ctx, ia, authCtx, dcql)
	if err != nil {
		return nil, err
	}

	// The wallet's half, recorded on the prepared issuance as it was read.
	// Nothing is stored yet: this is the document the claim will install.
	opened := *authCtx
	opened.WalletClientID = req.ClientID
	opened.WalletURI = req.RedirectURI
	opened.CodeChallenge = req.CodeChallenge
	opened.CodeChallengeMethod = req.CodeChallengeMethod
	opened.AuthSessionDPoPThumbprint = dpopThumbprint
	opened.AuthSession = authSession
	opened.DCQLQuery = dcql
	opened.ExpiresAt = time.Now().Add(ia.AuthSessionTTL()).Unix()

	// Move the physical anchor too, not just the logical deadline.
	//
	// MongoDB expires these documents on a TTL index over created_at, and
	// the claim below replaces the whole document - so without this, an
	// offer resumed late advertises an auth_session that outlives the
	// document holding it, and the wallet comes back to find the exchange
	// gone with nothing having gone wrong. The memory store re-anchors on
	// write anyway; this makes the two behave alike rather than leaving
	// the difference to be discovered in production.
	opened.CreatedAt = time.Now()

	// The point of no return, and ONE write. Exactly one caller gets the
	// handle; everyone else is told the issuer_state is invalid, which by
	// then it is.
	//
	// Claiming and then persisting as two writes had a failure mode with
	// no recovery: the claim succeeds, the persist does not, and the
	// document has lost its issuer_state without ever gaining an
	// auth_session - so the prepared issuance is unreachable by either
	// handle and nothing, including the issuer, can get it back. A
	// transient store failure must not be able to destroy a prepared
	// issuance, so the handle is replaced BY the opened exchange rather
	// than removed and then written over.
	claimed, err := c.cacheService.AuthContext.ClaimIssuerState(ctx, req.IssuerState, &opened)
	if err != nil || claimed == nil {
		if err != nil && !errors.Is(err, cache.ErrNoDocuments) {
			// A store that would not answer is ours, and the prepared
			// issuance is untouched - so the wallet can simply come back.
			return nil, c.authSessionStoreFailure(err, "claim issuer_state")
		}
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
			"issuer_state is invalid or has expired", 400)
	}
	authCtx = claimed

	c.log.Info("CHALLENGE: prepared issuance resumed, interaction required",
		"client_id", req.ClientID, "scope", scope,
		"interaction_type_required", required, "session_id", authCtx.SessionID)

	return nil, &AuthorizationChallengeError{
		ErrorCode:               errInsufficientAuthorization,
		InteractionTypeRequired: required,
		AuthSession:             authCtx.AuthSession,
		OpenID4VPRequest:        presentationRequest,
		HTTPStatus:              403,
	}
}

// The encryption an Interactive Authorization response must use. These are
// the values the request itself advertises - see the request object's
// encrypted_response_enc_values_supported and the ECDH-ES key agreement
// the ephemeral key is generated for - and a wallet that followed the
// request produces exactly them.
const iaResponseAlg = "ECDH-ES"

// validateInteractiveAuthorizationJWE refuses a response that is not the
// JWE this exchange asked for, BEFORE anything is decrypted.
//
// jwe.Decrypt on its own accepts a good deal more than the request
// advertised: other content-encryption algorithms, the JSON serialization,
// a compressed payload, and critical header parameters it silently ignores.
// None of that is what a conformant wallet sends, so accepting it only
// widens what an attacker may hand the decrypter - and the checks are the
// ones pkg/openid4vci already makes on encrypted Credential Requests, for
// the same reasons.
func validateInteractiveAuthorizationJWE(response []byte) error {
	// Compact serialization only, checked before anything is parsed.
	// jwe.Parse also accepts the JSON serialization, where a per-recipient
	// header can carry parameters the protected header does not - zip
	// among them, which would put a compressed payload past the check
	// below and into the decrypter. Refusing the JSON form closes that
	// whole class rather than chasing one member of it.
	if !isCompactJWE(response) {
		return errors.New("the response must use JWE compact serialization")
	}

	msg, err := jwe.Parse(response)
	if err != nil {
		return fmt.Errorf("the response is not a well-formed JWE: %w", err)
	}
	headers := msg.ProtectedHeaders()

	if alg, ok := headers.Algorithm(); !ok || alg.String() != iaResponseAlg {
		return fmt.Errorf("unsupported response encryption alg; this request asked for %s", iaResponseAlg)
	}
	// Against the list the REQUEST advertises, not a constant beside it:
	// a wallet that picks an offered algorithm and is refused for it has
	// been given no way to succeed, and by then its auth_session is spent.
	if enc, ok := headers.ContentEncryption(); !ok || !slices.Contains(openid4vp.InteractiveAuthorizationEncValues, enc.String()) {
		return fmt.Errorf("unsupported response encryption enc; this request asked for %v",
			openid4vp.InteractiveAuthorizationEncValues)
	}
	// No zip is advertised, so none is accepted: refusing here is the
	// point of not advertising it, rather than letting the library inflate
	// first.
	if zip, ok := headers.Compression(); ok && zip.String() != "" {
		return errors.New("a compressed response is not accepted")
	}
	// RFC 7516 §4.1.13, via RFC 7515 §4.1.11: a recipient MUST reject a
	// JWE whose crit list names an extension it does not understand. This
	// endpoint understands none, so any crit at all is refused - including
	// an empty list, which §4.1.11 makes invalid in its own right.
	//
	// Not inherited from the library: jwx only makes this check when asked,
	// with jwe.WithCritValidation(true), and the default is off.
	if _, ok := headers.Critical(); ok {
		return errors.New("no critical JWE header extensions are understood by this endpoint")
	}

	return nil
}

// isCompactJWE reports whether body is the five-part compact serialization.
func isCompactJWE(body []byte) bool {
	parts := bytes.Split(body, []byte("."))
	if len(parts) != 5 {
		return false
	}
	for i, part := range parts {
		// Only the encrypted key may be empty, which is what ECDH-ES
		// direct key agreement produces.
		if len(part) == 0 && i != 1 {
			return false
		}
		if _, err := base64.RawURLEncoding.DecodeString(string(part)); err != nil {
			return false
		}
	}
	return true
}
