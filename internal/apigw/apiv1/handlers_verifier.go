package apiv1

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/golang-jwt/jwt/v5"
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
	scope, _, err := c.matchScope(authorizationContext.Scopes)
	if err != nil {
		c.log.Error(err, "no matching scope in authorization context")
		return "", err
	}

	// Get OpenID4VP auth config for this credential type
	vpAuth := c.cfg.GetOpenID4VPAuth(scope)
	if vpAuth == nil {
		return "", fmt.Errorf("scope %q is not configured for openid4vp authentication", scope)
	}

	dcql, err := buildIssuanceAuthDCQL(vpAuth, c.cfg)
	if err != nil {
		return "", err
	}

	// Persist the DCQL query in the auth context so VerificationDirectPost
	// can use it for VP Token validation later.
	authorizationContext.DCQLQuery = dcql
	if err := c.cacheService.AuthContext.Update(ctx, authorizationContext); err != nil {
		c.log.Error(err, "failed to update authorization context with DCQL query")
		return "", fmt.Errorf("failed to update authorization context: %w", err)
	}

	authorizationRequest, err := c.buildIssuanceAuthRequestObject(ctx, authorizationContext, dcql)
	if err != nil {
		return "", err
	}

	c.log.Debug("Authorization request", "request", authorizationRequest)

	reply, err := authorizationRequest.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", reply)

	return reply, nil
}

// buildIssuanceAuthRequestObject builds the OpenID4VP Authorization Request
// that authenticates one issuance, in its browser-mediated (direct_post.jwt)
// form.
//
// This is the base both delivery channels start from: the link/QR channel
// signs it as it stands, and OpenID4VCI 1.1 Interactive Authorization takes
// it through RequestObject.WithInteractiveAuthorization, which changes only
// the three fields that describe how the request is delivered and answered.
// Everything a Wallet checks - client_id, nonce, client_metadata, the DCQL
// query - is built once, here, so the channels cannot drift into asking for
// different things.
func (c *Client) buildIssuanceAuthRequestObject(ctx context.Context, authCtx *cache.AuthorizationContext, dcql *openid4vp.DCQL) (*openid4vp.RequestObject, error) {
	// Derive VP formats from issuer metadata
	vf := deriveVPFormatsFromMetadata(c.issuerMetadata)

	_, ephemeralPublicJWK, err := c.EphemeralEncryptionKey(ctx, authCtx.EphemeralEncryptionKeyID)
	if err != nil {
		return nil, err
	}

	responseURI, err := url.JoinPath(c.cfg.APIGW.PublicURL, "/verification/direct_post")
	if err != nil {
		return nil, fmt.Errorf("failed to construct response URI: %w", err)
	}

	authorizationRequest := &openid4vp.RequestObject{
		ResponseURI:  responseURI,
		AUD:          "https://self-issued.me/v2",
		ISS:          authCtx.ClientID,
		ClientID:     authCtx.ClientID,
		ResponseType: "vp_token",
		ResponseMode: openid4vp.ResponseModeDirectPostJWT,
		State:        authCtx.State,
		Nonce:        authCtx.Nonce,
		DCQLQuery:    dcql,
		ClientMetadata: &openid4vp.ClientMetadata{
			VPFormatsSupported: vf,
			JWKS: &openid4vp.Keys{
				Keys: []jwk.Key{ephemeralPublicJWK},
			},
			// OpenID4VP 1.0 replaced authorization_encrypted_response_enc
			// with this array and closed client_metadata to a fixed set of
			// members, so the old pair is opt-in only - see OpenID4VPCompat.
			EncryptedResponseEncValuesSupported: []string{"A256GCM", "A128GCM"},
		},
		IAT: time.Now().UTC().Unix(),
	}

	// Off unless a deployment opts in - see OpenID4VPCompat.
	if c.cfg.SendLegacyJARMEncryptionParams() {
		authorizationRequest.ClientMetadata.AuthorizationEncryptedResponseALG = "ECDH-ES"
		authorizationRequest.ClientMetadata.AuthorizationEncryptedResponseENC = "A256GCM"
	}

	return authorizationRequest, nil
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

	// An Interactive Authorization exchange is answered at the
	// Authorization Challenge Endpoint, which verifies holder binding
	// before it accepts anything. This endpoint does not, and it finds the
	// same context by the same ephemeral key id - so answering an IA
	// request here is answering a request that was never made, through
	// the weaker of the two doors.
	//
	// Refused rather than verified-more-strictly. Even with holder binding
	// enforced here the audience and the mdoc session transcript would be
	// the browser flow's, not the ones the wallet signed over, so the two
	// channels are not interchangeable whatever this endpoint checks.
	//
	// Either marker refuses, because the marker is NEW and the contexts
	// are PERSISTED. A context opened by the previous version is still in
	// the store after an upgrade with no interactive_authorization member
	// at all, which decodes as false - so for as long as those contexts
	// live, the guard would wave through exactly the exchanges it exists
	// to stop. AuthSessionDPoPThumbprint is the durable second signal:
	// the challenge endpoint refuses a request without a DPoP proof
	// before it creates a context, so every IA context ever written has
	// one, and nothing else sets it.
	if authCtx.InteractiveAuthorization || authCtx.AuthSessionDPoPThumbprint != "" {
		c.log.Error(nil, "interactive authorization context answered at the browser-mediated endpoint",
			"session_id", authCtx.SessionID, "kid", kid)
		return nil, errors.New("this authorization is answered at the authorization challenge endpoint, not here")
	}

	c.log.Debug("VP Response received", "vp_token_keys", vpResponse.VPToken, "scope", authCtx.Scopes)
	outcome, err := c.consumeIssuanceAuthPresentation(ctx, authCtx, &vpResponse, issuanceAuthBinding{
		Audience:              authCtx.ClientID,
		MdocSessionTranscript: c.directPostSessionTranscript(authCtx, privateEphemeralJWK),
	})
	if err != nil {
		return nil, err
	}

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
	// Only the presentation-sourced path reports the session back: the
	// wallet uses it to resume an issuance it started, and the other paths
	// have nothing of the kind to resume.
	if outcome.PresentationSourced {
		reply.PresentationDuringIssuanceSession = authCtx.SessionID
	}
	return reply, nil
}

// ErrIssuanceAuthServerFault marks a failure in the issuance-auth pipeline
// that is this server's rather than the wallet's: a configuration problem,
// a datastore that would not answer, a key that should have been in the
// cache.
//
// It exists because the two kinds of failure have to become different HTTP
// answers at the Authorization Challenge Endpoint - a wallet that is told
// invalid_grant will stop and ask the user to try again, which is right
// for a presentation that did not verify and wrong for a datastore outage -
// and the pipeline is the only place that knows which is which. Everything
// NOT marked is the wallet's, which is the safe default: reporting our own
// fault as the caller's is merely unhelpful, while reporting the caller's
// as ours invites a retry loop against a request that can never succeed.
var ErrIssuanceAuthServerFault = errors.New("issuance authentication failed on the server side")

// serverFault tags err as ours. Formatting is left to the caller so the
// message reads the way it was written.
func serverFault(err error) error {
	return fmt.Errorf("%w: %w", ErrIssuanceAuthServerFault, err)
}

// issuanceAuthBinding is what a presentation must be bound to, which
// differs by the channel it arrived on.
type issuanceAuthBinding struct {
	// Audience is what the presentation must be addressed to: the
	// verifier's own client_id for the browser flow, and the prefixed
	// Authorization Challenge Endpoint for Interactive Authorization,
	// which is what stops one Authorization Server relaying another's
	// challenge.
	Audience string

	// MdocSessionTranscript builds the transcript an mdoc presentation on
	// this channel must have been signed over. Nil means the channel does
	// not accept mdoc, which is refused explicitly rather than verified
	// against some other channel's transcript.
	//
	// Both channels supply one now - direct_post and the Authorization
	// Challenge Endpoint build different structures - so nil is for a
	// channel added later that has not yet decided what its wallet signs
	// over. That is the safe default, and the reason this is a callback
	// rather than a flag.
	MdocSessionTranscript func() ([]byte, error)

	// ExpectedState is the state the response must carry back, or empty to
	// not check it.
	//
	// Empty is what the browser-mediated flow passes, and that is a real
	// gap rather than a decision: that channel puts the wallet's own PAR
	// state on the request and never compares what comes back
	// (OpenID4VP §14.1). It is pre-existing and not this change's to fix,
	// so it is named here rather than quietly inherited by the new caller.
	// Interactive Authorization mints its own and checks it, because
	// nothing there makes a state optional.
	ExpectedState string

	// VerifyHolderBinding requires the SD-JWT VC presentation to carry a
	// Key Binding JWT that actually VERIFIES against the cnf key the
	// Issuer bound the credential to.
	//
	// VPTokenValidator already verifies the KB-JWT signature against the
	// credential's cnf key on both channels. This flag adds two checks
	// the validator does not make: the cnf key is taken from the issuer
	// JWT whose signature was just verified (not from the presented
	// claims), and the credential must be inside its validity window
	// (exp/nbf), which signature verification does not enforce.
	//
	// Interactive Authorization sets it: the endpoint is new, nothing
	// depends on the weaker behaviour, and the whole purpose of the
	// exchange is to establish WHO is asking for an issuance - a check
	// that cannot tell the Holder from someone holding a copy does not do
	// that job at all.
	//
	// The browser-mediated flow does not set it yet, and that is a real
	// gap rather than a decision: it is pre-existing, it affects every
	// presentation that channel has ever accepted, and turning it on
	// there changes what an existing deployment accepts. It is named here
	// rather than quietly left out, and is on the user's list.
	VerifyHolderBinding bool
}

// issuanceAuthOutcome says how a presentation that authenticated an
// issuance was consumed, so each caller can finish in its own terms.
type issuanceAuthOutcome struct {
	// Scope is the issuance scope the presentation satisfied.
	Scope string

	// PresentationSourced is true when the scope derives its whole
	// document from the presented credential, so no datastore lookup
	// happened and finalisePresentationVerification has already run.
	PresentationSourced bool
}

// consumeIssuanceAuthPresentation verifies a presentation that authenticates
// an issuance and resolves it to a person, leaving the authorization context
// ready for the credential to be issued.
//
// Shared by the two ways such a presentation can arrive: the browser-mediated
// flow, where the wallet posts it to /verification/direct_post, and
// OpenID4VCI 1.1 Interactive Authorization, where it comes back to the
// Authorization Challenge Endpoint. Everything between "here is a VP token"
// and "this session has documents" is the same for both - the DCQL match,
// SD-JWT and mdoc verification, issuer trust, identity extraction, the
// datastore lookup - and it is not the kind of code to keep two copies of.
//
// audience is what the presentation must be addressed to. The browser flow
// passes the verifier's own client_id; Interactive Authorization passes the
// prefixed Authorization Challenge Endpoint, which is what stops one
// Authorization Server relaying another's challenge.
// issuanceAuthConsumer is consumeIssuanceAuthPresentation's signature, so
// that a channel feeding it can be tested against the pipeline rather than
// against a PDP, a trust deployment and a datastore.
type issuanceAuthConsumer func(ctx context.Context, authCtx *cache.AuthorizationContext, vpResponse *openid4vp.VPResponse, binding issuanceAuthBinding) (*issuanceAuthOutcome, error)

// issuanceAuthPipeline is the consumer to feed. The real one unless a test
// has put something else in its place - see Client.issuanceAuth.
func (c *Client) issuanceAuthPipeline() issuanceAuthConsumer {
	if c.issuanceAuth != nil {
		return c.issuanceAuth
	}
	return c.consumeIssuanceAuthPresentation
}

func (c *Client) consumeIssuanceAuthPresentation(ctx context.Context, authCtx *cache.AuthorizationContext, vpResponse *openid4vp.VPResponse, binding issuanceAuthBinding) (*issuanceAuthOutcome, error) {
	// Match a scope from the authorization context to a known credential constructor
	scope, credMetaCfg, err := c.matchScope(authCtx.Scopes)
	if err != nil {
		c.log.Error(err, "no matching scope in authorization context")
		return nil, serverFault(err)
	}

	// Extract the credential query ID from the persisted DCQL query.
	// The VP Token map is keyed by credential query ID (the auth scope),
	// not by the issuing scope. The wallet may have responded with any of
	// the acceptable credential types, so try all DCQL credential query IDs.
	var vpToken string
	var matchedAuthScope string
	if authCtx.DCQLQuery == nil || len(authCtx.DCQLQuery.Credentials) == 0 {
		c.log.Error(nil, "DCQL query has no credential queries", "scope", scope)
		return nil, serverFault(errors.New("DCQL query has no credential queries"))
	}
	for _, cq := range authCtx.DCQLQuery.Credentials {
		if tokens, ok := vpResponse.VPToken[cq.ID]; ok && len(tokens) > 0 {
			if len(tokens) > 1 {
				c.log.Info("multiple VP tokens received for credential query, using first", "credential_query_id", cq.ID, "count", len(tokens))
			}
			vpToken = tokens[0]
			matchedAuthScope = cq.ID
			c.log.Info("VP token matched credential query", "matched_auth_scope", matchedAuthScope, "scope", scope)
			break
		}
	}
	if vpToken == "" {
		c.log.Error(nil, "VP Token not found for any credential query", "available_keys", vpResponse.VPToken)
		return nil, errors.New("VP Token not found for any configured credential query")
	}

	// The state ties this response to the request that asked for it. A
	// response carrying someone else's state is someone else's
	// presentation, however well it verifies (OpenID4VP §14.1).
	if binding.ExpectedState != "" && vpResponse.State != binding.ExpectedState {
		c.log.Error(nil, "presentation state does not match the request it answers",
			"session_id", authCtx.SessionID)
		return nil, errors.New("presentation state does not match the request it answers")
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

	// SD-JWT and mdoc need different verification paths: VPTokenValidator +
	// EvaluateIssuerTrust both parse the token as SD-JWT (see
	// pkg/openid4vp/validator.go and pkg/trust/jwt_verifier.go), so an
	// mdoc VP token has to go through MDocHandler instead.
	var credential map[string]any
	if mdoc.IsMDocFormat(responseParams.VPToken) {
		// trust.NewTrustEvaluatorFromConfig returns a non-nil
		// AllowAllEvaluator when pdp_url is empty, so a plain
		// c.trustEvaluator == nil check cannot distinguish "no PDP
		// configured" from "a real PDP wired up". Mdoc issuer trust must
		// be a real decision, so refuse this path in allow-all mode.
		if c.cfg.APIGW.Trust.PDPURL == "" {
			return nil, serverFault(errors.New("mdoc VP verification requires apigw.trust.pdp_url to be configured"))
		}
		if authCtx.Nonce == "" || authCtx.ClientID == "" {
			return nil, serverFault(errors.New("mdoc VP verification requires nonce and client_id on the authorization context"))
		}
		// mdoc.IsMDocFormat is only a base64/CBOR-shape sniff and also
		// matches "mso_mdoc_zk" (ZK-mdoc) presentations, whose
		// zkDocuments carry a different verification contract than
		// plain mso_mdoc's DeviceResponse. MDocHandler.VerifyAndExtractBound
		// only decodes DeviceResponse.Documents, so a ZK presentation
		// would silently reach mdocClaimsFromResult with no documents
		// and be rejected. Detect ZK responses here and refuse rather
		// than mis-route them through the plain-mdoc verifier.
		if rawVPToken, derr := base64.RawURLEncoding.DecodeString(responseParams.VPToken); derr == nil {
			if isZK, perr := mdoc.PeekIsZkDeviceResponse(rawVPToken); perr == nil && isZK {
				return nil, errors.New("ZK-mdoc (mso_mdoc_zk) VP tokens are not supported on this presentation flow; use the ZK verifier instead")
			}
		}
		// The SessionTranscript binds the presentation to the channel it
		// arrived on, so the channel builds it. A wallet answering a
		// direct-post request and one answering an Authorization
		// Challenge Endpoint construct different transcripts, and
		// verifying against the wrong one fails device-auth with nothing
		// to point at - so a channel that has not supplied a builder
		// refuses mdoc rather than guessing.
		if binding.MdocSessionTranscript == nil {
			return nil, errors.New("mdoc presentations are not supported on this authentication channel")
		}
		sessionTranscript, err := binding.MdocSessionTranscript()
		if err != nil {
			return nil, serverFault(fmt.Errorf("build mdoc session transcript: %w", err))
		}
		mdocHandler, err := mdoc.NewMDocHandler(mdoc.WithMDocTrustEvaluator(c.trustEvaluator))
		if err != nil {
			c.log.Error(err, "failed to create mdoc handler")
			return nil, serverFault(fmt.Errorf("mdoc handler init failed: %w", err))
		}
		mdocResult, err := mdocHandler.VerifyAndExtractBound(ctx, responseParams.VPToken, sessionTranscript)
		if err != nil {
			c.log.Error(err, "mdoc VP verification failed")
			return nil, fmt.Errorf("mdoc VP verification failed: %w", err)
		}
		credential, err = mdocClaimsFromResult(mdocResult)
		if err != nil {
			return nil, err
		}
		c.log.Debug("mdoc VP verified", "doc_count", len(mdocResult.Documents))
	} else {
		validator := &openid4vp.VPTokenValidator{
			Nonce:           authCtx.Nonce,
			ClientID:        binding.Audience,
			ValidateFormat:  true,
			CheckRevocation: false,
			DCQLQuery:       authCtx.DCQLQuery,
		}
		if err := validator.Validate(responseParams.VPToken); err != nil {
			c.log.Error(err, "VP Token validation failed")
			return nil, fmt.Errorf("VP Token validation failed: %w", err)
		}
		c.log.Debug("VP Token validated successfully")

		if err := c.jwtTrustVerifier.EvaluateIssuerTrust(ctx, vpToken, scope); err != nil {
			c.log.Error(err, "Issuer trust evaluation failed", "scope", scope)
			return nil, fmt.Errorf("issuer trust evaluation failed: %w", err)
		}

		// Who is presenting this, as distinct from whether the claims are
		// genuine.
		//
		// Everything above establishes that a trusted Issuer signed these
		// claims. A credential and its disclosures are a bearer token to
		// anyone who obtains them, so that says nothing about the
		// presenter - and the validator above checks only that a key
		// binding proof is THERE, reading its nonce and audience without
		// verifying the signature. The proof has to be checked against
		// the cnf key the Issuer bound the credential to, and the claims
		// carrying that key have to be the ones whose signature was just
		// verified: reading cnf out of an unverified issuer JWT would let
		// the presenter nominate their own key.
		if binding.VerifyHolderBinding {
			issuerToken, _, err := c.jwtTrustVerifier.VerifyJWTSignature(ctx, issuerJWTOf(responseParams.VPToken), scope)
			if err != nil {
				c.log.Error(err, "issuer JWT did not verify while checking holder binding", "scope", scope)
				return nil, fmt.Errorf("issuer signature verification failed: %w", err)
			}
			issuerClaims, ok := issuerToken.Claims.(jwt.MapClaims)
			if !ok {
				return nil, serverFault(errors.New("verified issuer JWT carries no claims"))
			}

			// The credential has to be valid NOW, which its signature
			// does not say.
			//
			// VerifyJWTSignature parses with jwt.WithoutClaimsValidation
			// - it is answering "who signed this", and the trust
			// evaluation it feeds is about the issuer rather than the
			// document - and neither the VP validator nor the credential
			// parser looks at exp or nbf either. So an expired credential
			// presented with a freshly signed proof was accepted: the
			// holder genuinely holds the key, the nonce is genuinely this
			// request's, and the credential genuinely stopped being valid
			// last year. A fresh proof does not renew a credential.
			if err := validIssuerCredentialWindow(issuerClaims, time.Now()); err != nil {
				c.log.Error(err, "presented credential is outside its validity window", "scope", scope)
				return nil, fmt.Errorf("credential validity check failed: %w", err)
			}

			if err := sdjwtvc.VerifyKeyBinding(responseParams.VPToken, issuerClaims, sdjwtvc.KeyBindingExpectations{
				Nonce:    authCtx.Nonce,
				Audience: binding.Audience,
			}); err != nil {
				c.log.Error(err, "holder binding verification failed", "scope", scope)
				return nil, fmt.Errorf("holder binding verification failed: %w", err)
			}
			c.log.Debug("holder binding verified", "scope", scope)
		}

		built, err := responseParams.BuildCredential()
		if err != nil {
			c.log.Error(err, "failed to build credential from response parameters")
			return nil, err
		}
		credential = built
	}

	c.log.Debug("Found credential metadata", "scope", scope, "vct", credMetaCfg.GetVCTURL())

	// Enforce that the verified credential's type matches matchedAuthScope's
	// credential_metadata. VPTokenValidator's validateAgainstDCQL is
	// currently a no-op, and the mdoc branch above skips it entirely; a
	// trusted credential of another type that happens to carry the
	// requested claim keys must not be accepted for this auth scope.
	if err := c.enforceScopeCredentialType(matchedAuthScope, credential); err != nil {
		c.log.Error(err, "verified credential type does not match matched auth scope", "matched_auth_scope", matchedAuthScope, "scope", scope)
		return nil, err
	}

	// The rule the preparing caller supplied, where there was one.
	//
	// Here rather than at the Challenge Endpoint, so that an issuance
	// prepared with a rule is bound by it whichever channel the
	// presentation arrives on - and ABOVE the presentation-sourced branch
	// below, which returns early: a check placed after it would be skipped
	// by exactly the scopes that mint a credential straight out of the
	// presentation, which are the ones with the least else standing
	// between a wallet and an issued credential.
	//
	// After verification and before anything is issued or looked up: the
	// claims are trustworthy by this point, and nothing has been done with
	// them yet.
	if err := c.matchPresentedIdentity(c.cfg.GetFormatForScope(matchedAuthScope), credential, authCtx.IdentityMatch); err != nil {
		return nil, err
	}

	// Presentation-source scopes derive their whole document from the
	// presented credential — there is no datastore lookup by identity.
	// Guarded on DataSource so a scope shared with datastore/assertion still
	// follows the source Selector chose.
	if pScope, ok := c.cfg.APIGW.DataSources.Presentation.Scopes[scope]; ok && authCtx.DataSource == string(model.DataSourcePresentation) {
		if err := c.finalisePresentationVerification(ctx, authCtx, pScope, credential); err != nil {
			return nil, err
		}
		return &issuanceAuthOutcome{Scope: scope, PresentationSourced: true}, nil
	}

	// Extract identity from validated credential using the matched auth scope's claims.
	// The vpAuth config tells us which claims to extract based on which credential was presented.
	vpAuth2 := c.cfg.GetOpenID4VPAuth(scope)
	if vpAuth2 == nil {
		return nil, serverFault(fmt.Errorf("scope %q lost openid4vp configuration", scope))
	}
	authScopeEntry, ok := vpAuth2.AuthScopes[matchedAuthScope]
	if !ok {
		return nil, serverFault(fmt.Errorf("matched auth scope %q not found in config for scope %q", matchedAuthScope, scope))
	}
	identityClaims, err := model.ExtractIdentityClaims(credential, authScopeEntry.AuthClaims)
	if err != nil {
		c.log.Error(err, "required identity claims missing from presented credential", "matched_auth_scope", matchedAuthScope, "scope", scope)
		return nil, fmt.Errorf("identity extraction failed: %w", err)
	}

	// Resolve the person identifier — uses authentic_source_person_id directly
	// when present in the extracted claims, otherwise falls back to identity
	// mapping (given_name, family_name, birth_date → authentic_source_person_id).
	claimsAny := make(map[string]any, len(identityClaims))
	for k, v := range identityClaims {
		claimsAny[k] = v
	}
	identityMappingID, err := c.ResolveIdentifier(ctx, authCtx.AuthenticSource, claimsAny)
	if err != nil {
		if errors.Is(err, helpers.ErrNoIdentityFound) {
			return nil, fmt.Errorf("failed to resolve identity from VP claims: %w", err)
		}
		return nil, serverFault(fmt.Errorf("failed to resolve identity from VP claims: %w", err))
	}

	// Persist the resolved identifier on the authorization context so that
	// downstream credential issuance (VCICredential) can find it.
	if err := c.cacheService.AuthContext.SetIdentifier(ctx, &cache.AuthorizationContext{SessionID: authCtx.SessionID}, identityMappingID); err != nil {
		c.log.Error(err, "failed to persist identifier on auth context")
		return nil, serverFault(fmt.Errorf("failed to persist identifier: %w", err))
	}

	// Retrieve documents matching the identity by scope
	c.log.Debug("Querying documents", "scope", scope, "identity_mapping_id", identityMappingID)
	documents, err := c.datastoreStore.GetByIdentity(ctx, scope, identityMappingID)
	if err != nil {
		c.log.Debug("failed to get document", "error", err)
		return nil, serverFault(err)
	}

	c.log.Debug("Retrieved documents", "count", len(documents))

	if len(documents) == 0 {
		c.log.Error(nil, "no documents found for identity", "identity_claims", identityClaims)
		return nil, errors.New("no documents found for the provided identity")
	}

	// Cache PID documents for session
	c.cacheService.Document.Set(ctx, authCtx.SessionID, documents)

	c.log.Debug("Documents cached for session", "session_id", authCtx.SessionID)

	return &issuanceAuthOutcome{Scope: scope}, nil
}

// buildIssuanceAuthDCQL builds the DCQL query the wallet must satisfy to
// authenticate the user during OpenID4VP-based issuance. One CredentialQuery
// per auth scope so the wallet may present any acceptable credential type
// (e.g. pid OR eduid); each carries its per-scope auth_claims and the
// scope's canonical vct (VCTM.VCT after ResolveVCTUrls -- preserved from the
// VCTM file when present (both local and external), and back-filled from the
// /type-metadata/<scope> hosting URL only when a local file left vct empty).
// That single value is what the credential body carries, what the issuer
// metadata advertises, and what wallets store as the credential's type tag
// -- see (*model.Cfg).VCTIdentifiersForScopes.
func buildIssuanceAuthDCQL(vpAuth *model.OpenID4VPCredentialAuth, cfg *model.Cfg) (*openid4vp.DCQL, error) {
	credentialQueries := make([]openid4vp.CredentialQuery, 0, len(vpAuth.AuthScopes))
	options := make([][]string, 0, len(vpAuth.AuthScopes))
	for _, authScope := range slices.Sorted(maps.Keys(vpAuth.AuthScopes)) {
		entry := vpAuth.AuthScopes[authScope]
		scopeClaimQueries := make([]openid4vp.ClaimQuery, 0, len(entry.AuthClaims))
		format := cfg.GetFormatForScope(authScope)
		for _, claim := range entry.AuthClaims {
			scopeClaimQueries = append(scopeClaimQueries, openid4vp.ClaimQuery{
				Path: openid4vp.StringPath(authClaimPathSegments(format, claim)...),
			})
		}
		// By format, so an mso_mdoc auth scope is constrained by its doctype
		// rather than sent out with a vct_values no mdoc credential carries.
		// An auth scope naming no configured credential resolves to a nil
		// entry here, which DCQLMetaQuery reports rather than dereferences.
		// Issuance auth is answered by THIS package's VerificationDirectPost,
		// which validates the response as an SD-JWT and has no format
		// dispatch. A W3C scope would produce a query a wallet can satisfy
		// and this flow then cannot read, so refuse to build it rather than
		// advertise a request that fails after the user has already been
		// sent to their wallet.
		//
		// The verifier service verifies W3C properly; issuance auth is a
		// separate flow in a separate service and has not been taught to.
		if openid4vp.IsW3CVCFormatIdentifier(format) {
			return nil, fmt.Errorf("auth scope %q is format %q, which issuance auth cannot verify; use an SD-JWT or mdoc credential for authentication", authScope, format)
		}

		meta, ok := cfg.GetCredentialMetadata(authScope).DCQLMetaQuery()
		if !ok {
			return nil, fmt.Errorf("auth scope %q has no usable DCQL meta constraint (format %q); check credential_metadata", authScope, format)
		}
		credentialQueries = append(credentialQueries, openid4vp.CredentialQuery{
			ID:       authScope,
			Format:   format,
			Multiple: false,
			Meta:     meta,
			// Left unset, which is the specification's default of TRUE.
			//
			// It said false, which told every wallet that a presentation
			// authenticating an issuance need not prove possession - and
			// the verifier did not check, so the two agreed. A
			// presentation that proves nothing about who is presenting is
			// not an authentication, and this is the flow that decides
			// whose documents get issued.
			Claims: scopeClaimQueries,
		})
		options = append(options, []string{authScope})
	}
	return &openid4vp.DCQL{
		Credentials: credentialQueries,
		CredentialSets: []openid4vp.CredentialSetQuery{
			{
				Options:  options,
				Required: new(false),
			},
		},
	}, nil
}

// authClaimPathSegments turns an auth-scope claim into DCQL path segments.
// For SD-JWT VC a dotted "address.locality" becomes the nested path
// ["address", "locality"]. For mdoc DCQL requires exactly [namespace,
// element_identifier] (OpenID4VP 1.0 §6.4.1); a bare element is resolved
// against the primary ISO 18013-5 namespace and a "<namespace>.<element>"
// entry is split on the LAST dot so a multi-dot namespace such as
// "eu.europa.ec.eudi.pid.1" survives as one segment.
func authClaimPathSegments(format, claim string) []string {
	switch format {
	case openid4vp.FormatMsoMdoc, openid4vp.FormatMsoMdocZk:
		if idx := strings.LastIndex(claim, "."); idx > 0 && idx < len(claim)-1 {
			return []string{claim[:idx], claim[idx+1:]}
		}
		return []string{mdoc.Namespace, claim}
	default:
		return strings.Split(claim, ".")
	}
}

// directPostSessionTranscript builds the mdoc SessionTranscript for the
// browser-mediated direct-post channel.
//
// It binds the presentation to this request's nonce, client_id and
// response_uri, and to the ephemeral response-encryption public key
// advertised in ClientMetadata.JWKS. A conformant mdoc wallet puts that
// reader-key thumbprint in its own transcript, so the same one has to be
// derived here or device-auth rejects valid encrypted presentations.
func (c *Client) directPostSessionTranscript(authCtx *cache.AuthorizationContext, privateEphemeralJWK jwk.Key) func() ([]byte, error) {
	return func() ([]byte, error) {
		responseURI, err := url.JoinPath(c.cfg.APIGW.PublicURL, "/verification/direct_post")
		if err != nil {
			return nil, fmt.Errorf("compute mdoc response_uri: %w", err)
		}
		ephemeralPublicJWK, err := privateEphemeralJWK.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("derive ephemeral public key: %w", err)
		}
		readerPubKeyThumbprint, err := ephemeralPublicJWK.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("compute ephemeral JWK thumbprint: %w", err)
		}
		return mdoc.BuildOID4VPSessionTranscript(authCtx.ClientID, authCtx.Nonce, responseURI, readerPubKeyThumbprint)
	}
}

// issuerJWTOf returns the issuer-signed JWT at the head of an SD-JWT VC
// presentation, without the disclosures or the key binding proof.
func issuerJWTOf(vpToken string) string {
	issuerJWT, _, _ := strings.Cut(vpToken, "~")
	return issuerJWT
}

// issuerCredentialClockSkew is how far out of its window a presented
// credential may be and still be accepted.
//
// Small, and symmetric. Clocks between an Issuer, a Holder's device and
// this server differ by seconds in practice, and refusing a credential
// that became valid one second ago is a failure a user cannot act on;
// accepting one that expired a minute ago is not a risk worth the
// confusion either.
const issuerCredentialClockSkew = 30 * time.Second

// validIssuerCredentialWindow refuses a credential that has expired or has
// not started.
//
// Both are read from the ISSUER-VERIFIED claims, so a presenter cannot
// extend its own credential's life by rewriting them. A credential with
// neither claim is accepted: SD-JWT VC makes exp OPTIONAL, and refusing
// one that omits it would reject credentials that are valid by their own
// terms.
func validIssuerCredentialWindow(claims jwt.MapClaims, now time.Time) error {
	exp, haveExp, err := numericDate(claims, "exp")
	if err != nil {
		return err
	}
	if haveExp && now.After(exp.Add(issuerCredentialClockSkew)) {
		return fmt.Errorf("the presented credential expired at %s", exp.UTC().Format(time.RFC3339))
	}

	nbf, haveNbf, err := numericDate(claims, "nbf")
	if err != nil {
		return err
	}
	if haveNbf && now.Before(nbf.Add(-issuerCredentialClockSkew)) {
		return fmt.Errorf("the presented credential is not valid until %s", nbf.UTC().Format(time.RFC3339))
	}

	return nil
}

// numericDate reads a JWT NumericDate claim, and distinguishes the three
// cases that are not the same thing: absent, a date, and a value that is
// present but is not a date.
//
// The last one is REFUSED rather than treated as either of the others.
// Absent means the issuer placed no restriction; present-but-malformed
// means the issuer placed one this server cannot read, and accepting the
// credential without it decides in the presenter's favour a question we
// were unable to answer. Reading it as zero would be the opposite
// failure - 1970, expiring every credential carrying one - which is why
// it cannot simply be parsed loosely either. Nothing upstream catches it:
// the issuer signature check runs with claims validation off.
func numericDate(claims jwt.MapClaims, name string) (time.Time, bool, error) {
	raw, present := claims[name]
	if !present || raw == nil {
		return time.Time{}, false, nil
	}

	switch v := raw.(type) {
	case float64:
		return time.Unix(int64(v), 0), true, nil
	case int64:
		return time.Unix(v, 0), true, nil
	case int:
		return time.Unix(int64(v), 0), true, nil
	case json.Number:
		n, err := v.Float64()
		if err != nil {
			return time.Time{}, true, fmt.Errorf("the presented credential has a %s claim that is not a number: %q", name, v.String())
		}
		return time.Unix(int64(n), 0), true, nil
	default:
		return time.Time{}, true, fmt.Errorf("the presented credential has a %s claim that is not a NumericDate, but a %T", name, raw)
	}
}
