package apiv1

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/google/uuid"
)

// PrepareIssuanceRequest asks this server to prepare an issuance that a
// wallet will complete later, and to say who may complete it.
//
// It is the issuer-initiated half of Interactive Authorization. The caller
// is a system that has already authenticated the user and let them decide
// what is being issued - a portal where someone signed in, picked the
// company they represent, and asked for a credential about it. What it
// cannot do is reach into the wallet; so it hands the user an offer, and
// tells this server which Holder that offer is for.
// Every field is `header:"-"`, and that is load-bearing rather than tidy.
//
// httphelpers.Binding.Request binds headers BEFORE the JSON body, and
// gin's header binder falls back to the FIELD NAME when a struct carries
// no header tag - so a "Scope:" header would populate Scope, and a body
// that simply omits the member leaves it there. The SPOCP authorization
// middleware extracts the resource pairs it checks from the query string
// and the JSON body and never looks at headers, so a scope smuggled
// through one is acted on without having been authorized. Refusing the
// header source keeps the value the middleware checks and the value this
// handler acts on the same value.
type PrepareIssuanceRequest struct {
	// Scope is the credential being prepared.
	Scope string `json:"scope" header:"-" validate:"required"`

	// IdentityMatch decides whether the Holder who turns up is the one
	// this issuance was prepared for.
	//
	// REQUIRED. An issuance prepared without one is an offer anybody's
	// wallet may complete, which is what the pre-authorized grant already
	// provides and what this endpoint exists to improve on. A caller that
	// wants that should ask for it by name rather than by omission.
	IdentityMatch *openid4vci.IdentityMatch `json:"identity_match" header:"-" validate:"required"`

	// AuthenticSource names the source this credential will be issued
	// from, and is checked against the one the scope actually resolves to.
	//
	// Optional, and NOT how the source is chosen - the Selector decides
	// that, from what this deployment has running. It exists because the
	// authorization middleware reads authentic_source out of this body and
	// authorizes the (source, scope) pair it finds there. A caller allowed
	// source A could otherwise send "authentic_source": "A" alongside a
	// scope that resolves to B, pass a check about A, and have an issuance
	// prepared against B. Supplying it means the pair that was authorized
	// is the pair that is used; omitting it authorizes a pair with no
	// source, which the deployment's own rules decide about.
	AuthenticSource string `json:"authentic_source,omitempty" header:"-" validate:"omitempty"`

	// TTLSeconds bounds how long the offer may be left unredeemed.
	// Optional; the server's default applies when it is absent.
	TTLSeconds int `json:"ttl_seconds,omitempty" header:"-" validate:"omitempty,gt=0"`
}

// PrepareIssuanceReply is the prepared issuance.
type PrepareIssuanceReply struct {
	// CredentialOffer is handed to the wallet, by QR or deep link.
	CredentialOffer *openid4vci.CredentialOfferResult `json:"credential_offer"`

	// IssuerState is the handle inside that offer. Returned separately so
	// the caller can record which of its own sessions this issuance
	// belongs to without parsing the offer back apart.
	IssuerState string `json:"issuer_state"`

	// ExpiresAt is when the prepared issuance stops being redeemable,
	// as a Unix timestamp.
	ExpiresAt int64 `json:"expires_at"`
}

// defaultPreparedIssuanceTTL is how long a prepared issuance lasts when
// the caller does not say.
//
// Long enough for someone to pick up their phone and scan, short enough
// that an offer left on a screen does not stay live. Bounded above by the
// authorization-context cache, which is what it is stored in.
const defaultPreparedIssuanceTTLSeconds = 300

// maxPreparedIssuanceTTLSeconds is the longest a prepared issuance may be
// asked to last.
//
// It is the authorization-context cache's own lifetime, and it is a hard
// bound rather than a policy: the prepared issuance IS a document in that
// cache, so a longer TTL would return an expires_at the caller can read,
// print on a QR code and hand to someone, for an issuer_state that has
// already been deleted. Refused rather than clamped - a caller that asked
// for an hour should be told it cannot have one, not handed ten minutes
// and left to discover the difference.
//
// Same bound as model.MaxAuthSessionTTLSeconds, for the same reason and
// from the same cache.
const maxPreparedIssuanceTTLSeconds = model.MaxAuthSessionTTLSeconds

// PrepareIssuance prepares an issuer-initiated issuance and returns the
// Credential Offer for it.
//
// The offer carries the authorization_code grant with an issuer_state,
// NOT a pre-authorized code. The difference is the whole point: a
// pre-authorized code is a bearer secret, so whoever holds it may redeem
// it, and the only binding available is a transaction code typed by
// whoever is holding the phone. This hands out no secret. The wallet
// takes the issuer_state to the Authorization Challenge Endpoint, is told
// to present a credential, and is issued to only if that credential
// satisfies the rule the caller supplied here.
func (c *Client) PrepareIssuance(ctx context.Context, req *PrepareIssuanceRequest) (*PrepareIssuanceReply, error) {
	ia := &c.cfg.APIGW.Delivery.InteractiveAuthorization

	// Nothing prepared here is redeemable while Interactive Authorization
	// is off: the Challenge Endpoint is the only place an issuer_state can
	// be spent, and it answers 404 when the mechanism is not enabled. A
	// preparation that succeeds anyway hands the caller a valid-looking
	// offer to print and distribute, and the failure surfaces to whoever
	// scans it.
	if !ia.Enabled() {
		return nil, helpers.NewErrorDetailsWithStatus("interactive_authorization_disabled",
			"interactive authorization is not enabled on this server, so a prepared issuance could not be redeemed", 400)
	}

	if err := req.IdentityMatch.Validate(); err != nil {
		return nil, helpers.NewErrorDetailsWithStatus("invalid_identity_match", err.Error(), 400)
	}

	// The scope has to be one a presentation can authenticate, or there is
	// no point at which the rule could be evaluated. Asked through the
	// same Selector the Challenge Endpoint and /authorize use, so a scope
	// prepared here is one this deployment will actually answer with a
	// presentation rather than a browser.
	required, source, err := c.interactionTypeForScope(ia, req.Scope)
	if err != nil {
		return nil, err
	}
	if required != ia.InteractionType(model.InteractionOpenID4VPPresentation) {
		return nil, helpers.NewErrorDetailsWithStatus("scope_not_presentation_authenticated",
			fmt.Sprintf("scope %q is authenticated by %q, and an identity match can only be evaluated against a presentation",
				req.Scope, required), 400)
	}

	// The offer names req.Scope as its credential_configuration_id, and
	// issuance resolves it through matchScope only after the exchange is spent.
	if c.cfg.GetCredentialMetadata(req.Scope) == nil {
		return nil, helpers.NewErrorDetailsWithStatus("unknown_credential_configuration",
			fmt.Sprintf("scope %q has no credential metadata, so the offer would name a credential this issuer does not advertise", req.Scope), 400)
	}

	// The source the caller named, if it named one, has to be the source
	// this scope resolves to.
	//
	// The authorization middleware reads authentic_source from this body
	// and authorizes the (source, scope) pair it finds. Nothing else
	// compared that pair to the one preparation would actually use, so a
	// caller permitted source A could name A, send a scope the Selector
	// resolves to B, and have the issuance prepared against B having been
	// authorized for nothing of the sort. Refusing the mismatch keeps the
	// pair that was checked and the pair that is used the same pair.
	if req.AuthenticSource != "" && req.AuthenticSource != source.AuthenticSource {
		c.log.Error(nil, "PREPARE: authentic_source does not match the source the scope resolves to",
			"scope", req.Scope, "named", req.AuthenticSource, "resolved", source.AuthenticSource)
		return nil, helpers.NewErrorDetailsWithStatus("authentic_source_mismatch",
			fmt.Sprintf("scope %q is served by authentic source %q, not %q",
				req.Scope, source.AuthenticSource, req.AuthenticSource), 403)
	}

	// The request has to be buildable, which matching claim NAMES does
	// not establish.
	//
	// buildIssuanceAuthDCQL refuses an auth scope whose format it cannot
	// query and one whose credential metadata is missing, and it is not
	// reached until a wallet resumes the offer - by which point the
	// failure belongs to a Holder standing in front of a QR code, for a
	// configuration problem the caller could have been told about at the
	// moment it prepared the issuance. Built here and thrown away: it is
	// rebuilt when the exchange opens, from configuration that may have
	// changed, so storing this one would only make the two disagree.
	if _, err := c.issuanceAuthDCQL(req.Scope); err != nil {
		c.log.Error(err, "PREPARE: scope cannot be turned into a presentation request", "scope", req.Scope)
		return nil, helpers.NewErrorDetailsWithStatus("scope_not_presentable",
			fmt.Sprintf("scope %q cannot be turned into a presentation request: %v", req.Scope, err), 400)
	}

	// And a rule naming a claim the request will not ask for can never
	// pass. Checked against a request that can be built, so every auth
	// scope has the credential metadata its claims are read by.
	if err := c.validateIdentityMatchIsAskable(req.Scope, req.IdentityMatch); err != nil {
		return nil, err
	}

	host, err := helpers.HostFromURL(c.cfg.APIGW.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
	}

	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = defaultPreparedIssuanceTTLSeconds
	}
	if ttl > maxPreparedIssuanceTTLSeconds {
		return nil, helpers.NewErrorDetailsWithStatus("ttl_too_long",
			fmt.Sprintf("ttl_seconds must be at most %d; a prepared issuance is stored in a cache that does not keep it longer",
				maxPreparedIssuanceTTLSeconds), 400)
	}

	issuerState, err := crypto.GenerateSecureToken(32, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to generate issuer_state: %w", err)
	}

	authCtx := &cache.AuthorizationContext{
		SessionID:       uuid.NewString(),
		Code:            uuid.NewString(),
		IssuerState:     issuerState,
		IdentityMatch:   req.IdentityMatch,
		Scopes:          []string{req.Scope},
		ClientID:        fmt.Sprintf("x509_san_dns:%s", host),
		AuthProvider:    source.AuthProvider,
		DataSource:      string(source.DataSource),
		RemoteName:      source.RemoteName,
		AuthenticSource: source.AuthenticSource,
		ExpiresAt:       time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
	}

	if authCtx.Nonce, err = crypto.GenerateSecureToken(0, 32); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	if authCtx.EphemeralEncryptionKeyID, err = crypto.GenerateSecureToken(0, 32); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	if authCtx.State, err = crypto.GenerateSecureToken(0, 32); err != nil {
		return nil, fmt.Errorf("failed to generate presentation state: %w", err)
	}

	if err := c.cacheService.AuthContext.Save(ctx, authCtx); err != nil {
		return nil, err
	}

	offer, err := openid4vci.NewCredentialOffer(
		c.cfg.APIGW.Delivery.CredentialOffers.IssuerURL, req.Scope, openid4vci.GrantTypeAuthorizationCode)
	if err != nil {
		return nil, err
	}
	// NewCredentialOffer mints its own token; this issuance is identified
	// by the one indexed above, so the offer carries that instead.
	offer.Grants[openid4vci.GrantTypeAuthorizationCode] = openid4vci.GrantAuthorizationCode{
		IssuerState: issuerState,
	}

	c.log.Info("prepared an issuer-initiated issuance",
		"scope", req.Scope, "session_id", authCtx.SessionID,
		"match_claims", req.IdentityMatch.ClaimPaths())

	return &PrepareIssuanceReply{
		CredentialOffer: offer,
		IssuerState:     issuerState,
		ExpiresAt:       authCtx.ExpiresAt,
	}, nil
}

// validateIdentityMatchIsAskable refuses a rule that names a claim the
// presentation request will not ask the Wallet for.
//
// The DCQL this scope's challenge produces is built from the configured
// authentication scopes' auth_claims (see buildIssuanceAuthDCQL), and a
// privacy-preserving Wallet discloses what it was asked for and no more.
// So a rule naming anything outside those lists cannot be evaluated: the
// claim never arrives, matchPresentedIdentity refuses, and the prepared
// issuance is one that can never be redeemed by anyone.
//
// Refused here rather than widened into the request. Adding the caller's
// paths to the DCQL would make an API caller able to decide what this
// Issuer asks Holders to disclose, which is an operator's decision and is
// configured as one.
//
// Satisfiable by ONE authentication scope is enough. A deployment with
// several lets a Holder authenticate with any of them; a presentation of a
// scope that does not carry the matched claim then fails the match, which
// is the correct outcome and not this check's business. What this check
// catches is the rule no presentation at all could satisfy.
func (c *Client) validateIdentityMatchIsAskable(scope string, match *openid4vci.IdentityMatch) error {
	if len(match.Claims) == 0 {
		return nil
	}

	vpAuth := c.cfg.GetOpenID4VPAuth(scope)
	if vpAuth == nil || len(vpAuth.AuthScopes) == 0 {
		return helpers.NewErrorDetailsWithStatus("invalid_identity_match",
			fmt.Sprintf("scope %q has no authentication scopes configured, so no claim could be matched on", scope), 400)
	}

	// Compared as the claims path pointers the REQUEST carries. A dotted
	// rule path is read the way the authentication scope's credential
	// reads it, so for an mdoc both "family_name" and
	// "org.iso.18013.5.1.family_name" name the
	// ["org.iso.18013.5.1", "family_name"] the request asks for, and the
	// comparison is about the claim rather than how it was spelled.
	offered := make(map[string][]string, len(vpAuth.AuthScopes))
	for _, authScope := range slices.Sorted(maps.Keys(vpAuth.AuthScopes)) {
		claims := vpAuth.AuthScopes[authScope].AuthClaims
		offered[authScope] = renderPaths(claims)
		shape, err := c.cfg.PresentedShape(authScope)
		if err != nil {
			return err
		}
		if coversAll(shape, claims, match.Claims) {
			return nil
		}
	}

	return helpers.NewErrorDetailsWithStatus("invalid_identity_match",
		fmt.Sprintf("no authentication scope for %q discloses every claim this rule matches on (%s); "+
			"the authentication scopes offer %v, and the presentation request asks for those and nothing else",
			scope, strings.Join(match.ClaimPaths(), ", "), offered), 400)
}

// coversAll reports whether every claim of a rule is one of claims, with a
// dotted rule path read in shape.
func coversAll(shape claimpath.Shape, claims []claimpath.Pointer, matches openid4vci.ClaimMatches) bool {
	for _, match := range matches {
		path := match.Path
		if err := path.Resolve(shape.Dotted); err != nil || !slices.ContainsFunc(claims, path.Equal) {
			return false
		}
	}
	return true
}

// renderPaths renders claims path pointers for a message.
func renderPaths(paths []claimpath.Pointer) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, path.String())
	}
	return out
}
