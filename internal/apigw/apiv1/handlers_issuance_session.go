package apiv1

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
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
type PrepareIssuanceRequest struct {
	// Scope is the credential being prepared.
	Scope string `json:"scope" validate:"required"`

	// IdentityMatch decides whether the Holder who turns up is the one
	// this issuance was prepared for.
	//
	// REQUIRED. An issuance prepared without one is an offer anybody's
	// wallet may complete, which is what the pre-authorized grant already
	// provides and what this endpoint exists to improve on. A caller that
	// wants that should ask for it by name rather than by omission.
	IdentityMatch *openid4vci.IdentityMatch `json:"identity_match" validate:"required"`

	// TTLSeconds bounds how long the offer may be left unredeemed.
	// Optional; the server's default applies when it is absent.
	TTLSeconds int `json:"ttl_seconds,omitempty" validate:"omitempty,gt=0"`
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
	if err := req.IdentityMatch.Validate(); err != nil {
		return nil, helpers.NewErrorDetailsWithStatus("invalid_identity_match", err.Error(), 400)
	}

	// The scope has to be one a presentation can authenticate, or there is
	// no point at which the rule could be evaluated.
	source, err := c.openID4VPCredentialSource(req.Scope)
	if err != nil {
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
