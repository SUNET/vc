package cache

import (
	"reflect"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/go-playground/validator/v10"
)

// AuthorizationContext.Validate below builds its own minimal
// *validator.Validate, because pkg/helpers.NewValidator resolves tag names
// differently (json vs. yaml-preferring) and reusing it here would change
// error messages for every other field on this struct. Only the constructor
// is separate: the safe_key guard itself comes from openid4vci.

// SessionStatus represents the status of an OIDC session
type SessionStatus string

const (
	SessionStatusPending              SessionStatus = "pending"
	SessionStatusAwaitingPresentation SessionStatus = "awaiting_presentation"
	SessionStatusCodeIssued           SessionStatus = "code_issued"
	SessionStatusTokenIssued          SessionStatus = "token_issued"
	SessionStatusCompleted            SessionStatus = "completed"
	SessionStatusExpired              SessionStatus = "expired"
	SessionStatusError                SessionStatus = "error"

	// MaxPreAuthRedeemers is the maximum number of distinct clients that can
	// redeem a single pre-authorized code. This prevents unbounded growth of
	// the RedeemedBy array and child sessions if a code leaks.
	MaxPreAuthRedeemers = 10

	// MaxTXCodeAttempts caps the number of transaction-code (PIN) attempts
	// per pre-authorized code. Once reached, the code is forfeited so an
	// attacker who obtains the code cannot brute-force the PIN by
	// distributing guesses across IPs (OID4VCI §6.3).
	MaxTXCodeAttempts = 5
)

// Token represents an access token with expiration
type Token struct {
	AccessToken    string `json:"access_token" bson:"access_token" validate:"required,max=4096,printascii"`
	ExpiresAt      int64  `json:"expires_at" bson:"expires_at" validate:"required"`
	DPoPThumbprint string `json:"dpop_thumbprint,omitempty" bson:"dpop_thumbprint,omitempty" validate:"omitempty,max=128,printascii"`
}

// AuthorizationContext is the unified model for OIDC/OpenID4VP sessions
// It supports both issuer credential issuance flows and verifier presentation/RP flows
type AuthorizationContext struct {
	// Core session fields
	SessionID string        `json:"session_id" bson:"session_id" validate:"required,max=128,printascii"`
	Status    SessionStatus `json:"status,omitempty" bson:"status,omitempty" validate:"omitempty,max=32,printascii"`
	CreatedAt time.Time     `json:"created_at" bson:"created_at,omitempty"`
	ExpiresAt int64         `json:"expires_at" bson:"expires_at"`

	// SourceSessionID references the parent session from which this session was
	// derived. Used in the pre-authorized code flow where each client redemption
	// creates a new child session that still needs access to the original
	// session's credential documents.
	SourceSessionID string `json:"source_session_id,omitempty" bson:"source_session_id,omitempty" validate:"omitempty,max=128,printascii"`

	// Client and authorization fields
	// ClientID is this deployment's own identifier for the flow - the
	// issuance path stores "x509_san_dns:<host>", and the verifier stores an
	// RP client_id. WalletClientID is the one the wallet sent, in PAR.
	//
	// Both are 512 characters, not 128, because the wallet's may be a DID: a
	// did:jwk over a P-256 key is around 175. The bound is kept in step with
	// openid4vci.TokenRequest.ClientID, where the same wallet-supplied value
	// arrives at the token endpoint.
	ClientID            string   `json:"client_id" bson:"client_id" validate:"omitempty,max=512,printascii"`
	WalletClientID      string   `json:"wallet_client_id,omitempty" bson:"wallet_client_id,omitempty" validate:"omitempty,max=512,printascii"`
	Scopes              []string `json:"scopes,omitempty" bson:"scopes,omitempty"`
	State               string   `json:"state,omitempty" bson:"state,omitempty" validate:"omitempty,max=500,printascii"`
	Nonce               string   `json:"nonce,omitempty" bson:"nonce,omitempty" validate:"omitempty,max=128,printascii"`
	CodeChallenge       string   `json:"code_challenge,omitempty" bson:"code_challenge,omitempty" validate:"omitempty,max=128,printascii"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty" bson:"code_challenge_method,omitempty" validate:"omitempty,max=16,printascii"`

	// AuthSession is the opaque handle that carries one Interactive
	// Authorization exchange across its several requests (OpenID4VCI 1.1,
	// profiling draft-ietf-oauth-first-party-apps §5.3.1).
	//
	// Opaque to the wallet, and REGENERATED on every challenge response -
	// the specification requires each response to carry a distinct value,
	// so this is rotated rather than reused. The wallet echoes the most
	// recent one.
	//
	// Looking the context up by this value, rather than by anything the
	// presentation itself carries, is what defends against session
	// fixation: a presentation answering some other exchange's nonce
	// cannot resolve to this context at all.
	AuthSession string `json:"auth_session,omitempty" bson:"auth_session,omitempty" validate:"omitempty,max=128,printascii"`

	// IssuerState is the handle an issuer-initiated Credential Offer
	// carries, joining a session the Issuer already has - a portal where
	// the user authenticated and chose what is being issued - to the
	// wallet-initiated exchange that follows.
	//
	// OpenID4VCI 1.0 defines it for the Authorization Endpoint. Nothing
	// in the 1.1 Interactive Authorization text says how an
	// issuer-initiated offer reaches the Authorization Challenge
	// Endpoint, so this server accepts it there too
	// (openid/OpenID4VCI#815); see the Challenge Endpoint's own
	// documentation.
	IssuerState string `json:"issuer_state,omitempty" bson:"issuer_state,omitempty" validate:"omitempty,max=128,printascii"`

	// IdentityMatch is the rule the preparing caller supplied for
	// deciding whether the Holder who presents a credential is the one
	// this issuance was prepared for.
	//
	// Carried on the context rather than taken from configuration because
	// only the caller knows what "the same user" means for its own
	// session. Nil means no such rule was given, which is a different
	// thing from a rule that matches anything - IdentityMatch.Validate
	// refuses the latter.
	IdentityMatch *openid4vci.IdentityMatch `json:"identity_match,omitempty" bson:"identity_match,omitempty" validate:"omitempty"`

	// AuthSessionDPoPThumbprint binds the Interactive Authorization
	// exchange to the DPoP key that began it, when DPoP is in use.
	//
	// Distinct from Token.DPoPThumbprint, which is set when an access
	// token is issued and so does not exist yet during this exchange.
	// OpenID4VCI 1.1 requires every request carrying an auth_session to
	// present the same key, so it has to be recorded at the start.
	AuthSessionDPoPThumbprint string `json:"auth_session_dpop_thumbprint,omitempty" bson:"auth_session_dpop_thumbprint,omitempty" validate:"omitempty,max=128,printascii"`

	// InteractiveAuthorization marks a context opened by the
	// Authorization Challenge Endpoint, so that it can only be answered
	// there.
	//
	// The channel is part of what the request said. An Interactive
	// Authorization request names ia_post.jwt and carries the challenge
	// endpoint's origin in expected_origins, and the endpoint verifies
	// holder binding before it will accept the presentation. The
	// browser-mediated /verification/direct_post endpoint resolves a
	// context by EphemeralEncryptionKeyID - which this context also has,
	// and whose kid the wallet was given in the request's client_metadata
	// - and runs the same pipeline WITHOUT that verification.
	//
	// So without this marker the two channels were interchangeable in one
	// direction: a wallet could complete its own challenge honestly, then
	// post a copied credential with a self-signed key binding proof to the
	// other endpoint, overwrite VerifiedClaims on the context its own
	// authorization code belongs to, and redeem that code for a credential
	// built from someone else's claims. Clearing the auth_session does not
	// stop it, because that only removes the auth_session index.
	//
	// A bool rather than a cleared field, for the same reason
	// AuthSessionDPoPThumbprint is: it has to survive the handle being
	// consumed, which is exactly when the attack is available.
	InteractiveAuthorization bool `json:"interactive_authorization,omitempty" bson:"interactive_authorization,omitempty"`

	// Authorization code fields
	Code      string `json:"code,omitempty" bson:"code,omitempty" validate:"omitempty,max=128,printascii"`
	Forfeited bool   `json:"forfeited,omitempty" bson:"forfeited,omitempty"`

	// PreAuthorized marks the context as belonging to an OID4VCI
	// pre-authorized code offer. The token endpoint rejects cross-grant
	// use so a pre-auth code cannot be redeemed via authorization_code
	// (which would skip the tx_code check) and vice versa.
	PreAuthorized bool `json:"pre_authorized,omitempty" bson:"pre_authorized,omitempty"`

	// RedeemedBy tracks DPoP thumbprints that have redeemed a pre-authorized code.
	// Pre-authorized codes may be redeemed by multiple distinct clients (each
	// identified by a unique DPoP key), but a given client must not redeem
	// the same code twice.
	RedeemedBy []string `json:"redeemed_by,omitempty" bson:"redeemed_by,omitempty"`

	// TXCode is the transaction code (PIN) the wallet must present at the
	// token endpoint for a pre-authorized credential offer. Empty when the
	// offer does not require a PIN. Bound matches openid4vci.TokenRequest.TXCode.
	TXCode string `json:"tx_code,omitempty" bson:"tx_code,omitempty" validate:"omitempty,max=64,printascii"`

	// TXCodeAttempts counts the number of tx_code (PIN) attempts consumed
	// for this pre-authorized code. Bounded by MaxTXCodeAttempts.
	TXCodeAttempts int `json:"tx_code_attempts,omitempty" bson:"tx_code_attempts,omitempty"`

	// Token fields
	Token       *Token `json:"token,omitempty" bson:"token,omitempty"`
	AccessToken string `json:"access_token,omitempty" bson:"access_token,omitempty" validate:"omitempty,max=16384,printascii"`
	IDToken     string `json:"id_token,omitempty" bson:"id_token,omitempty" validate:"omitempty,max=32768,printascii"`

	// Issuer-specific fields (credential issuance)
	AuthorizationDetails []openid4vci.AuthorizationDetailsParameter `json:"authorization_details,omitempty" bson:"authorization_details,omitempty"`
	RequestURI           string                                     `json:"request_uri,omitempty" bson:"request_uri,omitempty" validate:"omitempty,max=2048,printascii"`
	// RequestURIExpiresAt is the request_uri's own deadline; ExpiresAt is extended to the code's at /authorize.
	RequestURIExpiresAt int64  `json:"request_uri_expires_at,omitempty" bson:"request_uri_expires_at,omitempty"`
	WalletURI           string `json:"redirect_url,omitempty" bson:"redirect_url,omitempty" validate:"omitempty,max=2048,printascii"`
	Consent             bool   `json:"consent,omitempty" bson:"consent,omitempty"`
	AuthenticSource     string `json:"authentic_source,omitempty" bson:"authentic_source,omitempty" validate:"omitempty,max=128,printascii"`
	Scope               string `json:"scope,omitempty" bson:"scope,omitempty" validate:"omitempty,max=128,printascii"`
	Identifier          string `json:"identifier,omitempty" bson:"identifier,omitempty" validate:"omitempty,max=256,printascii"`
	AuthProvider        string `json:"auth_provider,omitempty" bson:"auth_provider,omitempty" validate:"omitempty,max=32,printascii"`
	DataSource          string `json:"data_source,omitempty" bson:"data_source,omitempty" validate:"omitempty,max=32,printascii"`
	RemoteName          string `json:"remote_name,omitempty" bson:"remote_name,omitempty" validate:"omitempty,max=128,printascii"`

	// DynamicParams holds key-value parameters bound directly from the PAR
	// caller's request body at flow initiation time (see PARRequest.DynamicParams
	// for why the name is misleading: nothing here verifies these actually
	// came from an authentic source business system). Used only for template
	// substitution in outgoing OIDC request parameters (e.g., acr_values,
	// claims) -- deliberately NOT used for issuance policy evaluation, which
	// is gated on OP-asserted claims instead.
	DynamicParams map[string]string `json:"dynamic_params,omitempty" bson:"dynamic_params,omitempty" validate:"omitempty,dive,keys,safe_key,endkeys,max=1024,printascii"`

	// Verifier-specific fields (presentation/RP flows)
	RedirectURI           string `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty" validate:"omitempty,max=2048,printascii"`
	ResponseType          string `json:"response_type,omitempty" bson:"response_type,omitempty" validate:"omitempty,max=32,printascii"`
	ResponseMode          string `json:"response_mode,omitempty" bson:"response_mode,omitempty" validate:"omitempty,max=32,printascii"`
	ShowCredentialDetails bool   `json:"show_credential_details,omitempty" bson:"show_credential_details,omitempty"`
	// WalletFollowsRedirect is set when the user leaves /authorize for a
	// same-device web wallet. ProcessDirectPost then returns redirect_uri so
	// the wallet can send the browser back to the RP. Cross-device flows
	// leave this false; the /authorize page poller performs the redirect.
	WalletFollowsRedirect  bool           `json:"wallet_follows_redirect,omitempty" bson:"wallet_follows_redirect,omitempty"`
	CodeExpiresAt          int64          `json:"code_expires_at,omitempty" bson:"code_expires_at,omitempty"`                 // Unix timestamp
	AccessTokenExpiresAt   int64          `json:"access_token_expires_at,omitempty" bson:"access_token_expires_at,omitempty"` // Unix timestamp
	RefreshToken           string         `json:"refresh_token,omitempty" bson:"refresh_token,omitempty" validate:"omitempty,max=4096,printascii"`
	RefreshTokenExpiresAt  int64          `json:"refresh_token_expires_at,omitempty" bson:"refresh_token_expires_at,omitempty"` // Unix timestamp
	VerifiedClaims         map[string]any `json:"verified_claims,omitempty" bson:"verified_claims,omitempty"`
	VPToken                string         `json:"vp_token,omitempty" bson:"vp_token,omitempty" validate:"omitempty,max=65536,printascii"`
	PresentationSubmission any            `json:"presentation_submission,omitempty" bson:"presentation_submission,omitempty"`

	// OpenID4VP fields (wallet interaction)
	EphemeralEncryptionKeyID string `json:"ephemeral_encryption_key_id,omitempty" bson:"ephemeral_encryption_key_id,omitempty" validate:"omitempty,max=128,printascii"`
	VerifierResponseCode     string `json:"verifier_response_code,omitempty" bson:"verifier_response_code,omitempty" validate:"omitempty,max=128,printascii"`

	// Error and ErrorDescription record an Authorization Error Response
	// the Wallet returned instead of a presentation - most often
	// access_denied, which OpenID4VP 1.0 section 8.5 defines as covering
	// a lack of End-User consent.
	//
	// Recorded rather than merely logged, because a declined request is
	// an OUTCOME. Without it the session has no terminal state at all:
	// /ui/completion reports pending until the cache evicts the context,
	// so the relying party waits for an answer the user already gave.
	//
	// ErrorDescription is the Wallet's own text and is bounded and
	// printable-checked like every other field here: it crosses from a
	// wallet into a verifier's UI.
	Error              string          `json:"error,omitempty" bson:"error,omitempty" validate:"omitempty,max=64,printascii"`
	ErrorDescription   string          `json:"error_description,omitempty" bson:"error_description,omitempty" validate:"omitempty,max=512"`
	RequestObjectID    string          `json:"request_object_id,omitempty" bson:"request_object_id,omitempty" validate:"omitempty,max=128,printascii"`
	RequestObjectNonce string          `json:"request_object_nonce,omitempty" bson:"request_object_nonce,omitempty" validate:"omitempty,max=128,printascii"`
	DCQLQuery          *openid4vp.DCQL `json:"dcql_query,omitempty" bson:"dcql_query,omitempty"`
	// ScopeQueryIDs maps a requested scope to the id of the DCQL credential
	// query that stands for it, for the scopes where the two differ.
	//
	// A wallet keys vp_token by query id, not by scope (OpenID4VP 1.0), and a
	// template names its queries whatever its author chose - the shipped PID
	// template asks for "eudi_pid" while the request uses scope "pid" - so
	// without this the verifier reads a key the wallet never sent.
	//
	// Only differing pairs are stored; an absent entry looks up directly.
	ScopeQueryIDs map[string]string                      `json:"scope_query_ids,omitempty" bson:"scope_query_ids,omitempty"`
	Validations   map[string][]openid4vp.ClaimValidation `json:"validations,omitempty" bson:"validations,omitempty" validate:"omitempty,dive,dive"`
	WalletID      string                                 `json:"wallet_id,omitempty" bson:"wallet_id,omitempty" validate:"omitempty,max=128,printascii"`
}

// Validate checks the AuthorizationContext against its struct validation tags.
func (a *AuthorizationContext) Validate() error {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name, _, _ := strings.Cut(fld.Tag.Get("json"), ",")
		if name == "-" {
			return ""
		}
		return name
	})
	if err := openid4vci.RegisterSafeKey(v); err != nil {
		return err
	}
	return v.Struct(a)
}
