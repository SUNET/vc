package cache

import (
	"context"
)

// AuthProviderFields are the four values that say which auth provider, and
// which credential source, will serve a context. Plain strings so this
// package stays independent of pkg/model.
type AuthProviderFields struct {
	AuthProvider    string
	DataSource      string
	RemoteName      string
	AuthenticSource string
}

// AuthContextStore defines the interface for authorization context storage.
// Implementations can use in-memory caching, MongoDB, or other backends.
// This abstraction enables horizontal scaling (HA) by allowing shared storage backends.
type AuthContextStore interface {
	// Save stores an authorization context with sessionID as primary key.
	Save(ctx context.Context, doc *AuthorizationContext) error

	// Create is an alias for Save.
	Create(ctx context.Context, doc *AuthorizationContext) error

	// Get retrieves an authorization context by query fields (sessionID, requestURI, code, state, etc.).
	Get(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error)

	// GetSnapshot retrieves a context the way Get does, but returns a
	// copy the caller owns rather than the stored document.
	//
	// Get hands back the stored document itself, which is what lets a
	// caller mutate it and persist with Update. That also makes every
	// reader a writer's neighbour: reading the fields it was given races
	// with any concurrent claim mutating the same struct, and several
	// requests do reach the Authorization Challenge Endpoint with one
	// issuer_state while one of them is consuming it.
	//
	// Use this wherever a context is only READ. A caller that goes on to
	// Update must use Get: writing a snapshot back would replace whatever
	// an in-store mutation - a forfeited code, a redeemed pre-authorized
	// code, an added token - had recorded in the meantime.
	GetSnapshot(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error)

	// GetByID retrieves an authorization context by session ID.
	GetByID(ctx context.Context, id string) (*AuthorizationContext, error)

	// GetByAuthorizationCode retrieves an authorization context by authorization code.
	GetByAuthorizationCode(ctx context.Context, code string) (*AuthorizationContext, error)

	// GetByAccessToken retrieves an authorization context by access token.
	GetByAccessToken(ctx context.Context, token string) (*AuthorizationContext, error)

	// GetWithAccessToken retrieves an authorization context by access token (legacy method).
	GetWithAccessToken(ctx context.Context, token string) (*AuthorizationContext, error)

	// Update updates an existing authorization context.
	Update(ctx context.Context, doc *AuthorizationContext) error

	// Delete removes an authorization context by session ID.
	Delete(ctx context.Context, id string) error

	// ForfeitAuthorizationCode marks an authorization code as used and returns the updated context.
	ForfeitAuthorizationCode(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error)

	// ClaimAuthSession atomically takes the Interactive Authorization handle
	// off the context it names and returns that context as it was BEFORE
	// the handle was removed.
	//
	// Only the handle is removed. AuthSessionDPoPThumbprint stays, because
	// the authorization code this exchange produces inherits that binding
	// and the Token Endpoint enforces it at redemption.
	//
	// The returned document has the handle cleared as well. The caller
	// already has it, and anything downstream that persists the document
	// would otherwise write it back and make the exchange claimable again.
	//
	// Exactly one caller can claim a given handle. A second attempt, and a
	// concurrent one that had already resolved the same handle, both get
	// ErrNoDocuments. That is what makes one exchange yield one
	// authorization code: clearing the field and calling Update cannot,
	// because the memory store hands out the stored pointer and the Mongo
	// store replaces unconditionally.
	ClaimAuthSession(ctx context.Context, authSession string) (*AuthorizationContext, error)

	// ClaimIssuerState atomically replaces the issuer-initiated handle with
	// the exchange that claims it, and returns the document as it now
	// stands.
	//
	// opened is the whole document the claimant wants stored: the context
	// as it was read, with the handle cleared and the wallet's half filled
	// in. One mutation, filtered on the handle - which gives the same
	// one-shot guarantee as ClaimAuthSession, for the same reason (an
	// issuance prepared for one Holder must open one exchange, not one per
	// wallet that scans the offer) AND makes the claim and the opened
	// exchange inseparable.
	//
	// That second property is the point of the signature. Claiming and
	// then persisting as two writes leaves a window where the first
	// succeeded and the second did not: the document has lost its
	// issuer_state and never gained an auth_session, so the prepared
	// issuance is unreachable by either handle and nothing can recover it.
	// A transient store failure must not be able to destroy a prepared
	// issuance.
	ClaimIssuerState(ctx context.Context, issuerState string, opened *AuthorizationContext) (*AuthorizationContext, error)

	// ResumeIssuerState claims the issuer-initiated handle AND records the
	// exchange that replaces it, in one store operation.
	//
	// ClaimIssuerState followed by Update does the same thing in two, and
	// the gap between them is a hole: the prepared issuance is consumed by
	// the first call and the resumable exchange only exists after the
	// second, so a failure in between destroys an issuance that nothing
	// re-prepares. A wallet is then holding a handle the server has eaten
	// and no auth_session to continue with, over a server-side fault it
	// did nothing to cause.
	//
	// Same one-shot guarantee as ClaimIssuerState: exactly one caller
	// wins, everyone else gets ErrNoDocuments. The returned document is
	// the resumed one - after the write, not before - because that is the
	// state the caller goes on to answer from.
	ResumeIssuerState(ctx context.Context, issuerState string, resume *IssuerStateResume) (*AuthorizationContext, error)

	// RedeemPreAuthorizedCode allows a pre-authorized code to be redeemed by multiple
	// distinct clients (per DPoP thumbprint). Returns the auth context or an error if
	// the same client attempts to redeem the code twice.
	RedeemPreAuthorizedCode(ctx context.Context, code, dpopThumbprint string) (*AuthorizationContext, error)

	// ConsumeTXCodeAttempt atomically records a tx_code (PIN) attempt against
	// a pre-authorized code and returns the updated context. If the code has
	// already reached MaxTXCodeAttempts, the code is forfeited and
	// ErrTXCodeAttemptsExceeded is returned so callers can reject further
	// guesses without leaking whether the PIN was correct.
	ConsumeTXCodeAttempt(ctx context.Context, code string) (*AuthorizationContext, error)

	// MarkCodeAsForfeited marks an authorization code as forfeited by session ID.
	MarkCodeAsForfeited(ctx context.Context, id string) error

	// Consent marks an authorization context as consented.
	Consent(ctx context.Context, query *AuthorizationContext) error

	// ExtendExpiry moves the expiry of the context query names out to
	// expiresAt, and is how the short life of whatever started a flow -
	// a request_uri, an auth_session - is kept separate from the
	// authorization code's. It never shortens: a value at or before the
	// stored one leaves the document alone.
	//
	// query is resolved the same way Get resolves one, so a caller holding
	// a session_id need not have a request_uri: the browser flow extends by
	// the request_uri it is consuming, and Interactive Authorization by the
	// session whose auth_session it has just claimed and which therefore no
	// longer has a handle to name.
	//
	// It moves the logical deadline only. A store with its own physical
	// lifetime - MongoDB's TTL index is anchored to created_at - still
	// deletes the document on its own schedule, so callers must keep the
	// extended deadline inside that window rather than assume this buys
	// more time than the store will hold.
	ExtendExpiry(ctx context.Context, query *AuthorizationContext, expiresAt int64) error

	// SetAuthProvider records which auth provider, and which credential
	// source, will serve a context.
	//
	// A targeted write rather than Update, and that is the point of it
	// existing: Update replaces the whole document, so persisting these
	// four fields from a copy read a moment earlier also writes back every
	// OTHER field as it was then - including expires_at, undoing an
	// ExtendExpiry that a concurrent request had already applied. The
	// never-shortens guarantee is only worth having if nothing else
	// overwrites the field behind it.
	SetAuthProvider(ctx context.Context, sessionID string, fields AuthProviderFields) error

	// AddToken adds a token to an authorization context identified by code.
	AddToken(ctx context.Context, code string, token *Token) error

	// GetByRefreshToken retrieves an authorization context by refresh token.
	GetByRefreshToken(ctx context.Context, refreshToken string) (*AuthorizationContext, error)

	// RotateRefreshToken atomically replaces oldToken with the fields in updated,
	// but only if the document still holds oldToken. Returns ErrNoDocuments if the
	// old token was already consumed by a concurrent request, enforcing one-time use.
	RotateRefreshToken(ctx context.Context, oldToken string, updated *AuthorizationContext) error

	// SetAuthenticSource sets the authentic source for an authorization context.
	SetAuthenticSource(ctx context.Context, query *AuthorizationContext, authenticSource string) error

	// SetIdentifier sets the resolved identifier on an authorization context.
	SetIdentifier(ctx context.Context, query *AuthorizationContext, identifier string) error
}

// Compile-time checks that backends implement the interface.
var (
	_ AuthContextStore = (*MemoryStore)(nil)
	_ AuthContextStore = (*MongoStore)(nil)
)
