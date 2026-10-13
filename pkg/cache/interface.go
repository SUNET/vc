package cache

import (
	"context"
)

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

	// ExtendExpiry moves the expiry of the context the request_uri in query
	// names out to expiresAt, and is how a request_uri's short life is kept
	// separate from the authorization code's. It never shortens: a value
	// at or before the stored one leaves the document alone.
	//
	// It moves the logical deadline only. A store with its own physical
	// lifetime - MongoDB's TTL index is anchored to created_at - still
	// deletes the document on its own schedule, so callers must keep the
	// extended deadline inside that window rather than assume this buys
	// more time than the store will hold.
	ExtendExpiry(ctx context.Context, query *AuthorizationContext, expiresAt int64) error

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
