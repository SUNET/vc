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

	// RedeemPreAuthorizedCode allows a pre-authorized code to be redeemed by multiple
	// distinct clients (per DPoP thumbprint). Returns the auth context or an error if
	// the same client attempts to redeem the code twice.
	RedeemPreAuthorizedCode(ctx context.Context, code, dpopThumbprint string) (*AuthorizationContext, error)

	// MarkCodeAsForfeited marks an authorization code as forfeited by session ID.
	MarkCodeAsForfeited(ctx context.Context, id string) error

	// Consent marks an authorization context as consented.
	Consent(ctx context.Context, query *AuthorizationContext) error

	// AddToken adds a token to an authorization context identified by code.
	AddToken(ctx context.Context, code string, token *Token) error

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
