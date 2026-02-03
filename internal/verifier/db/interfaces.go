package db

import (
	"context"
)

// SessionStore defines the interface for OIDC session operations
type SessionStore interface {
	Create(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, id string) (*Session, error)
	GetByAuthorizationCode(ctx context.Context, code string) (*Session, error)
	GetByAccessToken(ctx context.Context, token string) (*Session, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id string) error
	MarkCodeAsUsed(ctx context.Context, id string) error
}

// ClientStore defines the interface for OIDC client operations
type ClientStore interface {
	GetByClientID(ctx context.Context, clientID string) (*Client, error)
	Create(ctx context.Context, client *Client) error
	Update(ctx context.Context, client *Client) error
	Delete(ctx context.Context, clientID string) error
}

// Ensure concrete types implement the interfaces
var _ SessionStore = (*SessionCollection)(nil)
var _ ClientStore = (*ClientCollection)(nil)
