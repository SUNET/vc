package db

import (
	"context"
)

// ClientStore defines the interface for OIDC client operations
type ClientStore interface {
	GetByClientID(ctx context.Context, clientID string) (*Client, error)
	Create(ctx context.Context, client *Client) error
	Update(ctx context.Context, client *Client) error
	Delete(ctx context.Context, clientID string) error
}

// Ensure concrete types implement the interfaces
var _ ClientStore = (*ClientCollection)(nil)
