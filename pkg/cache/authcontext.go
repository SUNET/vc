package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

var ErrNoDocuments = errors.New("no documents found")

// AuthContextCache implements authorization context storage using ttlcache
type AuthContextCache struct {
	// Primary storage: sessionID -> AuthorizationContext
	cache *ttlcache.Cache[string, *AuthorizationContext]
	// Secondary indices: various fields -> sessionID
	indices map[string]string
	mu      sync.RWMutex
}

// NewAuthContextCache creates a new cache-based authorization context store
func NewAuthContextCache(ttl time.Duration) *AuthContextCache {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, *AuthorizationContext](ttl),
	)

	// Start automatic expired item deletion
	go cache.Start()

	return &AuthContextCache{
		cache:   cache,
		indices: make(map[string]string),
	}
}

// Save stores an authorization context in the cache with sessionID as primary key
func (c *AuthContextCache) Save(ctx context.Context, doc *AuthorizationContext) error {
	if doc == nil {
		return errors.New("document cannot be nil")
	}

	if doc.SessionID == "" {
		return errors.New("sessionID is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Store by primary key (sessionID)
	c.cache.Set(doc.SessionID, doc, ttlcache.DefaultTTL)

	// Create secondary indices for lookups by other fields
	if doc.RequestURI != "" {
		c.indices[fmt.Sprintf("request_uri:%s", doc.RequestURI)] = doc.SessionID
	}
	if doc.Code != "" {
		c.indices[fmt.Sprintf("code:%s", doc.Code)] = doc.SessionID
	}
	if doc.State != "" {
		c.indices[fmt.Sprintf("state:%s", doc.State)] = doc.SessionID
	}
	if doc.VerifierResponseCode != "" {
		c.indices[fmt.Sprintf("verifier_response_code:%s", doc.VerifierResponseCode)] = doc.SessionID
	}
	if doc.EphemeralEncryptionKeyID != "" {
		c.indices[fmt.Sprintf("ephemeral_key_id:%s", doc.EphemeralEncryptionKeyID)] = doc.SessionID
	}
	if doc.RequestObjectID != "" {
		c.indices[fmt.Sprintf("request_object_id:%s", doc.RequestObjectID)] = doc.SessionID
	}
	if doc.Token != nil && doc.Token.AccessToken != "" {
		c.indices[fmt.Sprintf("access_token:%s", doc.Token.AccessToken)] = doc.SessionID
	}

	return nil
}

// Get retrieves an authorization context by query fields
func (c *AuthContextCache) Get(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error) {
	if query == nil {
		return nil, errors.New("query cannot be nil")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var sessionID string

	// If sessionID is provided directly, use it
	if query.SessionID != "" {
		sessionID = query.SessionID
	} else {
		// Otherwise, look up sessionID via secondary indices
		var indexKey string

		if query.RequestURI != "" {
			indexKey = fmt.Sprintf("request_uri:%s", query.RequestURI)
		} else if query.Code != "" {
			indexKey = fmt.Sprintf("code:%s", query.Code)
		} else if query.State != "" {
			indexKey = fmt.Sprintf("state:%s", query.State)
		} else if query.VerifierResponseCode != "" {
			indexKey = fmt.Sprintf("verifier_response_code:%s", query.VerifierResponseCode)
		} else if query.EphemeralEncryptionKeyID != "" {
			indexKey = fmt.Sprintf("ephemeral_key_id:%s", query.EphemeralEncryptionKeyID)
		} else if query.RequestObjectID != "" {
			indexKey = fmt.Sprintf("request_object_id:%s", query.RequestObjectID)
		} else {
			return nil, errors.New("query must have at least one search field")
		}

		var ok bool
		sessionID, ok = c.indices[indexKey]
		if !ok {
			return nil, ErrNoDocuments
		}
	}

	// Retrieve from primary cache using sessionID
	item := c.cache.Get(sessionID)
	if item == nil {
		return nil, ErrNoDocuments
	}

	return item.Value(), nil
}

// GetWithAccessToken retrieves an authorization context by access token
func (c *AuthContextCache) GetWithAccessToken(ctx context.Context, token string) (*AuthorizationContext, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	indexKey := fmt.Sprintf("access_token:%s", token)
	sessionID, ok := c.indices[indexKey]
	if !ok {
		return nil, ErrNoDocuments
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		return nil, ErrNoDocuments
	}

	return item.Value(), nil
}

// ForfeitAuthorizationCode marks an authorization code as used
func (c *AuthContextCache) ForfeitAuthorizationCode(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error) {
	if query == nil {
		return nil, errors.New("query cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var sessionID string
	var ok bool

	if query.Code != "" {
		indexKey := fmt.Sprintf("code:%s", query.Code)
		sessionID, ok = c.indices[indexKey]
	} else if query.RequestURI != "" {
		indexKey := fmt.Sprintf("request_uri:%s", query.RequestURI)
		sessionID, ok = c.indices[indexKey]
	} else {
		return nil, errors.New("query must have code or request_uri")
	}

	if !ok {
		return nil, ErrNoDocuments
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		return nil, ErrNoDocuments
	}

	doc := item.Value()

	// Check if the code has already been forfeited (security check for replay attacks)
	if doc.Forfeited {
		return nil, errors.New("authorization code already forfeited")
	}

	doc.Forfeited = true

	// Update the primary cache entry
	c.cache.Set(sessionID, doc, ttlcache.DefaultTTL)

	// Update indices if needed
	c.updateIndices(doc)

	return doc, nil
}

// Consent marks an authorization context as consented
func (c *AuthContextCache) Consent(ctx context.Context, query *AuthorizationContext) error {
	if query == nil || query.RequestURI == "" {
		return errors.New("request_uri cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	indexKey := fmt.Sprintf("request_uri:%s", query.RequestURI)
	sessionID, ok := c.indices[indexKey]
	if !ok {
		return ErrNoDocuments
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		return ErrNoDocuments
	}

	doc := item.Value()
	doc.Consent = true

	// Update the primary cache entry
	c.cache.Set(sessionID, doc, ttlcache.DefaultTTL)

	// Update indices if needed
	c.updateIndices(doc)

	return nil
}

// AddToken adds a token to an authorization context
func (c *AuthContextCache) AddToken(ctx context.Context, code string, token *Token) error {
	if code == "" {
		return errors.New("code cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	indexKey := fmt.Sprintf("code:%s", code)
	sessionID, ok := c.indices[indexKey]
	if !ok {
		return ErrNoDocuments
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		return ErrNoDocuments
	}

	doc := item.Value()
	doc.Token = token

	// Update the primary cache entry
	c.cache.Set(sessionID, doc, ttlcache.DefaultTTL)

	// Update indices with new access token
	c.updateIndices(doc)

	return nil
}

// SetAuthenticSource sets the authentic source for an authorization context
func (c *AuthContextCache) SetAuthenticSource(ctx context.Context, query *AuthorizationContext, authenticSource string) error {
	if authenticSource == "" {
		return errors.New("authentic source cannot be empty")
	}
	if query == nil || query.SessionID == "" {
		return errors.New("session_id cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	sessionID := query.SessionID
	item := c.cache.Get(sessionID)
	if item == nil {
		return ErrNoDocuments
	}

	doc := item.Value()
	doc.AuthenticSource = authenticSource

	// Update the primary cache entry
	c.cache.Set(sessionID, doc, ttlcache.DefaultTTL)

	return nil
}

// AddIdentity adds identity information to an authorization context
func (c *AuthContextCache) AddIdentity(ctx context.Context, query *AuthorizationContext, input *AuthorizationContext) error {
	if query == nil {
		return errors.New("query cannot be nil")
	}
	if input == nil || input.Identity == nil {
		return errors.New("identity cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var sessionID string
	var ok bool

	if query.SessionID != "" {
		sessionID = query.SessionID
		ok = true
	} else if query.RequestURI != "" {
		indexKey := fmt.Sprintf("request_uri:%s", query.RequestURI)
		sessionID, ok = c.indices[indexKey]
	} else if query.EphemeralEncryptionKeyID != "" {
		indexKey := fmt.Sprintf("ephemeral_key_id:%s", query.EphemeralEncryptionKeyID)
		sessionID, ok = c.indices[indexKey]
	} else {
		return errors.New("query must have sessionID, requestURI, or ephemeralEncryptionKeyID")
	}

	if !ok {
		return ErrNoDocuments
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		return ErrNoDocuments
	}

	doc := item.Value()
	doc.Identity = input.Identity
	doc.VCT = input.VCT
	doc.AuthenticSource = input.AuthenticSource

	// Update the primary cache entry
	c.cache.Set(sessionID, doc, ttlcache.DefaultTTL)

	return nil
}

// updateIndices updates secondary indices for a document (must be called with lock held)
func (c *AuthContextCache) updateIndices(doc *AuthorizationContext) {
	if doc.RequestURI != "" {
		c.indices[fmt.Sprintf("request_uri:%s", doc.RequestURI)] = doc.SessionID
	}
	if doc.Code != "" {
		c.indices[fmt.Sprintf("code:%s", doc.Code)] = doc.SessionID
	}
	if doc.State != "" {
		c.indices[fmt.Sprintf("state:%s", doc.State)] = doc.SessionID
	}
	if doc.VerifierResponseCode != "" {
		c.indices[fmt.Sprintf("verifier_response_code:%s", doc.VerifierResponseCode)] = doc.SessionID
	}
	if doc.EphemeralEncryptionKeyID != "" {
		c.indices[fmt.Sprintf("ephemeral_key_id:%s", doc.EphemeralEncryptionKeyID)] = doc.SessionID
	}
	if doc.RequestObjectID != "" {
		c.indices[fmt.Sprintf("request_object_id:%s", doc.RequestObjectID)] = doc.SessionID
	}
	if doc.Token != nil && doc.Token.AccessToken != "" {
		c.indices[fmt.Sprintf("access_token:%s", doc.Token.AccessToken)] = doc.SessionID
	}
}
