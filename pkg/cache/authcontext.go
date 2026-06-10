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

// MemoryStore implements authorization context storage using an in-memory ttlcache.
// Suitable for single-instance deployments.
type MemoryStore struct {
	// Primary storage: sessionID -> AuthorizationContext
	cache *ttlcache.Cache[string, *AuthorizationContext]
	// Secondary indices: various fields -> sessionID
	indices map[string]string
	mu      sync.RWMutex
}

// NewMemoryStore creates a new in-memory authorization context store.
func NewMemoryStore(ttl time.Duration) *MemoryStore {
	s := &MemoryStore{
		indices: make(map[string]string),
	}

	c := ttlcache.New(
		ttlcache.WithTTL[string, *AuthorizationContext](ttl),
	)

	// Clean up secondary indices when entries are automatically evicted.
	c.OnEviction(func(_ context.Context, _ ttlcache.EvictionReason, item *ttlcache.Item[string, *AuthorizationContext]) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.deleteIndices(item.Value())
	})

	// Start automatic expired item deletion
	go c.Start()

	s.cache = c
	return s
}

// Save stores an authorization context in the cache with sessionID as primary key
func (c *MemoryStore) Save(ctx context.Context, doc *AuthorizationContext) error {
	if doc == nil {
		return errors.New("document cannot be nil")
	}

	if doc.SessionID == "" {
		return errors.New("sessionID is required")
	}

	if err := doc.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
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
	if doc.AccessToken != "" {
		c.indices[fmt.Sprintf("access_token:%s", doc.AccessToken)] = doc.SessionID
	}

	return nil
}

// Get retrieves an authorization context by query fields
func (c *MemoryStore) Get(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error) {
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
func (c *MemoryStore) GetWithAccessToken(ctx context.Context, token string) (*AuthorizationContext, error) {
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
func (c *MemoryStore) ForfeitAuthorizationCode(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error) {
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

// RedeemPreAuthorizedCode allows a pre-authorized code to be redeemed by
// multiple distinct clients (identified by DPoP thumbprint). Each client may
// redeem the code only once. This implements OID4VCI §4.1.1 "single use" on a
// per-client basis: the code is single-use for each wallet, but the same
// credential offer can serve multiple wallets.
func (c *MemoryStore) RedeemPreAuthorizedCode(ctx context.Context, code, dpopThumbprint string) (*AuthorizationContext, error) {
	if code == "" {
		return nil, errors.New("code cannot be empty")
	}
	if dpopThumbprint == "" {
		return nil, errors.New("dpop thumbprint is required for pre-authorized code redemption")
	}
	if len(dpopThumbprint) > 128 {
		return nil, errors.New("dpop thumbprint exceeds maximum length")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	indexKey := fmt.Sprintf("code:%s", code)
	sessionID, ok := c.indices[indexKey]
	if !ok {
		return nil, ErrNoDocuments
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		return nil, ErrNoDocuments
	}

	doc := item.Value()

	// Reject redemption if the code was forfeited (e.g. non-DPoP redemption
	// already consumed it via ForfeitAuthorizationCode).
	if doc.Forfeited {
		return nil, errors.New("pre-authorized code has been forfeited")
	}

	// Check if this specific client (DPoP thumbprint) already redeemed the code
	for _, tp := range doc.RedeemedBy {
		if tp == dpopThumbprint {
			return nil, errors.New("pre-authorized code already redeemed by this client")
		}
	}

	// Enforce maximum number of distinct redeemers to prevent unbounded growth
	if len(doc.RedeemedBy) >= MaxPreAuthRedeemers {
		return nil, errors.New("pre-authorized code has reached the maximum number of redemptions")
	}

	// Record this client as having redeemed the code.
	// Use PreviousOrDefaultTTL to preserve the original TTL — repeated redemptions
	// by different clients must not extend the code's lifetime.
	doc.RedeemedBy = append(doc.RedeemedBy, dpopThumbprint)
	c.cache.Set(sessionID, doc, ttlcache.PreviousOrDefaultTTL)

	return doc, nil
}

// Consent marks an authorization context as consented
func (c *MemoryStore) Consent(ctx context.Context, query *AuthorizationContext) error {
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
func (c *MemoryStore) AddToken(ctx context.Context, code string, token *Token) error {
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
func (c *MemoryStore) SetAuthenticSource(ctx context.Context, query *AuthorizationContext, authenticSource string) error {
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

// SetIdentifier sets the resolved identifier on an authorization context.
func (c *MemoryStore) SetIdentifier(ctx context.Context, query *AuthorizationContext, identifier string) error {
	if query == nil {
		return errors.New("query cannot be nil")
	}
	if identifier == "" {
		return errors.New("identifier cannot be empty")
	}
	if query.SessionID == "" {
		return errors.New("session_id cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	item := c.cache.Get(query.SessionID)
	if item == nil {
		return ErrNoDocuments
	}

	doc := item.Value()
	doc.Identifier = identifier

	// Update the primary cache entry
	c.cache.Set(query.SessionID, doc, ttlcache.DefaultTTL)

	return nil
}

// updateIndices updates secondary indices for a document (must be called with lock held)
func (c *MemoryStore) updateIndices(doc *AuthorizationContext) {
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
	if doc.AccessToken != "" {
		c.indices[fmt.Sprintf("access_token:%s", doc.AccessToken)] = doc.SessionID
	}
}

// GetByID retrieves an authorization context by session ID
func (c *MemoryStore) GetByID(ctx context.Context, id string) (*AuthorizationContext, error) {
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	item := c.cache.Get(id)
	if item == nil {
		return nil, ErrNoDocuments
	}

	return item.Value(), nil
}

// GetByAuthorizationCode retrieves an authorization context by authorization code
func (c *MemoryStore) GetByAuthorizationCode(ctx context.Context, code string) (*AuthorizationContext, error) {
	if code == "" {
		return nil, errors.New("code cannot be empty")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	indexKey := fmt.Sprintf("code:%s", code)
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

// GetByAccessToken retrieves an authorization context by access token
func (c *MemoryStore) GetByAccessToken(ctx context.Context, token string) (*AuthorizationContext, error) {
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

// Update updates an existing authorization context
func (c *MemoryStore) Update(ctx context.Context, doc *AuthorizationContext) error {
	if doc == nil {
		return errors.New("document cannot be nil")
	}

	if doc.SessionID == "" {
		return errors.New("sessionID is required")
	}

	if err := doc.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if exists
	item := c.cache.Get(doc.SessionID)
	if item == nil {
		return ErrNoDocuments
	}

	// Update in cache
	c.cache.Set(doc.SessionID, doc, ttlcache.DefaultTTL)

	// Update secondary indices
	c.updateIndices(doc)

	return nil
}

// Delete removes an authorization context from the cache
func (c *MemoryStore) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Get the doc first to clean up indices
	item := c.cache.Get(id)
	if item != nil {
		doc := item.Value()
		// Clean up indices
		c.deleteIndices(doc)
	}

	// Delete from primary cache
	c.cache.Delete(id)

	return nil
}

// deleteIndices removes secondary indices for a document (must be called with lock held)
func (c *MemoryStore) deleteIndices(doc *AuthorizationContext) {
	if doc.RequestURI != "" {
		delete(c.indices, fmt.Sprintf("request_uri:%s", doc.RequestURI))
	}
	if doc.Code != "" {
		delete(c.indices, fmt.Sprintf("code:%s", doc.Code))
	}
	if doc.State != "" {
		delete(c.indices, fmt.Sprintf("state:%s", doc.State))
	}
	if doc.VerifierResponseCode != "" {
		delete(c.indices, fmt.Sprintf("verifier_response_code:%s", doc.VerifierResponseCode))
	}
	if doc.EphemeralEncryptionKeyID != "" {
		delete(c.indices, fmt.Sprintf("ephemeral_key_id:%s", doc.EphemeralEncryptionKeyID))
	}
	if doc.RequestObjectID != "" {
		delete(c.indices, fmt.Sprintf("request_object_id:%s", doc.RequestObjectID))
	}
	if doc.Token != nil && doc.Token.AccessToken != "" {
		delete(c.indices, fmt.Sprintf("access_token:%s", doc.Token.AccessToken))
	}
	if doc.AccessToken != "" {
		delete(c.indices, fmt.Sprintf("access_token:%s", doc.AccessToken))
	}
}

// MarkCodeAsForfeited marks an authorization code as forfeited
func (c *MemoryStore) MarkCodeAsForfeited(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	item := c.cache.Get(id)
	if item == nil {
		return ErrNoDocuments
	}

	doc := item.Value()
	doc.Forfeited = true

	// Update the primary cache entry
	c.cache.Set(id, doc, ttlcache.DefaultTTL)

	return nil
}

// Create is an alias for Save to match the Session API
func (c *MemoryStore) Create(ctx context.Context, doc *AuthorizationContext) error {
	return c.Save(ctx, doc)
}
