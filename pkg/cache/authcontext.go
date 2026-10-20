package cache

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

var ErrNoDocuments = errors.New("no documents found")

// ErrTXCodeAttemptsExceeded is returned by ConsumeTXCodeAttempt when the
// pre-authorized code has already used its MaxTXCodeAttempts budget. When
// this happens the code is atomically forfeited to prevent further guesses.
var ErrTXCodeAttemptsExceeded = errors.New("tx_code attempt limit exceeded")

// MemoryStore implements authorization context storage using an in-memory ttlcache.
// Suitable for single-instance deployments.
type MemoryStore struct {
	// Primary storage: sessionID -> AuthorizationContext
	cache *ttlcache.Cache[string, *AuthorizationContext]
	// Secondary indices: various fields -> sessionID
	indices map[string]string
	mu      sync.RWMutex
	ttl     time.Duration
}

// TTL returns how long this store retains an authorization context.
//
// Retention is a configured value rather than a constant, and it has to
// cover the deadlines checked against the contexts it holds, so callers
// need to be able to read back what they got.
func (s *MemoryStore) TTL() time.Duration {
	return s.ttl
}

// NewMemoryStore creates a new in-memory authorization context store.
func NewMemoryStore(ttl time.Duration) *MemoryStore {
	s := &MemoryStore{
		indices: make(map[string]string),
		ttl:     ttl,
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
	if doc.AuthSession != "" {
		c.indices[fmt.Sprintf("auth_session:%s", doc.AuthSession)] = doc.SessionID
	}
	if doc.IssuerState != "" {
		c.indices[fmt.Sprintf("issuer_state:%s", doc.IssuerState)] = doc.SessionID
	}
	if doc.Token != nil && doc.Token.AccessToken != "" {
		c.indices[fmt.Sprintf("access_token:%s", doc.Token.AccessToken)] = doc.SessionID
	}
	if doc.AccessToken != "" {
		c.indices[fmt.Sprintf("access_token:%s", doc.AccessToken)] = doc.SessionID
	}
	if doc.RefreshToken != "" {
		c.indices[fmt.Sprintf("refresh_token:%s", doc.RefreshToken)] = doc.SessionID
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

	// The same resolver ExtendExpiry uses, so the two cannot drift: the
	// list of fields a context can be found by belongs in one place.
	sessionID, err := c.resolveSessionIDLocked(query)
	if err != nil {
		return nil, err
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
	if slices.Contains(doc.RedeemedBy, dpopThumbprint) {
		return nil, errors.New("pre-authorized code already redeemed by this client")
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

// ConsumeTXCodeAttempt atomically records a tx_code attempt on a
// pre-authorized code. When the attempt budget is exhausted the code is
// forfeited in the same critical section so concurrent guesses cannot slip
// past the cap.
func (c *MemoryStore) ConsumeTXCodeAttempt(ctx context.Context, code string) (*AuthorizationContext, error) {
	if code == "" {
		return nil, errors.New("code cannot be empty")
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

	if doc.Forfeited {
		return nil, errors.New("pre-authorized code has been forfeited")
	}

	if doc.TXCodeAttempts >= MaxTXCodeAttempts {
		doc.Forfeited = true
		c.cache.Set(sessionID, doc, ttlcache.PreviousOrDefaultTTL)
		return nil, ErrTXCodeAttemptsExceeded
	}

	doc.TXCodeAttempts++
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

// ExtendExpiry moves the expiry of the context request_uri names out to
// expiresAt. See AuthContextStore.ExtendExpiry.
func (c *MemoryStore) ExtendExpiry(ctx context.Context, query *AuthorizationContext, expiresAt int64) error {
	if query == nil {
		return errors.New("query cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	sessionID, err := c.resolveSessionIDLocked(query)
	if err != nil {
		return err
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		return ErrNoDocuments
	}

	stored := item.Value()
	if stored.ExpiresAt >= expiresAt {
		return nil
	}

	// A COPY, replacing the cached pointer, rather than a write through
	// it.
	//
	// Get hands out the pointer this cache holds and returns before the
	// caller is done with it, so a reader can be looking at the document
	// while this runs - /authorize reads ExpiresAt on a context it fetched
	// a moment earlier, and two overlapping authorization requests put a
	// read and this write on the same field. The lock here does not help:
	// the reader never takes it, because it is not calling this store at
	// all any more, it is holding a pointer it was given.
	updated := *stored
	updated.ExpiresAt = expiresAt

	c.cache.Set(sessionID, &updated, ttlcache.DefaultTTL)
	c.updateIndices(&updated)

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

// GetByRefreshToken retrieves an authorization context by refresh token.
func (c *MemoryStore) GetByRefreshToken(ctx context.Context, refreshToken string) (*AuthorizationContext, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh_token cannot be empty")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	indexKey := fmt.Sprintf("refresh_token:%s", refreshToken)
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

// RotateRefreshToken atomically replaces oldToken with the fields in updated,
// but only if the document still holds oldToken.
func (c *MemoryStore) RotateRefreshToken(ctx context.Context, oldToken string, updated *AuthorizationContext) error {
	if oldToken == "" {
		return errors.New("old refresh token cannot be empty")
	}
	if updated == nil || updated.SessionID == "" {
		return errors.New("updated document with session_id is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	indexKey := fmt.Sprintf("refresh_token:%s", oldToken)
	sessionID, ok := c.indices[indexKey]
	if !ok {
		return ErrNoDocuments
	}

	// Enforce that the caller's document belongs to the same session.
	if updated.SessionID != sessionID {
		return fmt.Errorf("session_id mismatch: index resolves to %q but updated document has %q", sessionID, updated.SessionID)
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		return ErrNoDocuments
	}

	// Verify the document still holds the old refresh token (compare-and-swap).
	doc := item.Value()
	if doc.RefreshToken != oldToken {
		return ErrNoDocuments
	}

	// Remove stale indices before overwriting.
	c.deleteIndices(doc)

	// Persist the updated document and rebuild indices under the resolved sessionID.
	c.cache.Set(sessionID, updated, ttlcache.DefaultTTL)
	c.updateIndices(updated)

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
	if doc.AuthSession != "" {
		c.indices[fmt.Sprintf("auth_session:%s", doc.AuthSession)] = doc.SessionID
	}
	if doc.IssuerState != "" {
		c.indices[fmt.Sprintf("issuer_state:%s", doc.IssuerState)] = doc.SessionID
	}
	if doc.Token != nil && doc.Token.AccessToken != "" {
		c.indices[fmt.Sprintf("access_token:%s", doc.Token.AccessToken)] = doc.SessionID
	}
	if doc.AccessToken != "" {
		c.indices[fmt.Sprintf("access_token:%s", doc.AccessToken)] = doc.SessionID
	}
	if doc.RefreshToken != "" {
		c.indices[fmt.Sprintf("refresh_token:%s", doc.RefreshToken)] = doc.SessionID
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

	// Remove stale indices from the old document before overwriting.
	// This prevents rotated tokens (e.g. refresh_token) from remaining resolvable.
	c.deleteIndices(item.Value())

	// Update in cache
	c.cache.Set(doc.SessionID, doc, ttlcache.DefaultTTL)

	// Rebuild secondary indices from the new document
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
	if doc.AuthSession != "" {
		delete(c.indices, fmt.Sprintf("auth_session:%s", doc.AuthSession))
	}
	if doc.IssuerState != "" {
		delete(c.indices, fmt.Sprintf("issuer_state:%s", doc.IssuerState))
	}
	if doc.Token != nil && doc.Token.AccessToken != "" {
		delete(c.indices, fmt.Sprintf("access_token:%s", doc.Token.AccessToken))
	}
	if doc.AccessToken != "" {
		delete(c.indices, fmt.Sprintf("access_token:%s", doc.AccessToken))
	}
	if doc.RefreshToken != "" {
		delete(c.indices, fmt.Sprintf("refresh_token:%s", doc.RefreshToken))
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
	if doc.Forfeited {
		return errors.New("authorization code already forfeited")
	}
	doc.Forfeited = true

	// Update the primary cache entry
	c.cache.Set(id, doc, ttlcache.DefaultTTL)

	return nil
}

// Create is an alias for Save to match the Session API
func (c *MemoryStore) Create(ctx context.Context, doc *AuthorizationContext) error {
	return c.Save(ctx, doc)
}

// ClaimAuthSession atomically takes the Interactive Authorization handle
// off the context it names. See AuthContextStore.ClaimAuthSession.
func (c *MemoryStore) ClaimAuthSession(ctx context.Context, authSession string) (*AuthorizationContext, error) {
	if authSession == "" {
		return nil, errors.New("authSession cannot be empty")
	}
	return c.claimIndexedHandle("auth_session", authSession,
		func(doc *AuthorizationContext) string { return doc.AuthSession },
		func(doc *AuthorizationContext) {
			// Only the handle. AuthSessionDPoPThumbprint is the binding
			// the authorization code inherits, and the Token Endpoint
			// checks it when the code is redeemed - clearing it here would
			// hand out a code that any key could spend.
			doc.AuthSession = ""
		})
}

// ClaimIssuerState atomically replaces the issuer-initiated handle with the
// exchange that claims it. See AuthContextStore.ClaimIssuerState.
//
// One mutation under the lock: the handle is read, checked and replaced
// without releasing it, so a second caller finds nothing to claim and
// there is no moment at which the document has neither handle.
func (c *MemoryStore) ClaimIssuerState(ctx context.Context, issuerState string, opened *AuthorizationContext) (*AuthorizationContext, error) {
	if issuerState == "" {
		return nil, errors.New("issuerState cannot be empty")
	}
	if opened == nil || opened.SessionID == "" {
		return nil, errors.New("opened document with session_id is required")
	}

	// Validated before anything is touched, as MongoStore does, so a
	// malformed replacement leaves the issuer_state claimable.
	stored := *opened
	stored.IssuerState = ""
	if err := stored.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	indexKey := "issuer_state:" + issuerState
	sessionID, ok := c.indices[indexKey]
	if !ok {
		return nil, ErrNoDocuments
	}
	if sessionID != opened.SessionID {
		return nil, ErrNoDocuments
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		delete(c.indices, indexKey)
		return nil, ErrNoDocuments
	}

	// The index could name a session whose handle has already been
	// replaced; treat that as unclaimed rather than trusting the index.
	if item.Value().IssuerState != issuerState {
		return nil, ErrNoDocuments
	}

	// The claimant's document wins wholesale, with the handle gone from
	// it (cleared on stored above): anything that persisted a document
	// still carrying the handle would re-create its index and make the
	// issuance claimable again.

	// The OLD document's indices go first, exactly as Update does it.
	//
	// A resume replaces the whole document, and it rotates fields that
	// are indexed - EphemeralEncryptionKeyID above all, which is minted
	// afresh so the key's life matches the exchange's. Deleting only the
	// issuer_state index left the prepared key id pointing at the
	// replacement, so the old kid went on resolving the live exchange
	// after the rotation that exists to retire it, and nothing ever
	// removed the entry: eviction cleans up the indices of the document
	// it evicts, which by then names only the current kid.
	//
	// updateIndices below rebuilds the ones the new document actually
	// has, so this removes stale entries rather than needed ones.
	c.deleteIndices(item.Value())

	delete(c.indices, indexKey)
	c.cache.Set(sessionID, &stored, ttlcache.DefaultTTL)
	c.updateIndices(&stored)

	claimed := stored
	return &claimed, nil
}

// claimIndexedHandle is the shared body of the two claims: resolve a
// one-shot handle through its index, take it off the stored document AND
// off the returned copy, and let exactly one caller have it.
//
// The handle is cleared on the returned copy too, not just the stored
// one. The caller already has it - it is what they asked with - and
// anything downstream that persists this document would otherwise write
// it straight back and make the handle resolvable again. That is not
// hypothetical: finalisePresentationVerification updates the context it
// is handed, so a presentation-sourced scope resurrected the handle it
// had just consumed.
func (c *MemoryStore) claimIndexedHandle(indexPrefix, handle string, read func(*AuthorizationContext) string, clear func(*AuthorizationContext)) (*AuthorizationContext, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	indexKey := fmt.Sprintf("%s:%s", indexPrefix, handle)
	sessionID, ok := c.indices[indexKey]
	if !ok {
		return nil, ErrNoDocuments
	}

	item := c.cache.Get(sessionID)
	if item == nil {
		delete(c.indices, indexKey)
		return nil, ErrNoDocuments
	}

	stored := item.Value()

	// The index could name a session whose handle has already been
	// replaced; treat that as unclaimed rather than trusting the index.
	if read(stored) != handle {
		return nil, ErrNoDocuments
	}

	claimed := *stored
	clear(&claimed)

	// A REPLACEMENT document, not a write into the stored one.
	//
	// Get returns the cached pointer and then releases the lock, so a
	// caller that fetched this context before the claim is still reading
	// the very struct a write here would touch - `go test -race` names
	// this line against a reader of the handle field. Replacing the
	// pointer leaves that reader with a consistent pre-claim snapshot and
	// makes the post-claim state reachable only through the cache, which
	// is where it belongs.
	//
	// Separate from `claimed` on purpose: the caller must not be able to
	// reach the stored document through the value it is handed either.
	//
	// Only the handle is cleared, by the caller's own clear func. The
	// bindings the authorization code inherits - AuthSessionDPoPThumbprint
	// among them - are checked when the code is redeemed, and clearing one
	// here would hand out a code that any key could spend.
	replacement := *stored
	clear(&replacement)
	delete(c.indices, indexKey)
	// Claiming must not extend the code's lifetime; the Mongo $unset does not either.
	c.cache.Set(sessionID, &replacement, ttlcache.PreviousOrDefaultTTL)

	return &claimed, nil
}

// resolveSessionIDLocked turns a query into the session it names, by the
// same fields Get accepts. The caller must hold the lock.
func (c *MemoryStore) resolveSessionIDLocked(query *AuthorizationContext) (string, error) {
	if query.SessionID != "" {
		return query.SessionID, nil
	}
	// Every field Get resolves by, in the order Get tries them. The two
	// must agree: ExtendExpiry's contract promises the same query fields,
	// and three were missing here - VerifierResponseCode,
	// EphemeralEncryptionKeyID and RequestObjectID - so a query that Get
	// and Mongo's ExtendExpiry both answered failed in memory with "no
	// searchable field set". A backend difference that only shows up for
	// some callers is worse than either behaviour on its own.
	for _, index := range []struct{ name, value string }{
		{"request_uri", query.RequestURI},
		{"code", query.Code},
		{"state", query.State},
		{"verifier_response_code", query.VerifierResponseCode},
		{"ephemeral_key_id", query.EphemeralEncryptionKeyID},
		{"request_object_id", query.RequestObjectID},
		{"auth_session", query.AuthSession},
		{"issuer_state", query.IssuerState},
	} {
		if index.value == "" {
			continue
		}
		sessionID, ok := c.indices[index.name+":"+index.value]
		if !ok {
			return "", ErrNoDocuments
		}
		return sessionID, nil
	}
	return "", errors.New("no searchable field set on the query")
}

// SetAuthProvider records the provider and credential source on a context.
// See AuthContextStore.SetAuthProvider for why it is not an Update.
func (c *MemoryStore) SetAuthProvider(ctx context.Context, sessionID string, fields AuthProviderFields) error {
	if sessionID == "" {
		return errors.New("sessionID is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	item := c.cache.Get(sessionID)
	if item == nil {
		return ErrNoDocuments
	}

	// Copied for the same reason ExtendExpiry copies: a caller holding a
	// pointer Get handed out would otherwise see these four fields change
	// underneath it, and /authorize is exactly such a caller - it reads
	// the context, then this runs against the same session.
	updated := *item.Value()
	updated.AuthProvider = fields.AuthProvider
	updated.DataSource = fields.DataSource
	updated.RemoteName = fields.RemoteName
	updated.AuthenticSource = fields.AuthenticSource

	c.cache.Set(sessionID, &updated, ttlcache.DefaultTTL)
	c.updateIndices(&updated)

	return nil
}
