package cache

import (
	"context"
	"fmt"
	"testing"
	"time"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemoryStore(t *testing.T) {
	cache := NewMemoryStore(5 * time.Minute)
	require.NotNil(t, cache)
	assert.NotNil(t, cache.cache)
	assert.NotNil(t, cache.indices)
	assert.Empty(t, cache.indices)
}

func TestSave_Success(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:  "session-123",
		RequestURI: "https://example.com/request",
		Code:       "auth-code-456",
		State:      "state-789",
	}

	err := cache.Save(ctx, doc)
	require.NoError(t, err)

	// Verify primary key storage
	item := cache.cache.Get("session-123")
	require.NotNil(t, item)
	assert.Equal(t, "session-123", item.Value().SessionID)

	// Verify secondary indices
	cache.mu.RLock()
	assert.Equal(t, "session-123", cache.indices["request_uri:https://example.com/request"])
	assert.Equal(t, "session-123", cache.indices["code:auth-code-456"])
	assert.Equal(t, "session-123", cache.indices["state:state-789"])
	cache.mu.RUnlock()
}

func TestSave_WithAllIndices(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:                "session-all",
		RequestURI:               "https://example.com/req",
		Code:                     "code-123",
		State:                    "state-456",
		VerifierResponseCode:     "verifier-789",
		EphemeralEncryptionKeyID: "ephemeral-abc",
		RequestObjectID:          "request-obj-def",
		Token: &Token{
			AccessToken: "access-token-xyz",
		},
	}

	err := cache.Save(ctx, doc)
	require.NoError(t, err)

	// Verify all indices are created
	cache.mu.RLock()
	assert.Equal(t, "session-all", cache.indices["request_uri:https://example.com/req"])
	assert.Equal(t, "session-all", cache.indices["code:code-123"])
	assert.Equal(t, "session-all", cache.indices["state:state-456"])
	assert.Equal(t, "session-all", cache.indices["verifier_response_code:verifier-789"])
	assert.Equal(t, "session-all", cache.indices["ephemeral_key_id:ephemeral-abc"])
	assert.Equal(t, "session-all", cache.indices["request_object_id:request-obj-def"])
	assert.Equal(t, "session-all", cache.indices["access_token:access-token-xyz"])
	cache.mu.RUnlock()
}

func TestSave_NilDocument(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	err := cache.Save(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "document cannot be nil")
}

func TestSave_EmptySessionID(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		RequestURI: "https://example.com/request",
	}

	err := cache.Save(ctx, doc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sessionID is required")
}

func TestGet_BySessionID(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-direct",
		Code:      "code-123",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{SessionID: "session-direct"}
	result, err := cache.Get(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, "session-direct", result.SessionID)
	assert.Equal(t, "code-123", result.Code)
}

func TestGet_ByRequestURI(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:  "session-uri",
		RequestURI: "https://example.com/unique-request",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{RequestURI: "https://example.com/unique-request"}
	result, err := cache.Get(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, "session-uri", result.SessionID)
}

func TestGet_ByCode(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-code",
		Code:      "unique-code-789",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{Code: "unique-code-789"}
	result, err := cache.Get(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, "session-code", result.SessionID)
}

func TestGet_ByState(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-state",
		State:     "unique-state-abc",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{State: "unique-state-abc"}
	result, err := cache.Get(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, "session-state", result.SessionID)
}

func TestGet_ByVerifierResponseCode(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:            "session-verifier",
		VerifierResponseCode: "verifier-code-xyz",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{VerifierResponseCode: "verifier-code-xyz"}
	result, err := cache.Get(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, "session-verifier", result.SessionID)
}

func TestGet_ByEphemeralKeyID(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:                "session-ephemeral",
		EphemeralEncryptionKeyID: "ephemeral-key-123",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{EphemeralEncryptionKeyID: "ephemeral-key-123"}
	result, err := cache.Get(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, "session-ephemeral", result.SessionID)
}

func TestGet_ByRequestObjectID(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:       "session-request-obj",
		RequestObjectID: "request-object-456",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{RequestObjectID: "request-object-456"}
	result, err := cache.Get(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, "session-request-obj", result.SessionID)
}

func TestGet_NilQuery(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	result, err := cache.Get(ctx, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "query cannot be nil")
}

func TestGet_NoSearchFields(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{} // Empty query
	result, err := cache.Get(ctx, query)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "query must have at least one search field")
}

func TestGet_NotFound(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{SessionID: "non-existent"}
	result, err := cache.Get(ctx, query)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrNoDocuments, err)
}

func TestGet_IndexNotFound(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{Code: "non-existent-code"}
	result, err := cache.Get(ctx, query)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrNoDocuments, err)
}

func TestGetWithAccessToken_Success(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-token",
		Token: &Token{
			AccessToken: "unique-access-token-xyz",
		},
	}
	require.NoError(t, cache.Save(ctx, doc))

	result, err := cache.GetWithAccessToken(ctx, "unique-access-token-xyz")
	require.NoError(t, err)
	assert.Equal(t, "session-token", result.SessionID)
	assert.Equal(t, "unique-access-token-xyz", result.Token.AccessToken)
}

func TestGetWithAccessToken_EmptyToken(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	result, err := cache.GetWithAccessToken(ctx, "")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "token cannot be empty")
}

func TestGetWithAccessToken_NotFound(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	result, err := cache.GetWithAccessToken(ctx, "non-existent-token")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrNoDocuments, err)
}

func TestForfeitAuthorizationCode_ByCode(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-forfeit",
		Code:      "code-to-forfeit",
		Forfeited: false,
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{Code: "code-to-forfeit"}
	result, err := cache.ForfeitAuthorizationCode(ctx, query)
	require.NoError(t, err)
	assert.True(t, result.Forfeited)

	// Verify the change persisted
	retrieved, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-forfeit"})
	require.NoError(t, err)
	assert.True(t, retrieved.Forfeited)
}

func TestForfeitAuthorizationCode_ByRequestURI(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:  "session-forfeit-uri",
		RequestURI: "https://example.com/forfeit-request",
		Forfeited:  false,
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{RequestURI: "https://example.com/forfeit-request"}
	result, err := cache.ForfeitAuthorizationCode(ctx, query)
	require.NoError(t, err)
	assert.True(t, result.Forfeited)
}

func TestForfeitAuthorizationCode_NilQuery(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	result, err := cache.ForfeitAuthorizationCode(ctx, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "query cannot be nil")
}

func TestForfeitAuthorizationCode_NoCodeOrRequestURI(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{SessionID: "session-123"}
	result, err := cache.ForfeitAuthorizationCode(ctx, query)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "query must have code or request_uri")
}

func TestForfeitAuthorizationCode_NotFound(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{Code: "non-existent-code"}
	result, err := cache.ForfeitAuthorizationCode(ctx, query)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrNoDocuments, err)
}

func TestForfeitAuthorizationCode_AlreadyUsed(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-already-used",
		Code:      "code-already-used",
		Forfeited: false,
	}
	require.NoError(t, cache.Save(ctx, doc))

	// First forfeit - should succeed
	query := &AuthorizationContext{Code: "code-already-used"}
	result, err := cache.ForfeitAuthorizationCode(ctx, query)
	require.NoError(t, err)
	assert.True(t, result.Forfeited)

	// Second forfeit attempt - trying to reuse an already-used authorization code
	// This should fail as it's a security violation (code replay attack)
	result2, err := cache.ForfeitAuthorizationCode(ctx, query)
	assert.Error(t, err, "Attempting to forfeit an already-forfeited code should fail")
	assert.Nil(t, result2)
	assert.Contains(t, err.Error(), "already forfeited", "Error should indicate the code was already forfeited")

	// Verify the context remains marked as forfeited
	retrieved, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-already-used"})
	require.NoError(t, err)
	assert.True(t, retrieved.Forfeited, "Context should remain marked as forfeited")
}

func TestConsent_Success(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:  "session-consent",
		RequestURI: "https://example.com/consent-request",
		Consent:    false,
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{RequestURI: "https://example.com/consent-request"}
	err := cache.Consent(ctx, query)
	require.NoError(t, err)

	// Verify the change persisted
	retrieved, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-consent"})
	require.NoError(t, err)
	assert.True(t, retrieved.Consent)
}

func TestConsent_NilQuery(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	err := cache.Consent(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request_uri cannot be empty")
}

func TestConsent_EmptyRequestURI(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{SessionID: "session-123"}
	err := cache.Consent(ctx, query)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request_uri cannot be empty")
}

func TestConsent_NotFound(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{RequestURI: "https://example.com/non-existent"}
	err := cache.Consent(ctx, query)
	assert.Error(t, err)
	assert.Equal(t, ErrNoDocuments, err)
}

func TestAddToken_Success(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-add-token",
		Code:      "code-for-token",
	}
	require.NoError(t, cache.Save(ctx, doc))

	token := &Token{
		AccessToken: "new-access-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	err := cache.AddToken(ctx, "code-for-token", token)
	require.NoError(t, err)

	// Verify the token was added
	retrieved, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-add-token"})
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", retrieved.Token.AccessToken)
	assert.Equal(t, token.ExpiresAt, retrieved.Token.ExpiresAt)

	// Verify access token index was created
	cache.mu.RLock()
	assert.Equal(t, "session-add-token", cache.indices["access_token:new-access-token"])
	cache.mu.RUnlock()
}

func TestAddToken_EmptyCode(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	token := &Token{AccessToken: "token-123"}
	err := cache.AddToken(ctx, "", token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "code cannot be empty")
}

func TestAddToken_NotFound(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	token := &Token{AccessToken: "token-123"}
	err := cache.AddToken(ctx, "non-existent-code", token)
	assert.Error(t, err)
	assert.Equal(t, ErrNoDocuments, err)
}

func TestSetAuthenticSource_Success(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-auth-source",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{SessionID: "session-auth-source"}
	err := cache.SetAuthenticSource(ctx, query, "authentic-source-123")
	require.NoError(t, err)

	// Verify the change persisted
	retrieved, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-auth-source"})
	require.NoError(t, err)
	assert.Equal(t, "authentic-source-123", retrieved.AuthenticSource)
}

func TestSetAuthenticSource_EmptySource(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{SessionID: "session-123"}
	err := cache.SetAuthenticSource(ctx, query, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentic source cannot be empty")
}

func TestSetAuthenticSource_NilQuery(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	err := cache.SetAuthenticSource(ctx, nil, "source-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session_id cannot be empty")
}

func TestSetAuthenticSource_EmptySessionID(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{}
	err := cache.SetAuthenticSource(ctx, query, "source-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session_id cannot be empty")
}

func TestSetAuthenticSource_NotFound(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{SessionID: "non-existent"}
	err := cache.SetAuthenticSource(ctx, query, "source-123")
	assert.Error(t, err)
	assert.Equal(t, ErrNoDocuments, err)
}

func TestAddIdentity_BySessionID(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID: "session-add-identity",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{SessionID: "session-add-identity"}
	input := &AuthorizationContext{
		Identity: &model.Identity{
			GivenName:  "John",
			FamilyName: "Doe",
		},
		VCT:             "urn:eudi:pid:1",
		AuthenticSource: "test-source",
	}

	err := cache.AddIdentity(ctx, query, input)
	require.NoError(t, err)

	// Verify the identity was added
	retrieved, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-add-identity"})
	require.NoError(t, err)
	assert.Equal(t, "John", retrieved.Identity.GivenName)
	assert.Equal(t, "Doe", retrieved.Identity.FamilyName)
	assert.Equal(t, "urn:eudi:pid:1", retrieved.VCT)
	assert.Equal(t, "test-source", retrieved.AuthenticSource)
}

func TestAddIdentity_ByRequestURI(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:  "session-identity-uri",
		RequestURI: "https://example.com/identity-request",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{RequestURI: "https://example.com/identity-request"}
	input := &AuthorizationContext{
		Identity: &model.Identity{
			GivenName: "Jane",
		},
	}

	err := cache.AddIdentity(ctx, query, input)
	require.NoError(t, err)

	// Verify the identity was added
	retrieved, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-identity-uri"})
	require.NoError(t, err)
	assert.Equal(t, "Jane", retrieved.Identity.GivenName)
}

func TestAddIdentity_ByEphemeralKeyID(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	doc := &AuthorizationContext{
		SessionID:                "session-identity-key",
		EphemeralEncryptionKeyID: "ephemeral-key-456",
	}
	require.NoError(t, cache.Save(ctx, doc))

	query := &AuthorizationContext{EphemeralEncryptionKeyID: "ephemeral-key-456"}
	input := &AuthorizationContext{
		Identity: &model.Identity{
			GivenName: "Bob",
		},
	}

	err := cache.AddIdentity(ctx, query, input)
	require.NoError(t, err)

	// Verify the identity was added
	retrieved, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-identity-key"})
	require.NoError(t, err)
	assert.Equal(t, "Bob", retrieved.Identity.GivenName)
}

func TestAddIdentity_NilQuery(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	input := &AuthorizationContext{
		Identity: &model.Identity{GivenName: "Test"},
	}

	err := cache.AddIdentity(ctx, nil, input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "query cannot be nil")
}

func TestAddIdentity_NilInput(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{SessionID: "session-123"}
	err := cache.AddIdentity(ctx, query, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "identity cannot be nil")
}

func TestAddIdentity_NilIdentity(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{SessionID: "session-123"}
	input := &AuthorizationContext{
		VCT: "urn:eudi:pid:1",
	}

	err := cache.AddIdentity(ctx, query, input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "identity cannot be nil")
}

func TestAddIdentity_NoQueryFields(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{}
	input := &AuthorizationContext{
		Identity: &model.Identity{GivenName: "Test"},
	}

	err := cache.AddIdentity(ctx, query, input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "query must have sessionID, requestURI, or ephemeralEncryptionKeyID")
}

func TestAddIdentity_NotFound(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	query := &AuthorizationContext{SessionID: "non-existent"}
	input := &AuthorizationContext{
		Identity: &model.Identity{GivenName: "Test"},
	}

	err := cache.AddIdentity(ctx, query, input)
	assert.Error(t, err)
	assert.Equal(t, ErrNoDocuments, err)
}

func TestCacheTTL(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(100 * time.Millisecond) // Very short TTL for testing

	doc := &AuthorizationContext{
		SessionID: "session-ttl",
		Code:      "code-ttl",
	}
	require.NoError(t, cache.Save(ctx, doc))

	// Should exist immediately
	result, err := cache.Get(ctx, &AuthorizationContext{SessionID: "session-ttl"})
	require.NoError(t, err)
	assert.Equal(t, "session-ttl", result.SessionID)

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Should no longer exist
	result, err = cache.Get(ctx, &AuthorizationContext{SessionID: "session-ttl"})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrNoDocuments, err)

	// Index should also be cleaned up (implicit in the cache implementation)
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	// Create multiple documents
	for i := 0; i < 10; i++ {
		doc := &AuthorizationContext{
			SessionID: fmt.Sprintf("session-%d", i),
			Code:      fmt.Sprintf("code-%d", i),
		}
		require.NoError(t, cache.Save(ctx, doc))
	}

	// Concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		i := i
		go func() {
			defer func() { done <- true }()
			query := &AuthorizationContext{Code: fmt.Sprintf("code-%d", i)}
			result, err := cache.Get(ctx, query)
			assert.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("session-%d", i), result.SessionID)
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestUpdateIndices(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryStore(5 * time.Minute)

	// Initial save
	doc := &AuthorizationContext{
		SessionID: "session-update",
		Code:      "initial-code",
	}
	require.NoError(t, cache.Save(ctx, doc))

	// Update with new code
	doc.Code = "updated-code"
	doc.RequestURI = "https://example.com/updated"
	require.NoError(t, cache.Save(ctx, doc))

	// Verify new indices work
	result, err := cache.Get(ctx, &AuthorizationContext{Code: "updated-code"})
	require.NoError(t, err)
	assert.Equal(t, "session-update", result.SessionID)

	result, err = cache.Get(ctx, &AuthorizationContext{RequestURI: "https://example.com/updated"})
	require.NoError(t, err)
	assert.Equal(t, "session-update", result.SessionID)
}
