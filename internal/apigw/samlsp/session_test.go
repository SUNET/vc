package samlsp

import (
	"testing"
	"time"

	"vc/pkg/cache"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionCache_SetAndGet(t *testing.T) {
	ctx := t.Context()
	sc := cache.NewMemoryCache[*Session](3600 * time.Second)
	defer sc.Stop()

	session := &Session{
		ID:             "test-session-id",
		CredentialType: "pid",
		IDPEntityID:    "https://idp.example.com",
		CreatedAt:      time.Now(),
	}

	// Store session
	sc.Set(ctx, session.ID, session)

	// Retrieve session
	retrieved, ok := sc.Get(ctx, session.ID)
	require.True(t, ok)
	assert.Equal(t, session.ID, retrieved.ID)
	assert.Equal(t, session.CredentialType, retrieved.CredentialType)
	assert.Equal(t, session.IDPEntityID, retrieved.IDPEntityID)
}

func TestSessionCache_GetNonExistent(t *testing.T) {
	ctx := t.Context()
	sc := cache.NewMemoryCache[*Session](3600 * time.Second)
	defer sc.Stop()

	// Try to get non-existent session
	_, ok := sc.Get(ctx, "non-existent-id")
	assert.False(t, ok)
}

func TestSessionCache_Expiration(t *testing.T) {
	ctx := t.Context()
	// Create cache with very short TTL (1 second)
	sc := cache.NewMemoryCache[*Session](1 * time.Second)
	defer sc.Stop()

	session := &Session{
		ID:             "expiring-session",
		CredentialType: "diploma",
		IDPEntityID:    "https://idp.example.com",
		CreatedAt:      time.Now(),
	}

	sc.Set(ctx, session.ID, session)

	// Session should exist immediately
	retrieved, ok := sc.Get(ctx, session.ID)
	require.True(t, ok)
	assert.Equal(t, session.ID, retrieved.ID)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Session should be expired
	_, ok = sc.Get(ctx, session.ID)
	assert.False(t, ok)
}

func TestSessionCache_Delete(t *testing.T) {
	ctx := t.Context()
	sc := cache.NewMemoryCache[*Session](3600 * time.Second)
	defer sc.Stop()

	session := &Session{
		ID:             "deletable-session",
		CredentialType: "ehic",
		IDPEntityID:    "https://idp.example.com",
		CreatedAt:      time.Now(),
	}

	// Store and verify
	sc.Set(ctx, session.ID, session)
	_, ok := sc.Get(ctx, session.ID)
	require.True(t, ok)

	// Delete
	sc.Delete(ctx, session.ID)

	// Should not exist
	_, ok = sc.Get(ctx, session.ID)
	assert.False(t, ok)
}

func TestSessionCache_MultipleSessionsIndependent(t *testing.T) {
	ctx := t.Context()
	sc := cache.NewMemoryCache[*Session](3600 * time.Second)
	defer sc.Stop()

	session1 := &Session{
		ID:             "session-1",
		CredentialType: "pid",
		IDPEntityID:    "https://idp1.example.com",
		CreatedAt:      time.Now(),
	}

	session2 := &Session{
		ID:             "session-2",
		CredentialType: "diploma",
		IDPEntityID:    "https://idp2.example.com",
		CreatedAt:      time.Now(),
	}

	// Store both
	sc.Set(ctx, session1.ID, session1)
	sc.Set(ctx, session2.ID, session2)

	// Retrieve independently
	retrieved1, ok := sc.Get(ctx, session1.ID)
	require.True(t, ok)
	assert.Equal(t, "pid", retrieved1.CredentialType)

	retrieved2, ok := sc.Get(ctx, session2.ID)
	require.True(t, ok)
	assert.Equal(t, "diploma", retrieved2.CredentialType)

	// Delete one shouldn't affect the other
	sc.Delete(ctx, session1.ID)

	_, ok = sc.Get(ctx, session1.ID)
	assert.False(t, ok)

	retrieved2Again, ok := sc.Get(ctx, session2.ID)
	require.True(t, ok)
	assert.Equal(t, session2.ID, retrieved2Again.ID)
}
