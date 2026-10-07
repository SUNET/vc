package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// newMongoTestLocker creates a MongoLocker backed by a real testcontainer.
// Each call gets a unique collection to isolate test state.
func newMongoTestLocker(t *testing.T, client *mongo.Client, name string) *MongoLocker {
	t.Helper()
	locker, err := NewMongoLocker(t.Context(), client, "test_cache", "lock_"+name)
	require.NoError(t, err)
	return locker
}

// TestMongoLocker_DuplicateAcquisition verifies that a held lock cannot be
// acquired a second time: the colliding insert loses and returns "".
func TestMongoLocker_DuplicateAcquisition(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	locker := newMongoTestLocker(t, client, "dup")
	ctx := t.Context()

	token, err := locker.TryLock(ctx, "k", time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	second, err := locker.TryLock(ctx, "k", time.Minute)
	require.NoError(t, err)
	assert.Empty(t, second, "a held lock cannot be acquired again")
}

// TestMongoLocker_UnlockRequiresOwnerToken verifies that only the current
// holder's token releases the lock; a non-owner release is a no-op.
func TestMongoLocker_UnlockRequiresOwnerToken(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	locker := newMongoTestLocker(t, client, "owner")
	ctx := t.Context()

	token, err := locker.TryLock(ctx, "k", time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	require.NoError(t, locker.Unlock(ctx, "k", "not-the-owner"))
	blocked, err := locker.TryLock(ctx, "k", time.Minute)
	require.NoError(t, err)
	assert.Empty(t, blocked, "a non-owner unlock must be a no-op")

	require.NoError(t, locker.Unlock(ctx, "k", token))
	reacquired, err := locker.TryLock(ctx, "k", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, reacquired, "owner unlock frees the lock")
}

// TestMongoLocker_AcquireAfterExpiry verifies that the lock is acquirable
// again once its document is gone. The TTL index reaps an expired hold on a
// ~60s sweep, too slow for a test, so deleting the document reproduces the
// same end state the sweep (or a crashed holder's expiry) leaves behind.
func TestMongoLocker_AcquireAfterExpiry(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	locker := newMongoTestLocker(t, client, "expiry")
	ctx := t.Context()

	token, err := locker.TryLock(ctx, "k", time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	_, err = locker.coll.DeleteOne(ctx, bson.M{"_id": "k"})
	require.NoError(t, err)

	reacquired, err := locker.TryLock(ctx, "k", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, reacquired, "a lock is acquirable once its document is gone")
}
