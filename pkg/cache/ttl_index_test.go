package cache

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Reopening an existing collection with a different TTL must work.
//
// MongoDB refuses to redefine an index through createIndexes: asking for
// {created_at: 1} with a different expireAfterSeconds returns
// IndexOptionsConflict (85). Since the verifier's retention is now derived
// from configuration, that is reached by an operator editing a duration -
// and before this, it stopped the service from starting at all.
func TestTTLIndexSurvivesADurationChange(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_change", "auth_ctx"

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int32(900), ttlOf(t, client, db, coll))

	// The same collection, reopened with a longer retention.
	_, err = NewMongoStore(ctx, client, db, coll, 60*time.Minute)
	require.NoError(t, err, "a changed TTL must not fail startup")
	assert.Equal(t, int32(3600), ttlOf(t, client, db, coll), "the TTL index was not updated")

	// ... and shorter again, so the test is not passing on "only grows".
	_, err = NewMongoStore(ctx, client, db, coll, 10*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int32(600), ttlOf(t, client, db, coll))
}

// The generic caches take the same path, and are where the request object
// and ephemeral keys live.
func TestGenericCacheTTLIndexSurvivesADurationChange(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_change_generic", "request_objects"

	_, err := NewMongoCache[string](ctx, client, db, coll, 5*time.Minute, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(300), ttlOf(t, client, db, coll))

	_, err = NewMongoCache[string](ctx, client, db, coll, 30*time.Minute, nil)
	require.NoError(t, err, "a changed TTL must not fail startup")
	assert.Equal(t, int32(1800), ttlOf(t, client, db, coll))
}

// ttlOf reads expireAfterSeconds off the created_at_1 index.
func ttlOf(t *testing.T, client *mongo.Client, db, coll string) int32 {
	t.Helper()

	cur, err := client.Database(db).Collection(coll).Indexes().List(t.Context())
	require.NoError(t, err)

	var specs []bson.M
	require.NoError(t, cur.All(t.Context(), &specs))

	for _, spec := range specs {
		if spec["name"] != createdAtTTLIndex {
			continue
		}
		v, ok := spec["expireAfterSeconds"]
		require.True(t, ok, "created_at_1 is not a TTL index")
		switch n := v.(type) {
		case int32:
			return n
		case int64:
			return int32(n)
		case float64:
			return int32(n)
		}
		t.Fatalf("unexpected expireAfterSeconds type %T", v)
	}

	t.Fatalf("no %s index on %s.%s", createdAtTTLIndex, db, coll)
	return 0
}

// A Mongo TTL index is collection-wide, so a changed duration governs
// documents that already exist.
//
// Lengthening must never shorten an entry, and shortening cuts existing
// entries short - including one whose own ExpiresAt is still in the future.
// That is the accepted trade-off (see ensureIndexes), and this records it
// rather than leaving it to be discovered.
func TestLoweringTheTTLShortensExistingEntries(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_existing", "auth_ctx"

	store, err := NewMongoStore(ctx, client, db, coll, 35*time.Minute)
	require.NoError(t, err)

	// A context with half an hour still to run on its own deadline.
	require.NoError(t, store.Create(ctx, &AuthorizationContext{
		SessionID: "long-lived",
		State:     "long-lived",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
	}))

	// Lengthening: the entry is still there and the index covers it.
	_, err = NewMongoStore(ctx, client, db, coll, 60*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int32(3600), ttlOf(t, client, db, coll))

	got, err := store.GetByID(ctx, "long-lived")
	require.NoError(t, err)
	require.NotNil(t, got, "lengthening the retention must not drop an entry")

	// Shortening: the index now expires it 15 minutes after creation, well
	// before its own ExpiresAt. MongoDB's TTL monitor runs about once a
	// minute, so this asserts the INDEX, not the deletion - what the next
	// reader needs to know is which rule applies.
	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)

	ttl := ttlOf(t, client, db, coll)
	assert.Equal(t, int32(900), ttl)

	stored, err := store.GetByID(ctx, "long-lived")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Greater(t, stored.ExpiresAt, time.Now().Add(time.Duration(ttl)*time.Second).Unix(),
		"this entry now outlives the retention that governs it - the documented trade-off")
}
