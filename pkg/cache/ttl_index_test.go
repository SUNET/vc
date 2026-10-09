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
