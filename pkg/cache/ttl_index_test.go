package cache

import (
	"context"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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

// A deployment whose credentials cannot run collMod still starts.
//
// collMod needs the collMod privilege, which the built-in readWrite role
// does not grant - measured on MongoDB 4.4: as a readWrite user collMod
// returns Unauthorized (13), while dropIndexes and createIndexes both
// succeed. So a failing collMod falls back to dropping the index and
// letting it be rebuilt with the new expiry.
func TestTTLIndexFallsBackWhenCollModIsUnavailable(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_no_collmod", "auth_ctx"

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int32(900), ttlOf(t, client, db, coll))

	// Stand in for a readWrite-only deployment.
	original := ttlIndexCollMod
	var attempted bool
	ttlIndexCollMod = func(context.Context, *mongo.Collection, time.Duration) error {
		attempted = true
		return mongo.CommandError{Code: 13, Message: "not authorized on t to execute command collMod"}
	}
	t.Cleanup(func() { ttlIndexCollMod = original })

	_, err = NewMongoStore(ctx, client, db, coll, 60*time.Minute)
	require.NoError(t, err, "a deployment without the collMod privilege must still start")
	assert.True(t, attempted, "the fallback ran without collMod having been tried")

	assert.Equal(t, int32(3600), ttlOf(t, client, db, coll),
		"the index was not rebuilt with the new expiry")

	// The store still works against the rebuilt index.
	store, err := NewMongoStore(ctx, client, db, coll, 60*time.Minute)
	require.NoError(t, err)
	require.NoError(t, store.Create(ctx, &AuthorizationContext{
		SessionID: "after-rebuild",
		State:     "after-rebuild",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
	}))

	got, err := store.GetByID(ctx, "after-rebuild")
	require.NoError(t, err)
	assert.NotNil(t, got)
}

// Losing the drop race to another replica is not an error.
//
// In a least-privilege HA rollout every replica sees the same TTL conflict
// and the same collMod refusal, so all of them reach the drop. One wins;
// the others get IndexNotFound (27) and must carry on to the retry, which
// is the correct next step - the index they wanted dropped is gone.
func TestTTLIndexToleratesLosingTheDropRace(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_drop_race", "auth_ctx"

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int32(900), ttlOf(t, client, db, coll))

	// collMod is refused, and while it is refused another replica drops the
	// index out from under this one.
	original := ttlIndexCollMod
	ttlIndexCollMod = func(ctx context.Context, c *mongo.Collection, _ time.Duration) error {
		dropErr := c.Indexes().DropOne(ctx, createdAtTTLIndex)
		require.NoError(t, dropErr, "the stand-in replica could not drop the index")
		return mongo.CommandError{Code: 13, Message: "not authorized to execute command collMod"}
	}
	t.Cleanup(func() { ttlIndexCollMod = original })

	_, err = NewMongoStore(ctx, client, db, coll, 60*time.Minute)
	require.NoError(t, err, "losing the drop race must not fail startup")

	assert.Equal(t, int32(3600), ttlOf(t, client, db, coll),
		"the index was not rebuilt at the new expiry")
}

// A transient collMod failure must not cost the collection its TTL index.
//
// Dropping and rebuilding is the right answer only when collMod can never
// succeed - the credentials lack the privilege. For a primary election, a
// network blip or a write-concern timeout it is destructive: if the rebuild
// then fails too, every replica runs on with NO expiry at all, silently,
// until some later startup repairs it.
func TestTTLIndexKeepsTheIndexOnATransientCollModFailure(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_transient", "auth_ctx"

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int32(900), ttlOf(t, client, db, coll))

	original := ttlIndexCollMod
	t.Cleanup(func() { ttlIndexCollMod = original })

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"primary stepped down", mongo.CommandError{Code: 189, Message: "PrimarySteppedDown"}},
		{"write concern timeout", mongo.CommandError{Code: 64, Message: "WriteConcernFailed"}},
		{"interrupted", mongo.CommandError{Code: 11602, Message: "InterruptedDueToReplStateChange"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ttlIndexCollMod = func(context.Context, *mongo.Collection, time.Duration) error {
				return tc.err
			}

			_, err := NewMongoStore(ctx, client, db, coll, 60*time.Minute)
			assert.Error(t, err, "a transient failure must be reported, not worked around")

			assert.Equal(t, int32(900), ttlOf(t, client, db, coll),
				"the TTL index was dropped over a retryable error")
		})
	}
}

// A conflict on some OTHER index must leave the TTL index alone.
//
// IndexOptionsConflict says some index in the batch differs, and
// NewMongoStore sends eleven. Without a check of WHICH, a conflict
// elsewhere lands in the TTL migration path and - with readWrite-only
// credentials, where collMod is refused and the fallback drops - takes out
// a perfectly good created_at_1 on the way to failing anyway, leaving the
// collection with no expiry at all.
//
// Measured on MongoDB 7, an expireAfterSeconds difference is the ONLY thing
// that raises 85 here; unique, sparse, hidden and partialFilterExpression
// mismatches all raise IndexKeySpecsConflict (86), which this code does not
// handle and passes straight through. So the reachable case is an operator
// having made one of these fields a TTL index by hand - and it is the case
// built here, rather than a unique/sparse mismatch that never reaches the
// branch at all.
func TestTTLIndexSurvivesAConflictOnAnotherIndex(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_other_conflict", "auth_ctx"
	c := client.Database(db).Collection(coll)

	// state_1 as the store wants it - sparse - but carrying an expiry the
	// store does not ask for. Differing in expireAfterSeconds alone is what
	// makes this 85 rather than 86.
	_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "state", Value: 1}},
		Options: options.Index().SetSparse(true).SetExpireAfterSeconds(600),
	})
	require.NoError(t, err)

	// ... and a healthy TTL index at exactly the expiry the store is about
	// to ask for, so there is nothing about IT to migrate.
	_, err = c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "created_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(900),
	})
	require.NoError(t, err)

	// collMod would be refused here, so reaching the fallback means
	// created_at_1 gets dropped.
	original := ttlIndexCollMod
	var reached bool
	ttlIndexCollMod = func(context.Context, *mongo.Collection, time.Duration) error {
		reached = true
		return mongo.CommandError{Code: 13, Message: "not authorized to execute command collMod"}
	}
	t.Cleanup(func() { ttlIndexCollMod = original })

	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.Error(t, err, "the state_1 conflict is real and must be reported")
	require.True(t, isIndexOptionsConflict(err),
		"this test only means something if the conflict is an 85 - got %v", err)
	assert.False(t, reached, "a conflict on another index reached the TTL migration")

	assert.Equal(t, int32(900), ttlOf(t, client, db, coll),
		"the TTL index was dropped over a conflict that was not its own")
}

// ttlIndexStateOf is the gate above, on its own.
func TestTTLIndexStateOf(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()

	for _, tc := range []struct {
		name string
		opts *options.IndexOptionsBuilder
		want ttlIndexState
	}{
		{"absent", nil, ttlIndexAbsent},
		{"same expiry", options.Index().SetExpireAfterSeconds(900), ttlIndexMatches},
		{"different expiry", options.Index().SetExpireAfterSeconds(600), ttlIndexExpiryChanged},
		{"no expiry at all", options.Index().SetSparse(true), ttlIndexNotTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := client.Database("test_ttl_gate").Collection(tc.name)
			if tc.opts != nil {
				_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
					Keys: bson.D{{Key: "created_at", Value: 1}}, Options: tc.opts,
				})
				require.NoError(t, err)
			}

			got, err := ttlIndexStateOf(ctx, c, 15*time.Minute)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// A created_at_1 that is not a TTL index at all is rebuilt, not collMod'd.
//
// collMod can only ADD expireAfterSeconds from MongoDB 5.1. Measured on the
// documented minimum and the next version up, both refuse:
//
//	mongo:4.4  ok=0 code=72 "no expireAfterSeconds field to update"
//	mongo:5.0  ok=0 code=72 "no expireAfterSeconds field to update"
//	mongo:7    ok=1
//
// 72 is not a permanent-failure code, so routing this state through collMod
// failed startup on exactly the versions this project supports - while the
// state check had already labelled it migratable.
func TestTTLIndexRebuildsAnIndexThatIsNotTTL(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_not_ttl", "auth_ctx"

	// created_at_1 exists, expiring nothing.
	c := client.Database(db).Collection(coll)
	_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: 1}},
	})
	require.NoError(t, err)

	// collMod must not be reached: on 4.4/5.0 it cannot do this.
	original := ttlIndexCollMod
	var reached bool
	ttlIndexCollMod = func(context.Context, *mongo.Collection, time.Duration) error {
		reached = true
		return mongo.CommandError{Code: 72, Message: "no expireAfterSeconds field to update"}
	}
	t.Cleanup(func() { ttlIndexCollMod = original })

	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err, "a non-TTL created_at_1 must be rebuilt, not refused")
	assert.False(t, reached, "collMod was attempted for a state it cannot change")

	assert.Equal(t, int32(900), ttlOf(t, client, db, coll),
		"created_at_1 is still not a TTL index")
}

// And the TTL index is still migrated when IT is the one that differs, even
// though the batch carries ten others that do not.
func TestTTLIndexStillMigratesWhenItIsTheConflict(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	const db, coll = "test_ttl_own_conflict", "auth_ctx"

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int32(900), ttlOf(t, client, db, coll))

	_, err = NewMongoStore(ctx, client, db, coll, 60*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int32(3600), ttlOf(t, client, db, coll))
}
