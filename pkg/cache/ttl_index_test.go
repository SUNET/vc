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
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_change")

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
	ctx, client, _, _ := ttlTestDB(t, "ttl_misc")
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

	specs := indexSpecs(t, client, db, coll)

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
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_existing")

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
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_no_collmod")

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int32(900), ttlOf(t, client, db, coll))

	// Stand in for a readWrite-only deployment.
	attempted := refuseCollMod(t, 13, "not authorized on t to execute command collMod")

	_, err = NewMongoStore(ctx, client, db, coll, 60*time.Minute)
	require.NoError(t, err, "a deployment without the collMod privilege must still start")
	assert.True(t, *attempted, "the fallback ran without collMod having been tried")

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
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_drop_race")

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int32(900), ttlOf(t, client, db, coll))

	// collMod is refused, and while it is refused another replica drops the
	// index out from under this one.
	stubCollMod(t, func(ctx context.Context, c *mongo.Collection, name string, _ time.Duration) error {
		require.NoError(t, c.Indexes().DropOne(ctx, name), "the stand-in replica could not drop the index")
		return mongo.CommandError{Code: 13, Message: "not authorized to execute command collMod"}
	})

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
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_transient")

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int32(900), ttlOf(t, client, db, coll))

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"primary stepped down", mongo.CommandError{Code: 189, Message: "PrimarySteppedDown"}},
		{"write concern timeout", mongo.CommandError{Code: 64, Message: "WriteConcernFailed"}},
		{"interrupted", mongo.CommandError{Code: 11602, Message: "InterruptedDueToReplStateChange"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubCollMod(t, func(context.Context, *mongo.Collection, string, time.Duration) error {
				return tc.err
			})

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
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_other_conflict")
	c := client.Database(db).Collection(coll)

	// state_1 as the store wants it - sparse - but carrying an expiry the
	// store does not ask for. Differing in expireAfterSeconds alone is what
	// makes this 85 rather than 86.
	_, err := c.Indexes().CreateOne(ctx, unresolvableStateConflict())
	require.NoError(t, err)

	// ... and a healthy TTL index at exactly the expiry the store is about
	// to ask for, so there is nothing about IT to migrate.
	_, err = c.Indexes().CreateOne(ctx, createdAtIndex(900, ""))
	require.NoError(t, err)

	// collMod would be refused here, so reaching the fallback means
	// created_at_1 gets dropped.
	reached := refuseCollMod(t, 13, "not authorized to execute command collMod")

	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.Error(t, err, "the state_1 conflict is real and must be reported")
	require.True(t, isIndexOptionsConflict(err),
		"this test only means something if the conflict is an 85 - got %v", err)
	assert.False(t, *reached, "a conflict on another index reached the TTL migration")

	assert.Equal(t, int32(900), ttlOf(t, client, db, coll),
		"the TTL index was dropped over a conflict that was not its own")
}

// ttlIndexStateOf is the gate above, on its own.
func TestTTLIndexStateOf(t *testing.T) {
	ctx, client, _, _ := ttlTestDB(t, "ttl_misc")

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

			got, _, err := ttlIndexStateOf(ctx, c, 15*time.Minute)
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
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_not_ttl")

	// created_at_1 exists, expiring nothing.
	c := client.Database(db).Collection(coll)
	_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: 1}},
	})
	require.NoError(t, err)

	// collMod must not be reached: on 4.4/5.0 it cannot do this.
	reached := refuseCollMod(t, 72, "no expireAfterSeconds field to update")

	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err, "a non-TTL created_at_1 must be rebuilt, not refused")
	assert.False(t, *reached, "collMod was attempted for a state it cannot change")

	assert.Equal(t, int32(900), ttlOf(t, client, db, coll),
		"created_at_1 is still not a TTL index")
}

// And the TTL index is still migrated when IT is the one that differs, even
// though the batch carries ten others that do not.
func TestTTLIndexStillMigratesWhenItIsTheConflict(t *testing.T) {
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_own_conflict")

	_, err := NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int32(900), ttlOf(t, client, db, coll))

	_, err = NewMongoStore(ctx, client, db, coll, 60*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int32(3600), ttlOf(t, client, db, coll))
}

// A conflict another replica has already resolved must not fail startup.
//
// In HA, replica A can fix created_at_1 between replica B's CreateMany and
// B's read of the index state. B is then holding a code-85 error describing
// a situation that no longer exists; returning it refuses startup over a
// conflict that is gone. Falling through to the retry is correct either
// way - if the conflict really did belong to another index, the retry
// raises it again.
func TestTTLIndexDoesNotRejectAConflictAnotherReplicaResolved(t *testing.T) {
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_stale_conflict")

	// created_at_1 at the wrong expiry, so our CreateMany conflicts.
	c := client.Database(db).Collection(coll)
	_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "created_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(600),
	})
	require.NoError(t, err)

	// The other replica wins the race: it resolves the index just before we
	// read the state, so what we then read is genuinely "matches".
	originalReader := ttlIndexStateReader
	var raced bool
	ttlIndexStateReader = func(ctx context.Context, coll *mongo.Collection, ttl time.Duration) (ttlIndexState, string, error) {
		if !raced {
			raced = true
			require.NoError(t, ttlIndexCollMod(ctx, coll, createdAtTTLIndex, ttl),
				"the stand-in replica could not resolve the index")
		}
		return originalReader(ctx, coll, ttl)
	}
	t.Cleanup(func() { ttlIndexStateReader = originalReader })

	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err, "startup was refused over a conflict that had already been resolved")
	assert.True(t, raced, "the interleaving never happened - the test proves nothing")

	assert.Equal(t, int32(900), ttlOf(t, client, db, coll))
}

// Two indexes conflicting at once must not cost the collection its TTL.
//
// With state_1 mismatched AND created_at_1 on an old expiry, dropping the
// TTL index and leaving the batched retry to rebuild it left the collection
// with no expiry at all: CreateMany fails again on state_1, which precedes
// the TTL model in the batch, and never reaches it.
func TestTTLIndexSurvivesASimultaneousConflict(t *testing.T) {
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_both_conflict")
	c := client.Database(db).Collection(coll)

	// state_1 as the store wants it but carrying an expiry it does not -
	// an 85 that this code cannot resolve.
	_, err := c.Indexes().CreateOne(ctx, unresolvableStateConflict())
	require.NoError(t, err)

	// ... and created_at_1 on the OLD expiry, so the TTL index genuinely
	// needs migrating at the same time.
	_, err = c.Indexes().CreateOne(ctx, createdAtIndex(600, ""))
	require.NoError(t, err)

	// readWrite-only, so the migration takes the drop-and-rebuild path.
	refuseCollMod(t, 13, "not authorized to execute command collMod")

	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.Error(t, err, "the state_1 conflict is real and must still be reported")

	// The point: startup failed, but the collection still expires
	// documents - and at the new expiry, not the old one.
	assert.Equal(t, int32(900), ttlOf(t, client, db, coll),
		"the collection was left without a TTL index by a conflict it could not fix")
}

// An unrelated index that merely happens to be NAMED created_at_1 is not
// the TTL index, and must not be migrated or dropped.
//
// "created_at_1" is only MongoDB's default name for {created_at: 1}; an
// operator can give any index any name.
func TestTTLIndexIgnoresAnImpostorByName(t *testing.T) {
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_impostor")
	c := client.Database(db).Collection(coll)
	_ = client

	// A different key, wearing the TTL index's default name.
	_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "state", Value: 1}},
		Options: options.Index().SetName(createdAtTTLIndex),
	})
	require.NoError(t, err)

	state, _, err := ttlIndexStateOf(ctx, c, 15*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, ttlIndexAbsent, state,
		"an index named created_at_1 on another key was taken for the TTL index")
}

// isCreatedAtKey on the shapes the driver and a hand-written spec produce.
func TestIsCreatedAtKey(t *testing.T) {
	assert.True(t, isCreatedAtKey(bson.D{{Key: "created_at", Value: int32(1)}}))
	assert.True(t, isCreatedAtKey(bson.M{"created_at": int32(1)}))

	assert.False(t, isCreatedAtKey(bson.D{{Key: "state", Value: int32(1)}}), "another field")
	assert.False(t, isCreatedAtKey(bson.D{{Key: "created_at", Value: int32(-1)}}), "descending")
	assert.False(t, isCreatedAtKey(bson.D{
		{Key: "created_at", Value: int32(1)}, {Key: "state", Value: int32(1)},
	}), "compound")
	assert.False(t, isCreatedAtKey(nil))
	assert.False(t, isCreatedAtKey("created_at"))
}

// A genuine {created_at: 1} TTL index under a custom name is migrated, not
// reported absent.
//
// "created_at_1" is only MongoDB's default name. Requiring it missed a real
// TTL index an operator had named something else: the state read as absent,
// the retry re-issued the same failing request, and startup failed instead
// of migrating it. The fix for the impostor case was to check the key; the
// fix for this one is to check ONLY the key, and carry the name found.
func TestTTLIndexMigratesACustomNamedIndex(t *testing.T) {
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_custom_name")
	const custom = "ttl_by_created_at"

	c := client.Database(db).Collection(coll)
	_, err := c.Indexes().CreateOne(ctx, createdAtIndex(600, custom))
	require.NoError(t, err)

	state, name, err := ttlIndexStateOf(ctx, c, 15*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, ttlIndexExpiryChanged, state, "a real TTL index was reported absent because of its name")
	assert.Equal(t, custom, name, "the name found must be carried to collMod and the drop")

	// ... and the migration goes through IN PLACE, keeping the operator's
	// name. collMod fixes the expiry and the retry asks for the index under
	// the name already there, so nothing is dropped.
	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err, "a real TTL index under a custom name must be migrated, not refused")

	assert.Equal(t, int32(900), ttlOfNamed(t, client, db, coll, custom),
		"the operator's index is missing or on the wrong expiry")
	assert.False(t, indexExists(t, client, db, coll, createdAtTTLIndex),
		"a duplicate was created under the generated name instead of updating theirs")
}

// The same index under a custom name, on a deployment that cannot collMod:
// it has to be rebuilt, and the operator's name still survives.
func TestTTLIndexRebuildKeepsACustomName(t *testing.T) {
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_custom_rebuild")
	const custom = "ttl_by_created_at"

	c := client.Database(db).Collection(coll)
	_, err := c.Indexes().CreateOne(ctx, createdAtIndex(600, custom))
	require.NoError(t, err)

	refuseCollMod(t, 13, "not authorized to execute command collMod")

	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.NoError(t, err)

	assert.Equal(t, int32(900), ttlOfNamed(t, client, db, coll, custom),
		"the rebuild did not keep the operator's index name")
}

// ttlOfNamed reads expireAfterSeconds off an index by name.
func ttlOfNamed(t *testing.T, client *mongo.Client, db, coll, name string) int32 {
	t.Helper()

	for _, spec := range indexSpecs(t, client, db, coll) {
		if spec["name"] != name {
			continue
		}
		v, ok := asInt32(spec["expireAfterSeconds"])
		require.True(t, ok, "%s is not a TTL index", name)
		return v
	}
	t.Fatalf("no %s index on %s.%s", name, db, coll)
	return 0
}

// indexExists reports whether an index of this name is on the collection.
func indexExists(t *testing.T, client *mongo.Client, db, coll, name string) bool {
	t.Helper()

	specs := indexSpecs(t, client, db, coll)

	for _, spec := range specs {
		if spec["name"] == name {
			return true
		}
	}
	return false
}

// Losing the collMod race must still leave a TTL index behind.
//
// IndexNotFound means another replica dropped it; leaving the rebuild to
// the batched retry reintroduces the no-expiry state, because a
// simultaneous conflict on an earlier index makes CreateMany fail first.
func TestTTLIndexRebuildsAfterLosingTheCollModRace(t *testing.T) {
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_collmod_race")
	c := client.Database(db).Collection(coll)

	// An unrelated 85 that this code cannot resolve, so the batched retry
	// fails before it ever reaches the TTL model.
	_, err := c.Indexes().CreateOne(ctx, unresolvableStateConflict())
	require.NoError(t, err)
	_, err = c.Indexes().CreateOne(ctx, createdAtIndex(600, ""))
	require.NoError(t, err)

	// collMod reports the index gone - another replica dropped it.
	stubCollMod(t, func(ctx context.Context, cc *mongo.Collection, name string, _ time.Duration) error {
		require.NoError(t, cc.Indexes().DropOne(ctx, name))
		return mongo.CommandError{Code: 27, Message: "index not found with name [created_at_1]"}
	})

	_, err = NewMongoStore(ctx, client, db, coll, 15*time.Minute)
	require.Error(t, err, "the state_1 conflict is real and must still be reported")

	assert.Equal(t, int32(900), ttlOf(t, client, db, coll),
		"losing the collMod race left the collection with no TTL index")
}

// A conflict when recreating is not proof the index came back correctly.
//
// Creating the same model twice is idempotent and returns no error, so code
// 85 means the index now present has DIFFERENT options - the very state
// rebuildTTLIndex exists to leave behind. Accepting it on faith let the
// helper report success over a wrong expiry.
func TestRebuildRefusesAConflictItCannotVerify(t *testing.T) {
	ctx, client, db, coll := ttlTestDB(t, "test_ttl_rebuild_conflict")
	c := client.Database(db).Collection(coll)
	_ = client

	indexes := []mongo.IndexModel{{
		Keys:    bson.D{{Key: "created_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(900),
	}}

	// Another replica rebuilt it at the WRONG expiry: the drop finds
	// nothing, the create conflicts, and the result must not be success.
	_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "created_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(1800),
	})
	require.NoError(t, err)

	err = rebuildTTLIndex(ctx, c, indexes, "nonexistent_index_name", 15*time.Minute)
	assert.Error(t, err, "a rebuild that left the wrong expiry reported success")

	// ... and when another replica rebuilt it at the RIGHT expiry, the
	// conflict really is benign.
	require.NoError(t, c.Indexes().DropOne(ctx, createdAtTTLIndex))
	_, err = c.Indexes().CreateOne(ctx, indexes[0])
	require.NoError(t, err)

	assert.NoError(t, rebuildTTLIndex(ctx, c, indexes, "nonexistent_index_name", 15*time.Minute))
}

// stubCollMod replaces the collMod seam for one test and restores it after.
func stubCollMod(t *testing.T, fn func(context.Context, *mongo.Collection, string, time.Duration) error) {
	t.Helper()

	original := ttlIndexCollMod
	ttlIndexCollMod = fn
	t.Cleanup(func() { ttlIndexCollMod = original })
}

// refuseCollMod stands in for a deployment whose credentials cannot run it.
func refuseCollMod(t *testing.T, code int32, message string) *bool {
	t.Helper()

	reached := new(bool)
	stubCollMod(t, func(context.Context, *mongo.Collection, string, time.Duration) error {
		*reached = true
		return mongo.CommandError{Code: code, Message: message}
	})
	return reached
}

// createdAtIndex is the TTL index model, optionally under a custom name.
func createdAtIndex(seconds int32, name string) mongo.IndexModel {
	opts := options.Index().SetExpireAfterSeconds(seconds)
	if name != "" {
		opts = opts.SetName(name)
	}
	return mongo.IndexModel{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: opts}
}

// unresolvableStateConflict is a state_1 index that raises code 85 against
// the store's own: sparse as the store wants it, carrying an expiry it does
// not. Nothing in ensureIndexes can fix it, so the batched retry fails on
// it - which is exactly what the TTL index must survive.
func unresolvableStateConflict() mongo.IndexModel {
	return mongo.IndexModel{
		Keys:    bson.D{{Key: "state", Value: 1}},
		Options: options.Index().SetSparse(true).SetExpireAfterSeconds(600),
	}
}

// ttlTestDB starts a MongoDB container and names a collection to work
// against. Every test here needs the same four lines; this is them.
func ttlTestDB(t *testing.T, database string) (context.Context, *mongo.Client, string, string) {
	t.Helper()

	_, client, cleanup := testsupport.StartMongoContainer(t)
	t.Cleanup(cleanup)

	return t.Context(), client, database, "auth_ctx"
}

// indexSpecs lists the index specifications on a collection.
func indexSpecs(t *testing.T, client *mongo.Client, db, coll string) []bson.M {
	t.Helper()

	cur, err := client.Database(db).Collection(coll).Indexes().List(t.Context())
	require.NoError(t, err)

	var specs []bson.M
	require.NoError(t, cur.All(t.Context(), &specs))
	return specs
}
