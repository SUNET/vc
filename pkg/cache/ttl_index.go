package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// createdAtTTLIndex is the name MongoDB gives the index on {created_at: 1}.
const createdAtTTLIndex = "created_at_1"

// indexOptionsConflict is MongoDB error code 85: an index with this key
// pattern already exists with different options.
const indexOptionsConflict = 85

// ensureIndexes creates indexes, adjusting an existing TTL index in place
// rather than failing when its duration has changed.
//
// A TTL is a configured value, so it changes. MongoDB will not redefine an
// existing index through createIndexes: asking for {created_at: 1} with a
// different expireAfterSeconds returns IndexOptionsConflict (85), and the
// service then fails to start - after an upgrade, or after an operator
// edits a duration, with nothing in the error pointing at the duration they
// changed.
//
// collMod is how an existing TTL is changed, and it works on MongoDB 4.4,
// the version this project documents as its minimum (measured, not assumed:
// 5.1 is where collMod gained the ability to turn a NON-TTL index into a
// TTL one, which is a different operation). It needs the collMod privilege
// though, which the built-in readWrite role does not grant, so there is a
// drop-and-rebuild fallback below for least-privilege deployments.
//
// Tried only on that specific conflict, and only for this one index;
// anything else is returned untouched.
//
// A Mongo TTL index is collection-wide, so the new duration governs
// documents already stored, not only the ones written afterwards.
// Lengthening is harmless. SHORTENING cuts existing entries short: lower
// the verifier's presentation_timeout from 1800s to 300s and an
// authorization context whose own ExpiresAt is still half an hour away is
// deleted when the new retention elapses, surfacing as "session not found"
// rather than "expired".
//
// That is accepted here rather than worked around. The operator has just
// shortened the window on purpose, and a session granted the old longer
// one is outside the policy they asked for; the alternative - per-document
// absolute expiry, an expires_at field with expireAfterSeconds 0 - is the
// right long-term shape but needs a migration for every document already
// written, which does not belong in a configuration fix. Pinned by
// TestLoweringTheTTLShortensExistingEntries so the behaviour is recorded
// rather than discovered.
func ensureIndexes(ctx context.Context, coll *mongo.Collection, indexes []mongo.IndexModel, ttl time.Duration) error {
	_, err := coll.Indexes().CreateMany(ctx, indexes)
	if err == nil {
		return nil
	}
	if !isIndexOptionsConflict(err) {
		return err
	}

	// IndexOptionsConflict says SOME index in the batch already exists with
	// different options, and the batch has eleven. A conflict on, say,
	// session_id_1 would otherwise land here and - with readWrite-only
	// credentials, where collMod is refused and the fallback drops - take
	// out a perfectly good created_at_1 on its way to failing anyway.
	//
	// So ask the collection rather than the error message: migrate only if
	// created_at_1 is actually present with an expiry other than the one
	// wanted. Reading live state also avoids parsing an error string whose
	// wording is not part of anyone's contract.
	state, listErr := ttlIndexStateReader(ctx, coll, ttl)
	switch {
	case listErr != nil:
		return fmt.Errorf("index %s conflicts and its current state could not be read: %w (original: %v)",
			createdAtTTLIndex, listErr, err)

	case state == ttlIndexAbsent || state == ttlIndexMatches:
		// Nothing of ours to migrate.
		//
		// Fall through to the retry rather than returning the conflict we
		// are holding. In HA another replica can resolve the TTL index
		// between our CreateMany and this read, and that error is then
		// stale - rejecting on it fails startup over a conflict that no
		// longer exists. If it really does belong to another index, the
		// retry raises it again, freshly, and without the TTL index having
		// been touched.

	case state == ttlIndexNotTTL:
		// created_at_1 exists with no expiry at all. collMod cannot ADD
		// expireAfterSeconds before MongoDB 5.1 - measured on 4.4 and 5.0,
		// which return code 72 "no expireAfterSeconds field to update" -
		// and 4.4 is the documented minimum. So go straight to the rebuild
		// rather than attempt a call that cannot work there.
		//
		// Safe to drop because the state has been read off the collection:
		// this IS the {created_at: 1} index, and it is expiring nothing.
		if rebuildErr := rebuildTTLIndex(ctx, coll, indexes, ttl); rebuildErr != nil {
			return fmt.Errorf("index %s exists without an expiry and %w (original: %v)",
				createdAtTTLIndex, rebuildErr, err)
		}

	default:
		if modErr := ttlIndexCollMod(ctx, coll, ttl); modErr != nil {
			switch {
			case isIndexNotFound(modErr):
				// Another replica dropped it between our CreateMany and
				// this collMod. Nothing to modify and nothing to drop; the
				// retry below rebuilds it.

			case isPermanentCollModFailure(modErr):
				// collMod needs the collMod privilege, which the built-in
				// readWrite role does NOT grant - a least-privilege
				// deployment gets Unauthorized (13). readWrite does grant
				// dropIndex and createIndex, so drop the index and let the
				// retry below rebuild it with the new expiry.
				//
				// Verified on MongoDB 4.4, the documented minimum: as a
				// readWrite user, collMod fails with 13 and dropIndexes +
				// createIndexes succeed.
				//
				// Between the drop and the rebuild nothing expires
				// documents in this collection. That window is one index
				// build at startup, and the alternative is refusing to
				// start at all.
				//
				// IndexNotFound means another replica got there first. In a
				// least-privilege HA rollout every replica sees the same
				// conflict and the same collMod failure, so all of them
				// reach this drop; losing that race is the expected
				// outcome, not an error.
				if err := rebuildTTLIndex(ctx, coll, indexes, ttl); err != nil {
					return fmt.Errorf(
						"index %s already exists with a different expiry; collMod to %s failed (%w) and %v",
						createdAtTTLIndex, ttl, modErr, err)
				}

			default:
				// Anything else - a primary election, a network blip, a
				// write concern timeout - resolves on a retry. Dropping the
				// shared TTL index over one of those risks leaving the
				// collection with NO expiry at all if the rebuild then
				// fails too, which is silent and lasts until some later
				// startup repairs it. Report it and let the deployment
				// retry instead.
				return fmt.Errorf("index %s could not be changed to %s: %w", createdAtTTLIndex, ttl, modErr)
			}
		}
	}

	// Either the TTL index now matches or it is gone, so this no longer
	// conflicts - and any non-TTL index in the batch still gets created.
	if _, err := coll.Indexes().CreateMany(ctx, indexes); err != nil {
		return err
	}
	return nil
}

// ttlIndexCollMod changes an existing TTL index's expiry in place.
//
// A package variable so the drop-and-rebuild fallback can be exercised
// without an auth-enabled MongoDB.
var ttlIndexCollMod = func(ctx context.Context, coll *mongo.Collection, ttl time.Duration) error {
	return coll.Database().RunCommand(ctx, bson.D{
		{Key: "collMod", Value: coll.Name()},
		{Key: "index", Value: bson.D{
			{Key: "name", Value: createdAtTTLIndex},
			{Key: "expireAfterSeconds", Value: int32(ttl.Seconds())},
		}},
	}).Err()
}

// isPermanentCollModFailure reports whether a collMod failure is one that
// a retry cannot fix, so dropping and rebuilding the index is the only way
// forward.
//
// Unauthorized is the one that matters in practice: the built-in readWrite
// role does not grant the collMod action. CommandNotFound covers a server
// that does not have the command at all. Everything else is assumed
// transient, because the cost of being wrong in that direction is a
// collection left with no TTL index.
func isPermanentCollModFailure(err error) bool {
	return hasMongoCode(err, unauthorized) || hasMongoCode(err, commandNotFound)
}

// MongoDB error codes.
const (
	// unauthorized: the credentials may not run this command.
	unauthorized = 13
	// commandNotFound: this server has no such command.
	commandNotFound = 59
)

// indexNotFound is MongoDB error code 27: no index by that name.
const indexNotFound = 27

// isIndexNotFound reports whether err is MongoDB's code 27.
func isIndexNotFound(err error) bool {
	return hasMongoCode(err, indexNotFound)
}

// isIndexOptionsConflict reports whether err is MongoDB's code 85.
func isIndexOptionsConflict(err error) bool {
	return hasMongoCode(err, indexOptionsConflict)
}

// hasMongoCode reports whether err carries this MongoDB error code, whether
// it arrives as a command error or inside a write exception - CreateMany
// reports per-index failures through the latter.
func hasMongoCode(err error, code int32) bool {
	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) && cmdErr.Code == code {
		return true
	}

	var writeErr mongo.WriteException
	if errors.As(err, &writeErr) {
		if writeErr.WriteConcernError != nil && int32(writeErr.WriteConcernError.Code) == code {
			return true
		}
		for _, we := range writeErr.WriteErrors {
			if int32(we.Code) == code {
				return true
			}
		}
	}
	return false
}

// ttlIndexState is what the collection currently has for created_at_1.
type ttlIndexState int

const (
	// ttlIndexAbsent: no such index, so whatever conflicted is not ours.
	ttlIndexAbsent ttlIndexState = iota
	// ttlIndexMatches: already a TTL index at the expiry wanted.
	ttlIndexMatches
	// ttlIndexExpiryChanged: a TTL index at some other expiry. collMod can
	// change that, on every version from 4.4 up.
	ttlIndexExpiryChanged
	// ttlIndexNotTTL: present with no expiry at all. collMod can only ADD
	// expireAfterSeconds from MongoDB 5.1, so this one has to be rebuilt.
	ttlIndexNotTTL
)

// ttlIndexStateReader is a seam so the HA interleaving - another replica
// resolving the conflict between our CreateMany and this read - can be
// exercised deterministically.
var ttlIndexStateReader = ttlIndexStateOf

// ttlIndexStateOf reads the state of created_at_1 off the collection.
//
// Live state rather than the conflict's error message, whose wording is
// nobody's contract - and the message does not distinguish "wrong expiry"
// from "no expiry", which is the distinction that decides whether collMod
// can be used at all.
func ttlIndexStateOf(ctx context.Context, coll *mongo.Collection, ttl time.Duration) (ttlIndexState, error) {
	cur, err := coll.Indexes().List(ctx)
	if err != nil {
		return ttlIndexAbsent, err
	}
	defer cur.Close(ctx)

	var specs []bson.M
	if err := cur.All(ctx, &specs); err != nil {
		return ttlIndexAbsent, err
	}

	want := int32(ttl.Seconds())
	for _, spec := range specs {
		if spec["name"] != createdAtTTLIndex || !isCreatedAtKey(spec["key"]) {
			continue
		}
		got, ok := asInt32(spec["expireAfterSeconds"])
		switch {
		case !ok:
			return ttlIndexNotTTL, nil
		case got == want:
			return ttlIndexMatches, nil
		default:
			return ttlIndexExpiryChanged, nil
		}
	}
	return ttlIndexAbsent, nil
}

// isCreatedAtKey reports whether this index spec's key really is
// {created_at: 1}.
//
// The name alone does not establish it. "created_at_1" is only MongoDB's
// default name for that key, and an operator can give any index any name -
// so an unrelated index called created_at_1 would otherwise be collMod'd,
// or under readWrite dropped, on its way to reporting someone else's
// conflict.
func isCreatedAtKey(key any) bool {
	// The driver decodes an index key as bson.D - it is ordered, and a
	// compound index's order matters. bson.M is accepted too so this does
	// not turn on a decoding detail.
	switch doc := key.(type) {
	case bson.D:
		if len(doc) != 1 || doc[0].Key != "created_at" {
			return false
		}
		order, ok := asInt32(doc[0].Value)
		return ok && order == 1
	case bson.M:
		if len(doc) != 1 {
			return false
		}
		order, ok := asInt32(doc["created_at"])
		return ok && order == 1
	}
	return false
}

// asInt32 normalises the numeric types BSON can decode a stored int into.
func asInt32(v any) (int32, bool) {
	switch n := v.(type) {
	case int32:
		return n, true
	case int64:
		return int32(n), true
	case float64:
		return int32(n), true
	case int:
		return int32(n), true
	}
	return 0, false
}

// rebuildTTLIndex drops created_at_1 and recreates it at the wanted expiry,
// on its own rather than through the caller's batch.
//
// The batch is not safe to rely on here: more than one index can conflict
// at once. With state_1 mismatched AND created_at_1 on an old expiry, a
// drop followed by the batched retry leaves the collection with no expiry
// at all - CreateMany fails again on state_1, which precedes the TTL model
// in the batch, and never reaches it. Recreating immediately means the
// retry can fail on someone else's conflict without that costing this
// collection its TTL.
func rebuildTTLIndex(ctx context.Context, coll *mongo.Collection, indexes []mongo.IndexModel, ttl time.Duration) error {
	if dropErr := coll.Indexes().DropOne(ctx, createdAtTTLIndex); dropErr != nil && !isIndexNotFound(dropErr) {
		return fmt.Errorf("it could not be dropped: %w", dropErr)
	}

	model, ok := ttlIndexModel(indexes)
	if !ok {
		// Nothing in the batch defines it, so there is nothing to put back
		// and the caller's retry is the whole story.
		return nil
	}

	if _, err := coll.Indexes().CreateOne(ctx, model); err != nil && !isIndexOptionsConflict(err) {
		// A conflict here means another replica rebuilt it first.
		return fmt.Errorf("it could not be recreated at %s: %w", ttl, err)
	}
	return nil
}

// ttlIndexModel finds the {created_at: 1} model in the batch.
func ttlIndexModel(indexes []mongo.IndexModel) (mongo.IndexModel, bool) {
	for _, m := range indexes {
		keys, ok := m.Keys.(bson.D)
		if !ok || len(keys) != 1 {
			continue
		}
		if keys[0].Key == "created_at" {
			return m, true
		}
	}
	return mongo.IndexModel{}, false
}
