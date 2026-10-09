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

	// A conflict means the collection and the index both exist, so the only
	// question is how to change the index.
	if modErr := ttlIndexCollMod(ctx, coll, ttl); modErr != nil {
		switch {
		case isIndexNotFound(modErr):
			// Another replica dropped it between our CreateMany and this
			// collMod. Nothing to modify and nothing to drop; the retry
			// below rebuilds it.

		case isPermanentCollModFailure(modErr):
			// collMod needs the collMod privilege, which the built-in
			// readWrite role does NOT grant - a least-privilege deployment
			// gets Unauthorized (13). readWrite does grant dropIndex and
			// createIndex, so drop the index and let the retry below
			// rebuild it with the new expiry.
			//
			// Verified on MongoDB 4.4, the documented minimum: as a
			// readWrite user, collMod fails with 13 and dropIndexes +
			// createIndexes succeed.
			//
			// Between the drop and the rebuild nothing expires documents in
			// this collection. That window is one index build at startup,
			// and the alternative is refusing to start at all.
			//
			// IndexNotFound means another replica got there first. In a
			// least-privilege HA rollout every replica sees the same
			// conflict and the same collMod failure, so all of them reach
			// this drop; losing that race is the expected outcome, not an
			// error, and the retry below is still the right next step.
			if dropErr := coll.Indexes().DropOne(ctx, createdAtTTLIndex); dropErr != nil && !isIndexNotFound(dropErr) {
				return fmt.Errorf(
					"index %s already exists with a different expiry; collMod to %s failed (%w) and it could not be dropped either: %v",
					createdAtTTLIndex, ttl, modErr, dropErr)
			}

		default:
			// Anything else - a primary election, a network blip, a write
			// concern timeout - resolves on a retry. Dropping the shared
			// TTL index over one of those risks leaving the collection with
			// NO expiry at all if the rebuild then fails too, which is
			// silent and lasts until some later startup repairs it. Report
			// it and let the deployment retry instead.
			return fmt.Errorf("index %s could not be changed to %s: %w", createdAtTTLIndex, ttl, modErr)
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
