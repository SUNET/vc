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
// collMod is how an existing TTL is changed. Tried only on that specific
// conflict, and only for this one index; anything else is returned
// untouched.
func ensureIndexes(ctx context.Context, coll *mongo.Collection, indexes []mongo.IndexModel, ttl time.Duration) error {
	_, err := coll.Indexes().CreateMany(ctx, indexes)
	if err == nil {
		return nil
	}
	if !isIndexOptionsConflict(err) {
		return err
	}

	// collMod returns NamespaceNotFound if the collection does not exist,
	// but a conflict means it does and the index is already there.
	res := coll.Database().RunCommand(ctx, bson.D{
		{Key: "collMod", Value: coll.Name()},
		{Key: "index", Value: bson.D{
			{Key: "name", Value: createdAtTTLIndex},
			{Key: "expireAfterSeconds", Value: int32(ttl.Seconds())},
		}},
	})
	if cmdErr := res.Err(); cmdErr != nil {
		return fmt.Errorf("index %s already exists with a different expiry and could not be modified to %s: %w (original: %v)",
			createdAtTTLIndex, ttl, cmdErr, err)
	}

	// Any non-TTL index in the batch still has to exist. The TTL index now
	// matches, so this second attempt does not conflict on it.
	if _, err := coll.Indexes().CreateMany(ctx, indexes); err != nil {
		return err
	}
	return nil
}

// isIndexOptionsConflict reports whether err is MongoDB's code 85.
func isIndexOptionsConflict(err error) bool {
	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) && cmdErr.Code == indexOptionsConflict {
		return true
	}

	// CreateMany reports per-index failures through a write exception.
	var writeErr mongo.WriteException
	if errors.As(err, &writeErr) {
		if writeErr.WriteConcernError != nil && writeErr.WriteConcernError.Code == indexOptionsConflict {
			return true
		}
		for _, we := range writeErr.WriteErrors {
			if we.Code == indexOptionsConflict {
				return true
			}
		}
	}
	return false
}
