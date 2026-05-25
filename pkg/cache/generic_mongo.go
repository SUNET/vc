package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// mongoCacheEntry is the document structure stored in MongoDB for generic cache entries.
type mongoCacheEntry[V any] struct {
	Key       string    `bson:"_id"`
	Value     V         `bson:"value"`
	Raw       bson.Raw  `bson:"raw_value,omitempty"`
	CreatedAt time.Time `bson:"created_at"`
}

// MongoCache is a generic cache backed by a MongoDB collection.
// It stores values as BSON documents and uses a TTL index on `created_at`
// for automatic expiration. Enables HA by sharing state across instances.
//
// V must be serializable to BSON. Primitive types (string, bool, int, []byte)
// and structs with bson tags are supported out of the box.
type MongoCache[V any] struct {
	coll       *mongo.Collection
	log        Logger
	collection string
}

// NewMongoCache creates a new MongoDB-backed generic cache.
// It creates the necessary indexes including a TTL index for automatic expiration.
// If log is nil operational errors are silently discarded.
func NewMongoCache[V any](ctx context.Context, client *mongo.Client, database, collection string, ttl time.Duration, log Logger) (*MongoCache[V], error) {
	if client == nil {
		return nil, fmt.Errorf("mongo client cannot be nil")
	}

	if log == nil {
		log = nopLogger{}
	}

	coll := client.Database(database).Collection(collection)

	indexes := []mongo.IndexModel{
		{
			// TTL index for automatic document expiration
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(int32(ttl.Seconds())),
		},
	}

	if _, err := coll.Indexes().CreateMany(ctx, indexes); err != nil {
		return nil, fmt.Errorf("failed to create indexes for cache %q: %w", collection, err)
	}

	return &MongoCache[V]{coll: coll, log: log, collection: collection}, nil
}

// Get retrieves a value by key.
func (m *MongoCache[V]) Get(ctx context.Context, key string) (V, bool) {
	var entry mongoCacheEntry[V]
	err := m.coll.FindOne(ctx, bson.M{"_id": key}).Decode(&entry)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) {
			m.log.Error(err, "mongo cache get: operational error treated as miss",
				"cache", m.collection, "key", key,
			)
		}
		var zero V
		return zero, false
	}

	// For interface types (like jwk.Key), BSON decodes to bson.Raw.
	// We detect this and use JSON round-trip as fallback.
	val, ok := tryRecoverValue[V](entry)
	if ok {
		return val, true
	}

	return entry.Value, true
}

// Set stores a value with the default TTL (uses upsert).
func (m *MongoCache[V]) Set(ctx context.Context, key string, value V) {
	m.upsert(ctx, key, value)
}

// SetNX stores a value only if the key does not already exist (atomic).
// Returns true if the value was inserted, false if the key already existed.
// Returns a non-nil error on operational failures (e.g. connectivity issues).
func (m *MongoCache[V]) SetNX(ctx context.Context, key string, value V) (bool, error) {
	entry := mongoCacheEntry[V]{
		Key:       key,
		Value:     value,
		CreatedAt: time.Now(),
	}
	_, err := m.coll.InsertOne(ctx, entry)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return false, fmt.Errorf("mongo cache setnx failed (cache=%s, key=%s): %w", m.collection, key, err)
	}
	return true, nil
}

// SetWithTTL stores a value with a custom TTL.
// Note: MongoDB TTL is per-collection, so custom TTL is approximated by
// setting created_at in the past/future relative to the collection TTL.
// For most use cases, use Set with the collection default.
func (m *MongoCache[V]) SetWithTTL(ctx context.Context, key string, value V, _ time.Duration) {
	// MongoDB TTL indexes are collection-wide; per-entry TTL isn't natively supported.
	// We store with current time and rely on the collection TTL index.
	m.upsert(ctx, key, value)
}

// Delete removes a value by key.
func (m *MongoCache[V]) Delete(ctx context.Context, key string) {
	if _, err := m.coll.DeleteOne(ctx, bson.M{"_id": key}); err != nil {
		m.log.Error(err, "mongo cache delete failed",
			"cache", m.collection, "key", key,
		)
	}
}

// Len returns the estimated number of items in the cache.
func (m *MongoCache[V]) Len() int {
	count, err := m.coll.EstimatedDocumentCount(context.Background())
	if err != nil {
		m.log.Error(err, "mongo cache len failed", "cache", m.collection)
		return 0
	}
	return int(count)
}

func (m *MongoCache[V]) upsert(ctx context.Context, key string, value V) {
	entry := mongoCacheEntry[V]{
		Key:       key,
		Value:     value,
		CreatedAt: time.Now(),
	}

	opts := options.Replace().SetUpsert(true)
	if _, err := m.coll.ReplaceOne(ctx, bson.M{"_id": key}, entry, opts); err != nil {
		m.log.Error(err, "mongo cache upsert failed",
			"cache", m.collection, "key", key,
		)
	}
}

// tryRecoverValue handles the case where V is an interface type and BSON
// decoded the value as bson.Raw instead of the concrete type.
// Falls back to JSON round-trip for recovery if raw bytes are present.
func tryRecoverValue[V any](entry mongoCacheEntry[V]) (V, bool) {
	// Check if Raw field has data (set when BSON couldn't decode to V directly)
	if len(entry.Raw) > 0 {
		var v V
		// Try JSON round-trip: Raw → JSON bytes → V
		jsonBytes, err := bson.MarshalExtJSON(entry.Raw, true, false)
		if err == nil {
			if err := json.Unmarshal(jsonBytes, &v); err == nil {
				return v, true
			}
		}
	}
	var zero V
	return zero, false
}
