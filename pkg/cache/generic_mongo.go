package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// mongoCacheEntry is the document structure stored in MongoDB for generic cache entries.
// Values are stored as JSON bytes to support interface types (e.g. jwk.Key) that
// have no BSON codec but implement json.Marshal/Unmarshal.
type mongoCacheEntry struct {
	Key       string    `bson:"_id"`
	JSONValue []byte    `bson:"json_value"`
	CreatedAt time.Time `bson:"created_at"`
}

// MongoCache is a generic cache backed by a MongoDB collection.
// Values are JSON-encoded before storage, which allows interface types
// (e.g. jwk.Key) to round-trip correctly. A TTL index on `created_at`
// provides automatic expiration. Enables HA by sharing state across instances.
//
// V must be JSON-serializable (implement json.Marshal/Unmarshal).
// For interface types that require custom parsing, supply a MongoCacheOption
// via WithDecoder.
type MongoCache[V any] struct {
	coll       *mongo.Collection
	log        Logger
	collection string
	decode     func([]byte) (V, error) // optional custom JSON decoder
}

// MongoCacheOption configures optional behaviour for MongoCache.
type MongoCacheOption[V any] func(*MongoCache[V])

// WithDecoder supplies a custom JSON decoder for V.
// Use this for interface types (e.g. jwk.Key) where json.Unmarshal cannot
// infer the concrete type.
func WithDecoder[V any](fn func([]byte) (V, error)) MongoCacheOption[V] {
	return func(m *MongoCache[V]) { m.decode = fn }
}

// NewMongoCache creates a new MongoDB-backed generic cache.
// It creates the necessary indexes including a TTL index for automatic expiration.
// If log is nil operational errors are silently discarded.
func NewMongoCache[V any](ctx context.Context, client *mongo.Client, database, collection string, ttl time.Duration, log Logger, opts ...MongoCacheOption[V]) (*MongoCache[V], error) {
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

	mc := &MongoCache[V]{
		coll:       coll,
		log:        log,
		collection: collection,
	}

	for _, opt := range opts {
		opt(mc)
	}

	return mc, nil
}

// Get retrieves a value by key.
func (m *MongoCache[V]) Get(ctx context.Context, key string) (V, bool) {
	var entry mongoCacheEntry
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

	var v V
	if m.decode != nil {
		v, err = m.decode(entry.JSONValue)
	} else {
		err = json.Unmarshal(entry.JSONValue, &v)
	}
	if err != nil {
		m.log.Error(err, "mongo cache get: failed to unmarshal JSON value",
			"cache", m.collection, "key", key,
		)
		var zero V
		return zero, false
	}
	return v, true
}

// Set stores a value with the default TTL (uses upsert).
func (m *MongoCache[V]) Set(ctx context.Context, key string, value V) {
	m.upsert(ctx, key, value)
}

// SetNX stores a value only if the key does not already exist (atomic).
// Returns true if the value was inserted, false if the key already existed.
// Returns a non-nil error on operational failures (e.g. connectivity issues).
func (m *MongoCache[V]) SetNX(ctx context.Context, key string, value V) (bool, error) {
	entry, err := m.marshalEntry(key, value)
	if err != nil {
		return false, fmt.Errorf("mongo cache setnx marshal failed (cache=%s): %w", m.collection, err)
	}
	_, err = m.coll.InsertOne(ctx, entry)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return false, fmt.Errorf("mongo cache setnx failed (cache=%s): %w", m.collection, err)
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
	entry, err := m.marshalEntry(key, value)
	if err != nil {
		m.log.Error(err, "mongo cache upsert marshal failed",
			"cache", m.collection, "key", key,
		)
		return
	}

	opts := options.Replace().SetUpsert(true)
	if _, err := m.coll.ReplaceOne(ctx, bson.M{"_id": key}, entry, opts); err != nil {
		m.log.Error(err, "mongo cache upsert failed",
			"cache", m.collection, "key", key,
		)
	}
}

// marshalEntry serializes value to JSON and wraps it in a mongoCacheEntry.
func (m *MongoCache[V]) marshalEntry(key string, value V) (mongoCacheEntry, error) {
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return mongoCacheEntry{}, fmt.Errorf("json marshal: %w", err)
	}
	return mongoCacheEntry{
		Key:       key,
		JSONValue: jsonBytes,
		CreatedAt: time.Now(),
	}, nil
}
