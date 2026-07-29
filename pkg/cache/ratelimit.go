package cache

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// RateLimitCounter provides an atomic sliding-window rate limit counter.
// Implementations must be safe for concurrent use.
type RateLimitCounter interface {
	// IncrementWithTTL atomically increments the request count for key and
	// returns a sliding-window estimate of the request rate over the given
	// window duration. The estimate is weighted: requests in the previous
	// window are scaled by the fraction of the window that has not yet
	// elapsed, giving smooth rate limiting without boundary bursts.
	// Returns the estimated count and any operational error.
	IncrementWithTTL(ctx context.Context, key string, window time.Duration) (int64, error)
}

// NewRateLimitCounter creates a RateLimitCounter backed by the service's backend.
func (s *Service) NewRateLimitCounter(ctx context.Context, collection string) (RateLimitCounter, error) {
	if !s.ha {
		return NewMemoryRateLimitCounter(), nil
	}
	return NewMongoRateLimitCounter(ctx, s.client, s.databaseName, collection, s.log)
}

// --- In-memory sliding window implementation ---

// slidingWindow tracks request counts across two adjacent windows.
type slidingWindow struct {
	prevCount       int64
	currCount       int64
	currWindowStart time.Time
}

// MemoryRateLimitCounter is an in-memory sliding-window rate limit counter.
type MemoryRateLimitCounter struct {
	mu      sync.Mutex
	windows map[string]*slidingWindow
}

// NewMemoryRateLimitCounter creates a new in-memory rate limit counter.
func NewMemoryRateLimitCounter() *MemoryRateLimitCounter {
	m := &MemoryRateLimitCounter{
		windows: make(map[string]*slidingWindow),
	}
	go m.cleanup()
	return m
}

// IncrementWithTTL atomically increments the counter and returns the
// sliding-window estimate.
func (m *MemoryRateLimitCounter) IncrementWithTTL(_ context.Context, key string, window time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	w, exists := m.windows[key]

	if !exists {
		m.windows[key] = &slidingWindow{
			currCount:       1,
			currWindowStart: now,
		}
		return 1, nil
	}

	elapsed := now.Sub(w.currWindowStart)

	if elapsed >= 2*window {
		// Both windows are stale — reset.
		w.prevCount = 0
		w.currCount = 0
		w.currWindowStart = now
	} else if elapsed >= window {
		// Current window ended — rotate.
		w.prevCount = w.currCount
		w.currCount = 0
		w.currWindowStart = w.currWindowStart.Add(window)
	}

	w.currCount++

	// Sliding window estimate: weight the previous window by the
	// fraction of the current window that has not yet elapsed.
	elapsedInWindow := now.Sub(w.currWindowStart)
	prevWeight := 1.0 - float64(elapsedInWindow)/float64(window)
	if prevWeight < 0 {
		prevWeight = 0
	}
	estimate := int64(math.Ceil(float64(w.prevCount)*prevWeight)) + w.currCount

	return estimate, nil
}

// cleanup periodically removes stale entries to prevent unbounded memory growth.
func (m *MemoryRateLimitCounter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for key, w := range m.windows {
			if now.Sub(w.currWindowStart) > 5*time.Minute {
				delete(m.windows, key)
			}
		}
		m.mu.Unlock()
	}
}

// --- MongoDB sliding window implementation ---

// rateLimitEntry is the document structure for MongoDB-backed rate limiting.
// Each entry represents one fixed sub-window. The key encodes the window ID.
type rateLimitEntry struct {
	Key       string    `bson:"_id"`
	Count     int64     `bson:"count"`
	CreatedAt time.Time `bson:"created_at"`
}

// MongoRateLimitCounter is a MongoDB-backed sliding-window rate limit counter.
// It uses two fixed sub-windows per key and weights them to approximate a
// sliding window. The current window is incremented atomically via $inc.
type MongoRateLimitCounter struct {
	coll *mongo.Collection
	log  Logger
}

// NewMongoRateLimitCounter creates a new MongoDB-backed rate limit counter.
func NewMongoRateLimitCounter(ctx context.Context, client *mongo.Client, database, collection string, log Logger) (*MongoRateLimitCounter, error) {
	if client == nil {
		return nil, fmt.Errorf("mongo client cannot be nil")
	}
	if log == nil {
		log = nopLogger{}
	}

	coll := client.Database(database).Collection(collection)

	indexes := []mongo.IndexModel{
		{
			// TTL index: entries expire 2 minutes after creation (covers
			// current + previous window for a 1-minute window).
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(120),
		},
	}
	if _, err := coll.Indexes().CreateMany(ctx, indexes); err != nil {
		return nil, fmt.Errorf("failed to create indexes for rate limit %q: %w", collection, err)
	}

	return &MongoRateLimitCounter{coll: coll, log: log}, nil
}

// IncrementWithTTL atomically increments the current sub-window's counter
// and returns the sliding-window estimate.
func (m *MongoRateLimitCounter) IncrementWithTTL(ctx context.Context, key string, window time.Duration) (int64, error) {
	now := time.Now()
	windowSecs := int64(window.Seconds())
	if windowSecs <= 0 {
		windowSecs = 60
	}
	currWindowID := now.Unix() / windowSecs
	prevWindowID := currWindowID - 1

	currKey := fmt.Sprintf("%s:%d", key, currWindowID)
	prevKey := fmt.Sprintf("%s:%d", key, prevWindowID)

	// Atomically increment the current window counter.
	filter := bson.M{"_id": currKey}
	update := bson.M{
		"$inc":         bson.M{"count": int64(1)},
		"$setOnInsert": bson.M{"created_at": now},
	}
	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)

	var currResult rateLimitEntry
	if err := m.coll.FindOneAndUpdate(ctx, filter, update, opts).Decode(&currResult); err != nil {
		return 0, fmt.Errorf("rate limit increment failed (key=%s): %w", currKey, err)
	}

	// Read the previous window's count (read-only — already finalized).
	var prevCount int64
	var prevResult rateLimitEntry
	if err := m.coll.FindOne(ctx, bson.M{"_id": prevKey}).Decode(&prevResult); err == nil {
		prevCount = prevResult.Count
	} else if !errors.Is(err, mongo.ErrNoDocuments) {
		return 0, fmt.Errorf("rate limit prev read failed (key=%s): %w", prevKey, err)
	}

	// Sliding window estimate.
	elapsedInWindow := now.Unix() % windowSecs
	prevWeight := 1.0 - float64(elapsedInWindow)/float64(windowSecs)
	estimate := int64(math.Ceil(float64(prevCount)*prevWeight)) + currResult.Count

	return estimate, nil
}
