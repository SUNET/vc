package cache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Locker is a best-effort distributed advisory lock with a TTL, used to make
// an at-most-one-winner operation single-flight across HA replicas.
//
// It is advisory, not a mutual-exclusion guarantee past the TTL: a lock
// auto-expires so a crashed holder cannot block the operation forever, which
// means a sufficiently slow holder can see its lock handed on. Callers must be
// correct when two of them run anyway - here, the loser adopts the winner's
// result instead of repeating the work.
type Locker interface {
	// TryLock attempts to acquire key until now+ttl. On success it returns an
	// opaque ownership token; when the lock is already held it returns "".
	TryLock(ctx context.Context, key string, ttl time.Duration) (token string, err error)
	// Unlock releases key, but only if token identifies the current holder. A
	// token that no longer matches - the lock expired and someone else took
	// it - is a no-op, so a late release cannot free a lock a different caller
	// now holds.
	Unlock(ctx context.Context, key, token string) error
}

// NewLocker creates a Locker backed by the service's backend: in-process when
// HA is disabled, MongoDB-backed and shared across replicas when it is.
func (s *Service) NewLocker(ctx context.Context, collection string) (Locker, error) {
	if !s.ha {
		return NewMemoryLocker(), nil
	}
	return NewMongoLocker(ctx, s.client, s.databaseName, collection)
}

// lockToken returns a random ownership token so Unlock can tell the current
// holder from a stale one.
func lockToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating lock token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// MemoryLocker is a process-local Locker. In a single replica it is all the
// coordination there is; the cross-replica contention it cannot see does not
// exist.
type MemoryLocker struct {
	mu    sync.Mutex
	locks map[string]memoryLock
}

type memoryLock struct {
	until time.Time
	token string
}

// NewMemoryLocker creates an in-memory Locker.
func NewMemoryLocker() *MemoryLocker {
	return &MemoryLocker{locks: map[string]memoryLock{}}
}

// TryLock acquires key unless a live hold already exists.
func (m *MemoryLocker) TryLock(_ context.Context, key string, ttl time.Duration) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if l, held := m.locks[key]; held && now.Before(l.until) {
		return "", nil
	}
	token, err := lockToken()
	if err != nil {
		return "", err
	}
	m.locks[key] = memoryLock{until: now.Add(ttl), token: token}
	return token, nil
}

// Unlock releases key if token is the current holder's.
func (m *MemoryLocker) Unlock(_ context.Context, key, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if l, held := m.locks[key]; held && l.token == token {
		delete(m.locks, key)
	}
	return nil
}

// MongoLocker is a MongoDB-backed Locker shared across HA replicas.
//
// Acquisition is an insert keyed on the lock name: _id uniqueness makes
// exactly one concurrent caller win, and a held lock's document still exists
// so a later caller's insert collides and loses. A holder releases by deleting
// its own document (matched on the owner token); a crashed holder's document
// is removed by a TTL index on expires_at instead.
//
// The TTL sweep is periodic (~60s), so a crashed holder's lock can linger past
// its logical expiry before another caller may take it. That is the crash
// bound only: a live holder releases explicitly, so the common failure path
// does not wait for it.
type MongoLocker struct {
	coll *mongo.Collection
}

type lockDoc struct {
	ID        string    `bson:"_id"`
	ExpiresAt time.Time `bson:"expires_at"`
	Owner     string    `bson:"owner"`
}

// NewMongoLocker creates a MongoDB-backed Locker, ensuring the TTL index that
// reaps a crashed holder's lock exists.
func NewMongoLocker(ctx context.Context, client *mongo.Client, database, collection string) (*MongoLocker, error) {
	if client == nil {
		return nil, fmt.Errorf("mongo client cannot be nil")
	}

	coll := client.Database(database).Collection(collection)

	// expires_at holds the moment the lock becomes free, so a zero
	// expireAfterSeconds deletes a document as soon as that moment passes.
	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}); err != nil {
		return nil, fmt.Errorf("creating TTL index for lock %q: %w", collection, err)
	}

	return &MongoLocker{coll: coll}, nil
}

// TryLock acquires key by inserting its lock document; a duplicate-key error
// means another caller holds it.
func (m *MongoLocker) TryLock(ctx context.Context, key string, ttl time.Duration) (string, error) {
	token, err := lockToken()
	if err != nil {
		return "", err
	}
	if _, err := m.coll.InsertOne(ctx, lockDoc{ID: key, ExpiresAt: time.Now().Add(ttl), Owner: token}); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return "", nil
		}
		return "", fmt.Errorf("acquiring lock %q: %w", key, err)
	}
	return token, nil
}

// Unlock deletes key's document only when token owns it, so a release arriving
// after the lock was handed on cannot free the new holder's lock.
func (m *MongoLocker) Unlock(ctx context.Context, key, token string) error {
	if _, err := m.coll.DeleteOne(ctx, bson.M{"_id": key, "owner": token}); err != nil {
		return fmt.Errorf("releasing lock %q: %w", key, err)
	}
	return nil
}
