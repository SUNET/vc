package cache

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Service manages cache creation. When HA is enabled, caches are
// backed by MongoDB using the provided client; otherwise in-memory.
type Service struct {
	ha           bool
	databaseName string
	client       *mongo.Client
	log          Logger
}

// New creates a cache Service.
// When ha is true the supplied mongo client is used for all caches;
// otherwise every cache is in-memory. The caller owns the client lifecycle.
// databaseName is the MongoDB database name to use for all caches.
// If log is nil operational errors from mongo-backed caches are silently discarded.
func New(ha bool, databaseName string, client *mongo.Client, log Logger) *Service {
	if log == nil {
		log = nopLogger{}
	}
	return &Service{ha: ha, databaseName: databaseName, client: client, log: log}
}

// NewAuthContextCache creates an AuthContextStore backed by the service's backend.
func (s *Service) NewAuthContextCache(ctx context.Context, collection string, ttl time.Duration) (AuthContextStore, error) {
	if !s.ha {
		return NewMemoryStore(ttl), nil
	}
	return NewMongoStore(ctx, s.client, s.databaseName, collection, ttl)
}

// NewGenericCache creates a Cache[V] backed by the service's backend.
func NewGenericCache[V any](s *Service, ctx context.Context, collection string, ttl time.Duration, opts ...MongoCacheOption[V]) (Cache[V], error) {
	if !s.ha {
		return NewMemoryCache[V](ttl), nil
	}
	return NewMongoCache[V](ctx, s.client, s.databaseName, collection, ttl, s.log, opts...)
}
