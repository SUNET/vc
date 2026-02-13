package cache

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

const defaultDatabase = "vc_cache"

// Service manages cache creation. When HA is enabled, caches are
// backed by MongoDB using the provided client; otherwise in-memory.
type Service struct {
	ha     bool
	client *mongo.Client
}

// New creates a cache Service.
// When ha is true the supplied mongo client is used for all caches;
// otherwise every cache is in-memory. The caller owns the client lifecycle.
func New(ha bool, client *mongo.Client) *Service {
	return &Service{ha: ha, client: client}
}

// NewAuthContextCache creates an AuthContextStore backed by the service's backend.
func (s *Service) NewAuthContextCache(ctx context.Context, collection string, ttl time.Duration) (AuthContextStore, error) {
	if !s.ha {
		return NewMemoryStore(ttl), nil
	}
	return NewMongoStore(ctx, s.client, defaultDatabase, collection, ttl)
}

// NewGenericCache creates a Cache[V] backed by the service's backend.
func NewGenericCache[V any](s *Service, ctx context.Context, collection string, ttl time.Duration) (Cache[V], error) {
	if !s.ha {
		return NewMemoryCache[V](ttl), nil
	}
	return NewMongoCache[V](ctx, s.client, defaultDatabase, collection, ttl)
}
