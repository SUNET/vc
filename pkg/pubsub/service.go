package pubsub

import (
	"github.com/redis/go-redis/v9"
)

// Backend selects which PubSub implementation Service.NewPubSub
// returns. BackendMemory is the zero value and the standalone default.
type Backend int

const (
	// BackendMemory selects MemoryPubSub, a single-process bus.
	// Standalone deployments and tests use this.
	BackendMemory Backend = iota
	// BackendRedis selects a Redis Pub/Sub-backed bus for cross-node
	// delivery in HA mode.
	BackendRedis
	// BackendValkey selects a Valkey Pub/Sub-backed bus. Valkey speaks
	// the same RESP protocol as Redis, so the underlying implementation
	// is shared; the separate value exists so operators configure the
	// backend they actually run and so logs identify it correctly.
	BackendValkey
)

// String returns the backend's canonical name, matching the yaml value
// an operator writes in config.
func (b Backend) String() string {
	switch b {
	case BackendMemory:
		return "memory"
	case BackendRedis:
		return "redis"
	case BackendValkey:
		return "valkey"
	default:
		return "memory"
	}
}

// ParseBackend maps a config string ("memory"/"redis"/"valkey") to a
// Backend. Unknown and empty values map to BackendMemory so a missing
// config falls back to the standalone default without erroring.
func ParseBackend(s string) Backend {
	switch s {
	case "redis":
		return BackendRedis
	case "valkey":
		return BackendValkey
	default:
		return BackendMemory
	}
}

// Service manages PubSub creation. One Service per process; one
// PubSub per logical bus (there is typically only one today). The
// factory shape mirrors pkg/cache.Service.
type Service struct {
	backend     Backend
	redisClient redis.UniversalClient
	log         Logger
}

// New creates a Service.
//
// backend picks the implementation. When backend is BackendRedis or
// BackendValkey the supplied redis.UniversalClient MUST be non-nil;
// a nil client falls back to MemoryPubSub with a logged warning so a
// misconfigured HA deployment degrades gracefully. The caller owns
// the client lifecycle.
//
// log is used for operational errors from the backing bus. Nil is
// accepted and swapped for a silent no-op.
func New(backend Backend, redisClient redis.UniversalClient, log Logger) *Service {
	if log == nil {
		log = nopLogger{}
	}
	return &Service{
		backend:     backend,
		redisClient: redisClient,
		log:         log,
	}
}

// NewPubSub builds a PubSub for the configured backend. prefix is used
// only by the RESP backends to namespace channel names so multiple
// buses can share one Redis/Valkey keyspace without colliding; it is
// ignored by MemoryPubSub.
func (s *Service) NewPubSub(prefix string) (PubSub, error) {
	switch s.backend {
	case BackendRedis, BackendValkey:
		if s.redisClient == nil {
			s.log.Error(ErrBackendUnavailable, "pubsub: HA backend requested without a redis client, falling back to memory", "backend", s.backend.String())
			return NewMemoryPubSub(), nil
		}
		return newRESPPubSub(s.redisClient, prefix, s.backend, s.log), nil
	default:
		return NewMemoryPubSub(), nil
	}
}
