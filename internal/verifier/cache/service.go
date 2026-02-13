package cache

import (
	"context"
	"fmt"
	"time"

	"vc/internal/verifier/db"
	pkgcache "vc/pkg/cache"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwtvc"
	"vc/pkg/trace"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Re-export types from pkg/cache so consumers only need this import.
type (
	AuthContextStore     = pkgcache.AuthContextStore
	AuthorizationContext = pkgcache.AuthorizationContext
	Cache[V any]         = pkgcache.Cache[V]
)

// NewTestMemoryStore returns an in-memory AuthContextStore for use in tests only.
var NewTestMemoryStore = pkgcache.NewMemoryStore

// NewTestMemoryCache returns an in-memory Cache for use in tests only.
func NewTestMemoryCache[V any](ttl time.Duration) *pkgcache.MemoryCache[V] {
	return pkgcache.NewMemoryCache[V](ttl)
}

// Service holds all caches used by the verifier service.
type Service struct {
	cfg    *model.Cfg
	log    *logger.Log
	tracer *trace.Tracer

	AuthContext            AuthContextStore
	Credential             Cache[[]sdjwtvc.CredentialCache]
	EphemeralEncryptionKey Cache[jwk.Key]
	RequestObject          Cache[*openid4vp.RequestObject]
}

// New creates the verifier cache service and initialises all caches.
func New(ctx context.Context, cfg *model.Cfg, dbService *db.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	cs := pkgcache.New(cfg.Common.HA, dbService.MongoClient)
	s := &Service{
		cfg:    cfg,
		log:    log.New("cache"),
		tracer: tracer,
	}
	var err error

	if s.AuthContext, err = cs.NewAuthContextCache(ctx, "verifier_auth_context", 15*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: auth_context: %w", err)
	}

	if s.Credential, err = pkgcache.NewGenericCache[[]sdjwtvc.CredentialCache](cs, ctx, "verifier_credentials", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: credentials: %w", err)
	}

	if s.EphemeralEncryptionKey, err = pkgcache.NewGenericCache[jwk.Key](cs, ctx, "verifier_ephemeral_keys", 10*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: ephemeral_keys: %w", err)
	}

	if s.RequestObject, err = pkgcache.NewGenericCache[*openid4vp.RequestObject](cs, ctx, "verifier_request_objects", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: request_objects: %w", err)
	}

	return s, nil
}
