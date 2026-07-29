package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/verifier/db"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trace"

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

	// SessionAuthKey is the HMAC key for session cookies, shared across HA instances.
	SessionAuthKey string
	// SessionEncKey is the AES encryption key for session cookies, shared across HA instances.
	SessionEncKey string
}

// New creates the verifier cache service and initialises all caches.
func New(ctx context.Context, cfg *model.Cfg, dbService *db.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("cache"),
		tracer: tracer,
	}
	cs := pkgcache.New(s.cfg.Common.HA.Enable, s.cfg.Common.HA.CacheDatabaseName, dbService.MongoClient, s.log)
	var err error

	if s.AuthContext, err = cs.NewAuthContextCache(ctx, "verifier_auth_context", 15*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: auth_context: %w", err)
	}

	if s.Credential, err = pkgcache.NewGenericCache[[]sdjwtvc.CredentialCache](cs, ctx, "verifier_credentials", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: credentials: %w", err)
	}

	if s.EphemeralEncryptionKey, err = pkgcache.NewGenericCache[jwk.Key](cs, ctx, "verifier_ephemeral_keys", 10*time.Minute, pkgcache.WithDecoder(jwkKeyDecoder)); err != nil {
		return nil, fmt.Errorf("cache: ephemeral_keys: %w", err)
	}

	if s.RequestObject, err = pkgcache.NewGenericCache[*openid4vp.RequestObject](cs, ctx, "verifier_request_objects", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: request_objects: %w", err)
	}

	// Resolve HA-shared session keys (atomic upsert in MongoDB when HA, ephemeral otherwise).
	sharedSecrets, err := pkgcache.EnsureSharedSecrets(ctx, cs, "verifier")
	if err != nil {
		return nil, fmt.Errorf("cache: shared_secrets: %w", err)
	}
	s.SessionAuthKey = sharedSecrets.SessionAuthKey
	s.SessionEncKey = sharedSecrets.SessionEncKey

	return s, nil
}

// jwkKeyDecoder parses raw JSON bytes into a jwk.Key.
func jwkKeyDecoder(data []byte) (jwk.Key, error) {
	return jwk.ParseKey(data)
}
