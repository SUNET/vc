package cache

import (
	"context"
	"fmt"
	"time"

	"vc/internal/apigw/db"
	pkgcache "vc/pkg/cache"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Re-export types from pkg/cache so consumers only need this import.
type (
	AuthContextStore     = pkgcache.AuthContextStore
	AuthorizationContext = pkgcache.AuthorizationContext
	Cache[V any]         = pkgcache.Cache[V]
	Token                = pkgcache.Token
)

// NewTestMemoryStore returns an in-memory AuthContextStore for use in tests only.
var NewTestMemoryStore = pkgcache.NewMemoryStore

// NewTestMemoryCache returns an in-memory Cache for use in tests only.
func NewTestMemoryCache[V any](ttl time.Duration) *pkgcache.MemoryCache[V] {
	return pkgcache.NewMemoryCache[V](ttl)
}

// Service holds all caches used by the apigw service.
type Service struct {
	cfg    *model.Cfg
	log    *logger.Log
	tracer *trace.Tracer

	AuthContext            AuthContextStore
	EphemeralEncryptionKey Cache[jwk.Key]
	SVGTemplate            Cache[string]
	Document               Cache[map[string]*model.CompleteDocument]
	DPopJTI                Cache[bool]
}

// New creates the apigw cache service and initialises all caches.
func New(ctx context.Context, cfg *model.Cfg, dbService *db.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	cs := pkgcache.New(cfg.Common.HA, dbService.MongoClient, log.New("cache"))
	s := &Service{
		cfg:    cfg,
		log:    log.New("cache"),
		tracer: tracer,
	}
	var err error

	if s.AuthContext, err = cs.NewAuthContextCache(ctx, "apigw_auth_context", 10*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: auth_context: %w", err)
	}

	if s.EphemeralEncryptionKey, err = pkgcache.NewGenericCache[jwk.Key](cs, ctx, "apigw_ephemeral_keys", 10*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: ephemeral_keys: %w", err)
	}

	if s.SVGTemplate, err = pkgcache.NewGenericCache[string](cs, ctx, "apigw_svg_templates", 2*time.Hour); err != nil {
		return nil, fmt.Errorf("cache: svg_templates: %w", err)
	}

	if s.Document, err = pkgcache.NewGenericCache[map[string]*model.CompleteDocument](cs, ctx, "apigw_documents", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: documents: %w", err)
	}

	if s.DPopJTI, err = pkgcache.NewGenericCache[bool](cs, ctx, "apigw_dpop_jti", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: dpop_jti: %w", err)
	}

	return s, nil
}
