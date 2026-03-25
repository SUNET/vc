package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/registry/db"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
)

// Re-export types from pkg/cache so consumers only need this import.
type (
	Cache[V any] = pkgcache.Cache[V]
)

// Service holds all caches used by the registry service.
type Service struct {
	cfg    *model.Cfg
	log    *logger.Log
	tracer *trace.Tracer

	JWT Cache[string]
	CWT Cache[[]byte]

	// SessionAuthKey is the HMAC key for session cookies, shared across HA instances.
	SessionAuthKey string
	// SessionEncKey is the AES encryption key for session cookies, shared across HA instances.
	SessionEncKey string
}

// New creates the registry cache service and initialises all caches.
func New(ctx context.Context, cfg *model.Cfg, dbService *db.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("cache"),
		tracer: tracer,
	}
	cs := pkgcache.New(s.cfg.Common.HA.Enable, s.cfg.Common.HA.CacheDatabaseName, dbService.MongoClient, s.log)
	var err error

	tokenValidity := time.Duration(cfg.Registry.TokenStatusLists.TokenRefreshInterval)*time.Second - 5*time.Minute

	s.JWT, err = pkgcache.NewGenericCache[string](cs, ctx, "tsl_jwt", tokenValidity)
	if err != nil {
		return nil, fmt.Errorf("cache: jwt: %w", err)
	}

	if s.CWT, err = pkgcache.NewGenericCache[[]byte](cs, ctx, "tsl_cwt", tokenValidity); err != nil {
		return nil, fmt.Errorf("cache: cwt: %w", err)
	}

	// Resolve HA-shared session keys (atomic upsert in MongoDB when HA, ephemeral otherwise).
	sharedSecrets, err := pkgcache.EnsureSharedSecrets(ctx, cs, "registry")
	if err != nil {
		return nil, fmt.Errorf("cache: shared_secrets: %w", err)
	}
	s.SessionAuthKey = sharedSecrets.SessionAuthKey
	s.SessionEncKey = sharedSecrets.SessionEncKey

	return s, nil
}
