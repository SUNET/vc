package cache

import (
	"context"
	"fmt"
	"time"

	pkgcache "vc/pkg/cache"
	"vc/pkg/logger"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Service holds session keys for the UI service.
type Service struct {
	cfg    *model.Cfg
	log    *logger.Log
	client *mongo.Client // nil when non-HA

	// SessionAuthKey is the HMAC key for session cookies, shared across HA instances.
	SessionAuthKey string
	// SessionEncKey is the AES encryption key for session cookies, shared across HA instances.
	SessionEncKey string
}

// New creates the UI cache service and resolves HA-shared session keys.
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg: cfg,
		log: log.New("cache"),
	}

	// When HA, connect to MongoDB for shared secrets.
	if cfg.Common.HA {
		connTimeout := 20 * time.Second

		connCtx, cancel := context.WithTimeout(ctx, connTimeout)
		defer cancel()

		client, err := mongo.Connect(
			options.Client().
				ApplyURI(cfg.Common.Mongo.URI).
				SetConnectTimeout(connTimeout).
				SetTimeout(connTimeout),
		)
		if err != nil {
			return nil, fmt.Errorf("cache: mongo connect: %w", err)
		}
		if err := client.Ping(connCtx, nil); err != nil {
			return nil, fmt.Errorf("cache: mongo ping: %w", err)
		}
		s.client = client
		s.log.Info("MongoDB connected for HA session keys")
	}

	cs := pkgcache.New(cfg.Common.HA, s.client, s.log)

	// Resolve HA-shared session keys (atomic upsert in MongoDB when HA, ephemeral otherwise).
	sharedSecrets, err := pkgcache.EnsureSharedSecrets(ctx, cs, "ui")
	if err != nil {
		return nil, fmt.Errorf("cache: shared_secrets: %w", err)
	}
	s.SessionAuthKey = sharedSecrets.SessionAuthKey
	s.SessionEncKey = sharedSecrets.SessionEncKey

	return s, nil
}

// Close disconnects MongoDB if connected.
func (s *Service) Close(ctx context.Context) error {
	if s.client != nil {
		return s.client.Disconnect(ctx)
	}
	return nil
}
