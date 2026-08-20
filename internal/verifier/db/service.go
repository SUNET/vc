package db

import (
	"context"
	"errors"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Service is the database service
type Service struct {
	MongoClient *mongo.Client
	cfg         *model.Cfg
	log         *logger.Log
	tracer      *trace.Tracer

	// OIDC client collection, client registration
	Clients ClientStore
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	service := &Service{
		log:    log.New("db"),
		cfg:    cfg,
		tracer: tracer,
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := service.connect(ctx); err != nil {
		return nil, err
	}

	// Initialize OIDC collections
	oidcDB := service.MongoClient.Database("verifier")
	clientsColl := &ClientCollection{
		Service:    service,
		collection: oidcDB.Collection("clients"),
	}
	if err := clientsColl.createIndex(ctx); err != nil {
		return nil, err
	}
	service.Clients = clientsColl

	service.log.Info("Started")

	return service, nil
}

// NewServiceWithMocks creates a db.Service with mock implementations for testing
// This allows unit tests to inject mock ClientStore implementation
func NewServiceWithMocks(clients ClientStore) *Service {
	return &Service{
		Clients: clients,
	}
}

// connect connects to the database
func (s *Service) connect(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "verifier:db:connect")
	defer span.End()

	opts, err := s.cfg.Common.Mongo.MongoClientOptions()
	if err != nil {
		return err
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return err
	}
	s.MongoClient = client

	return nil
}

// HealthProbe implements the status.Prober contract: returns nil when MongoDB
// is reachable, otherwise the underlying error.
func (s *Service) HealthProbe(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "verifier:db:healthprobe")
	defer span.End()

	if s.MongoClient == nil {
		return errors.New("mongo client not connected")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.MongoClient.Ping(pingCtx, nil)
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	if err := s.MongoClient.Disconnect(ctx); err != nil {
		return err
	}
	ctx.Done()
	return nil
}
