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

var databaseName = "vc_registry"

// Service is the database service
type Service struct {
	MongoClient *mongo.Client
	tracer      *trace.Tracer
	log         *logger.Log
	cfg         *model.Cfg

	// Token Status List collections (MongoDB)
	TokenStatusListColl     *TokenStatusListColl
	TokenStatusListMetadata *TokenStatusListMetadataColl
	CredentialSubjects      *CredentialSubjectsColl
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		log:    log.New("db"),
		cfg:    cfg,
		tracer: tracer,
	}

	// Start MongoDB for Status Lists
	if err := s.connectMongo(ctx); err != nil {
		return nil, err
	}

	// Initialize Token Status List collections
	var err error
	s.TokenStatusListColl, err = NewTokenStatusListColl(ctx, "token_status_list", s, log.New("token_status_list"))
	if err != nil {
		return nil, err
	}

	s.TokenStatusListMetadata, err = NewTokenStatusListMetadataColl(ctx, "token_status_list_metadata", s, log.New("token_status_list_metadata"))
	if err != nil {
		return nil, err
	}

	s.CredentialSubjects, err = NewCredentialSubjectsColl(ctx, "credential_subjects", s, log.New("credential_subjects"))
	if err != nil {
		return nil, err
	}

	s.log.Info("Started")

	return s, nil
}

// connectMongo connects to MongoDB
func (s *Service) connectMongo(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	opts, err := s.cfg.Common.Mongo.MongoClientOptions()
	if err != nil {
		return err
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return err
	}
	s.MongoClient = client

	// Verify connection
	if err := s.MongoClient.Ping(ctx, nil); err != nil {
		return err
	}

	s.log.Info("MongoDB connected")
	return nil
}

// Close closes the database connections
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")

	// Close MongoDB connection
	if s.MongoClient != nil {
		if err := s.MongoClient.Disconnect(ctx); err != nil {
			s.log.Error(err, "failed to disconnect MongoDB")
		}
	}

	ctx.Done()
	return nil
}

// HealthProbe implements the status.Prober contract: returns nil when MongoDB
// is reachable, otherwise the underlying error.
func (s *Service) HealthProbe(ctx context.Context) error {
	if s.MongoClient == nil {
		return errors.New("mongo client not connected")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.MongoClient.Ping(pingCtx, nil)
}
