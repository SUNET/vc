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

// ErrNoDocuments is returned when no documents are found
var ErrNoDocuments = errors.New("no documents in result")

// Service is the database service
type Service struct {
	MongoClient *mongo.Client
	cfg         *model.Cfg
	log         *logger.Log
	tracer      *trace.Tracer

	DatastoreColl           DatastoreStore
	IdentityMappingsColl    IdentityMappingStore
	CredentialOfferColl     CredentialOfferStore
	DynamicRegistrationColl DynamicRegistrationStore
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

	datastoreColl := &DatastoreColl{
		Service: service,
		Coll:    service.MongoClient.Database("vc").Collection("datastore"),
		log:     log.New("VCDatastoreColl"),
	}
	if err := datastoreColl.createIndex(ctx); err != nil {
		return nil, err
	}
	service.DatastoreColl = datastoreColl

	identityMappingsColl := &IdentityMappingsColl{
		Service: service,
		Coll:    service.MongoClient.Database("vc").Collection("identity_mappings"),
		log:     log.New("VCIdentityMappingsColl"),
	}
	if err := identityMappingsColl.createIndex(ctx); err != nil {
		return nil, err
	}
	service.IdentityMappingsColl = identityMappingsColl

	var err error

	service.CredentialOfferColl, err = NewCredentialOfferColl(ctx, "credential_offer", service, log.New("VCCredentialOfferColl"))
	if err != nil {
		service.log.Error(err, "failed to create credential offer collection")
		return nil, err
	}

	service.DynamicRegistrationColl, err = NewDynamicRegistrationColl(ctx, "oidc_dynamic_registration", service, log.New("VCDynamicRegistrationColl"))
	if err != nil {
		service.log.Error(err, "failed to create dynamic registration collection")
		return nil, err
	}

	service.log.Info("Started")

	return service, nil
}

// connect connects to the database
func (s *Service) connect(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "apigw:db:connect")
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
	ctx, span := s.tracer.Start(ctx, "apigw:db:healthprobe")
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
