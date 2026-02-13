package db

import (
	"context"
	"time"

	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Service is the database service
type Service struct {
	MongoClient *mongo.Client
	cfg         *model.Cfg
	log         *logger.Log
	tracer      *trace.Tracer
	probeStore  *apiv1_status.StatusProbeStore

	// OIDC client collection, client registration
	Clients ClientStore
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	service := &Service{
		log:        log.New("db"),
		cfg:        cfg,
		tracer:     tracer,
		probeStore: &apiv1_status.StatusProbeStore{},
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := service.connect(ctx); err != nil {
		return nil, err
	}

	// Initialize OIDC collections
	oidcDB := service.MongoClient.Database("verifier")
	service.Clients = &ClientCollection{
		Service:    service,
		collection: oidcDB.Collection("clients"),
	}

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

	client, err := mongo.Connect(options.Client().ApplyURI(s.cfg.Common.Mongo.URI))
	if err != nil {
		return err
	}
	s.MongoClient = client

	return nil
}

// Status returns the status of the database
func (s *Service) Status(ctx context.Context) *apiv1_status.StatusProbe {
	ctx, span := s.tracer.Start(ctx, "db:status")
	defer span.End()

	if time.Now().Before(s.probeStore.NextCheck.AsTime()) {
		return s.probeStore.PreviousResult
	}
	probe := &apiv1_status.StatusProbe{
		Name:          "db",
		Healthy:       true,
		Message:       "OK",
		LastCheckedTS: timestamppb.Now(),
	}

	if err := s.MongoClient.Ping(ctx, nil); err != nil {
		probe.Message = err.Error()
		probe.Healthy = false
	}

	s.probeStore.PreviousResult = probe
	s.probeStore.NextCheck = timestamppb.New(time.Now().Add(10 * time.Second))

	return probe
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	if err := s.MongoClient.Disconnect(ctx); err != nil {
		return err
	}
	ctx.Done()
	return nil
}
