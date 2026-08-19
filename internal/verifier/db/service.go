package db

import (
	"context"
	"time"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/jmoiron/sqlx"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Service is the database service
type Service struct {
	MongoClient *mongo.Client
	SQLDB       *sqlx.DB
	cfg         *model.Cfg
	log         *logger.Log
	tracer      *trace.Tracer
	probeStore  *apiv1_status.StatusProbeStore

	// OIDC client collection, client registration
	Clients ClientStore
}

// New creates a new database service. The storage backend is selected by
// cfg.Common.SQL.Backend: "postgres" or "mariadb" connect to the
// corresponding relational database (via pkg/sqlstore, running schema
// migrations at startup); anything else (including unset, the default)
// keeps the existing MongoDB-backed behavior unchanged.
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	switch cfg.Common.SQL.Backend {
	case "postgres", "mariadb":
		return newSQL(ctx, cfg, tracer, log)
	default:
		return newMongo(ctx, cfg, tracer, log)
	}
}

func newMongo(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
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

func newSQL(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	service := &Service{
		log:        log.New("db"),
		cfg:        cfg,
		tracer:     tracer,
		probeStore: &apiv1_status.StatusProbeStore{},
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	db, dialect, err := sqlstore.Connect(ctx, &cfg.Common.SQL)
	if err != nil {
		return nil, err
	}
	if err := sqlstore.ApplySchema(ctx, db, dialect); err != nil {
		return nil, err
	}
	service.SQLDB = db
	service.Clients = NewSQLClientColl(service, db, dialect)

	service.log.Info("Started", "backend", cfg.Common.SQL.Backend)

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

	var err error
	if s.SQLDB != nil {
		err = s.SQLDB.PingContext(ctx)
	} else {
		err = s.MongoClient.Ping(ctx, nil)
	}
	if err != nil {
		probe.Message = err.Error()
		probe.Healthy = false
	}

	s.probeStore.PreviousResult = probe
	s.probeStore.NextCheck = timestamppb.New(time.Now().Add(10 * time.Second))

	return probe
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	if s.SQLDB != nil {
		return s.SQLDB.Close()
	}
	if err := s.MongoClient.Disconnect(ctx); err != nil {
		return err
	}
	ctx.Done()
	return nil
}
