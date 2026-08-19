package db

import (
	"context"
	"time"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/dbservice"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/jmoiron/sqlx"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Service is the database service
type Service struct {
	MongoClient *mongo.Client
	SQLDB       *sqlx.DB
	cfg         *model.Cfg
	log         *logger.Log
	tracer      *trace.Tracer
	probeStore  *sqlstore.ProbeCache

	// OIDC client collection, client registration
	Clients ClientStore
}

// New creates a new database service. The storage backend is selected by
// cfg.Common.SQL.Backend: "postgres" or "mariadb" connect to the
// corresponding relational database (via pkg/sqlstore, running schema
// migrations at startup); anything else (including unset, the default)
// keeps the existing MongoDB-backed behavior unchanged.
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	conn, err := dbservice.Connect(ctx, cfg, tracer, "verifier:db:connect")
	if err != nil {
		return nil, err
	}

	service := &Service{
		log:         log.New("db"),
		cfg:         cfg,
		tracer:      tracer,
		probeStore:  &sqlstore.ProbeCache{},
		MongoClient: conn.MongoClient,
		SQLDB:       conn.SQLDB,
	}

	if conn.SQLDB != nil {
		service.Clients = NewSQLClientColl(service, conn.SQLDB, conn.Dialect)

		service.log.Info("Started", "backend", cfg.Common.SQL.Backend)
		return service, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

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

// Status returns the status of the database
func (s *Service) Status(ctx context.Context) *apiv1_status.StatusProbe {
	ctx, span := s.tracer.Start(ctx, "db:status")
	defer span.End()

	ping := func(ctx context.Context) error {
		if s.SQLDB != nil {
			return s.SQLDB.PingContext(ctx)
		}
		return s.MongoClient.Ping(ctx, nil)
	}
	return sqlstore.ProbeStatus(ctx, s.probeStore, ping)
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	return sqlstore.CloseBackend(s.SQLDB, func() error { return s.MongoClient.Disconnect(ctx) })
}
