package db

import (
	"context"
	"errors"
	"time"

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
		service.disconnectMongoOnStartupError()
		return nil, err
	}
	service.Clients = clientsColl

	service.log.Info("Started")

	return service, nil
}

// disconnectMongoOnStartupError disconnects the Mongo client after a
// collection/index setup failure in New, so a failed startup doesn't leak
// the already-open connection. Uses a fresh background context (not the
// caller's, which may be close to its own startup deadline) so cleanup
// still runs even if that deadline has passed.
func (s *Service) disconnectMongoOnStartupError() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.MongoClient.Disconnect(ctx); err != nil {
		s.log.Error(err, "failed to disconnect mongo client after startup error")
	}
}

// NewServiceWithMocks creates a db.Service with mock implementations for testing
// This allows unit tests to inject mock ClientStore implementation
func NewServiceWithMocks(clients ClientStore) *Service {
	return &Service{
		Clients: clients,
	}
}

// HealthProbe implements the status.Prober contract: returns nil when the
// active backend (SQL or MongoDB) is reachable, otherwise the underlying error.
func (s *Service) HealthProbe(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "verifier:db:healthprobe")
	defer span.End()

	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if s.SQLDB != nil {
		return s.SQLDB.PingContext(pingCtx)
	}
	if s.MongoClient == nil {
		return errors.New("mongo client not connected")
	}
	return s.MongoClient.Ping(pingCtx, nil)
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	return sqlstore.CloseBackend(s.SQLDB, func() error { return s.MongoClient.Disconnect(ctx) })
}
