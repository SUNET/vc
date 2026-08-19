package db

import (
	"context"
	"errors"
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

// ErrNoDocuments is returned when no documents are found
var ErrNoDocuments = errors.New("no documents in result")

// Service is the database service
type Service struct {
	MongoClient *mongo.Client
	SQLDB       *sqlx.DB
	cfg         *model.Cfg
	log         *logger.Log
	tracer      *trace.Tracer
	probeStore  *apiv1_status.StatusProbeStore

	DatastoreColl           DatastoreStore
	IdentityMappingsColl    IdentityMappingStore
	CredentialOfferColl     CredentialOfferStore
	DynamicRegistrationColl DynamicRegistrationStore
}

// New creates a new database service. The storage backend is selected by
// cfg.Common.SQL.Backend: "postgres" or "mariadb" connect to the
// corresponding relational database (via pkg/sqlstore, running schema
// migrations at startup); anything else (including unset, the default)
// keeps the existing MongoDB-backed behavior unchanged.
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	conn, err := dbservice.Connect(ctx, cfg, tracer, "apigw:db:connect")
	if err != nil {
		return nil, err
	}

	service := &Service{
		log:         log.New("db"),
		cfg:         cfg,
		tracer:      tracer,
		probeStore:  &apiv1_status.StatusProbeStore{},
		MongoClient: conn.MongoClient,
		SQLDB:       conn.SQLDB,
	}

	if conn.SQLDB != nil {
		service.DatastoreColl = NewSQLDatastoreColl(service, conn.SQLDB, conn.Dialect)
		service.IdentityMappingsColl = NewSQLIdentityMappingsColl(service, conn.SQLDB, conn.Dialect)
		service.CredentialOfferColl = NewSQLCredentialOfferColl(service, conn.SQLDB, conn.Dialect)
		service.DynamicRegistrationColl = NewSQLDynamicRegistrationColl(service, conn.SQLDB, conn.Dialect)

		service.log.Info("Started", "backend", cfg.Common.SQL.Backend)
		return service, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

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
