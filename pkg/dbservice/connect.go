// Package dbservice holds the one piece of db.Service setup genuinely
// shared across every service (apigw, verifier, ...): deciding, from
// cfg.Common.SQL.Backend, whether to connect to Mongo or to a SQL backend
// (via pkg/sqlstore, running schema migrations), and handing back whichever
// connection resulted. It intentionally stops there - each service's own
// store wiring (which collections/tables it needs, what indexes/schemas
// they use) stays in that service's own db package, not here.
//
// This package sits above both pkg/model and pkg/trace (it imports both),
// which is safe: pkg/trace already imports pkg/model (for otel setup), so
// pkg/model itself cannot import pkg/trace back - but a leaf package like
// this one, sitting a layer above both, introduces no cycle.
package dbservice

import (
	"context"
	"time"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sqlstore"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/jmoiron/sqlx"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// connectTimeout bounds how long Connect waits for the initial
// connection/ping/migration to complete, matching every db.Service.New this
// replaces.
const connectTimeout = 20 * time.Second

// Connection is the result of Connect: exactly one of MongoClient or SQLDB
// is set, matching db.Service's existing MongoClient/SQLDB field pair.
// Dialect is nil unless SQLDB is set.
type Connection struct {
	MongoClient *mongo.Client
	SQLDB       *sqlx.DB
	Dialect     sqlstore.Dialect
}

// Connect selects a backend from cfg.Common.SQL.Backend ("postgres" or
// "mariadb" connect to the corresponding relational database via
// pkg/sqlstore, running schema migrations at startup; anything else,
// including unset, keeps the default MongoDB-backed behavior) and connects
// to it. mongoSpanName names the tracing span opened around the Mongo
// connect call, since each caller already gives it its own name (e.g.
// "apigw:db:connect" vs "verifier:db:connect").
func Connect(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, mongoSpanName string) (*Connection, error) {
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	switch cfg.Common.SQL.Backend {
	case "postgres", "mariadb":
		db, dialect, err := sqlstore.ConnectAndApplySchema(ctx, &cfg.Common.SQL)
		if err != nil {
			return nil, err
		}
		return &Connection{SQLDB: db, Dialect: dialect}, nil

	default:
		_, span := tracer.Start(ctx, mongoSpanName)
		defer span.End()

		opts, err := cfg.Common.Mongo.MongoClientOptions()
		if err != nil {
			return nil, err
		}
		client, err := mongo.Connect(opts)
		if err != nil {
			return nil, err
		}
		return &Connection{MongoClient: client}, nil
	}
}
