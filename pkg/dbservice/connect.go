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
	"fmt"
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
// to it. spanName names the tracing span opened around the whole connect
// call (whichever backend is selected), since each caller already gives it
// its own name (e.g. "apigw:db:connect" vs "verifier:db:connect") -
// covering only the Mongo branch would silently drop startup connect/ping/
// migration work from traces whenever a deployment runs on SQL instead.
//
// Returns an error up front if Common.HA.Enable is set alongside a SQL
// backend: HA-mode caching (pkg/cache's Mongo-backed AuthContext/generic
// caches) is wired up by each service's own cache.Service.New using this
// same Connection's MongoClient, which is nil when the SQL backend is
// selected - without this guard, that would surface much later as a nil
// *mongo.Client reaching pkg/cache instead of a clear startup error.
// Combining SQL storage with HA caching isn't supported yet.
func Connect(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, spanName string) (*Connection, error) {
	if isSQLBackend := cfg.Common.SQL.Backend == "postgres" || cfg.Common.SQL.Backend == "mariadb"; cfg.Common.HA.Enable && isSQLBackend {
		return nil, fmt.Errorf("dbservice: Common.HA.Enable is not supported together with Common.SQL.Backend=%q - HA-mode caching requires a Mongo connection, which is not established when the SQL backend is selected", cfg.Common.SQL.Backend)
	}

	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	ctx, span := tracer.Start(ctx, spanName)
	defer span.End()

	switch cfg.Common.SQL.Backend {
	case "postgres", "mariadb":
		db, dialect, err := sqlstore.ConnectAndApplySchema(ctx, &cfg.Common.SQL)
		if err != nil {
			return nil, err
		}
		return &Connection{SQLDB: db, Dialect: dialect}, nil

	default:
		opts, err := cfg.Common.Mongo.MongoClientOptions()
		if err != nil {
			return nil, err
		}
		client, err := mongo.Connect(opts)
		if err != nil {
			return nil, err
		}
		// mongo.Connect doesn't itself dial the server - it constructs a
		// client that connects lazily on first real use. Without an
		// explicit Ping here, connectTimeout wouldn't actually bound the
		// "connect" step as documented, and a service could start
		// successfully even with an unreachable Mongo, only failing much
		// later on first query.
		if err := client.Ping(ctx, nil); err != nil {
			// ctx may already be expired (that's often exactly why Ping
			// failed), so use a fresh context for cleanup - Disconnect must
			// still run to release the connection even when the original
			// deadline has passed.
			disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = client.Disconnect(disconnectCtx)
			disconnectCancel()
			return nil, fmt.Errorf("dbservice: ping mongo: %w", err)
		}
		return &Connection{MongoClient: client}, nil
	}
}
