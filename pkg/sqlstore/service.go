package sqlstore

import (
	"context"
	"time"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"

	"github.com/jmoiron/sqlx"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// probeCacheTTL is how long a Status probe result is cached before the next
// call re-pings the backend.
const probeCacheTTL = 10 * time.Second

// ProbeStatus implements the shared caching health-probe pattern every
// db.Service.Status (apigw, verifier, ...) uses regardless of which backend
// (Mongo or SQL) is active: ping at most once per probeCacheTTL, returning
// the cached apiv1_status.StatusProbe otherwise. ping is the caller's own
// backend-specific ping call (e.g. *sqlx.DB.PingContext, or a closure over
// *mongo.Client.Ping) - this package deliberately doesn't import the mongo
// driver just to express "the other branch". The caller is expected to have
// already opened its own tracing span around ctx (this package can't import
// pkg/trace itself: pkg/model imports pkg/sqlstore, and pkg/trace imports
// pkg/model, so sqlstore -> trace would be a cycle).
func ProbeStatus(ctx context.Context, probeStore *apiv1_status.StatusProbeStore, ping func(context.Context) error) *apiv1_status.StatusProbe {
	if time.Now().Before(probeStore.NextCheck.AsTime()) {
		return probeStore.PreviousResult
	}
	probe := &apiv1_status.StatusProbe{
		Name:          "db",
		Healthy:       true,
		Message:       "OK",
		LastCheckedTS: timestamppb.Now(),
	}
	if err := ping(ctx); err != nil {
		probe.Message = err.Error()
		probe.Healthy = false
	}

	probeStore.PreviousResult = probe
	probeStore.NextCheck = timestamppb.New(time.Now().Add(probeCacheTTL))

	return probe
}

// CloseBackend closes whichever backend connection is actually active:
// sqlDB if non-nil (the SQL backend), otherwise closeMongo - the caller's
// own Mongo disconnect call, passed as a thunk so this package doesn't need
// to import the mongo driver just for this one alternative path.
func CloseBackend(sqlDB *sqlx.DB, closeMongo func() error) error {
	if sqlDB != nil {
		return sqlDB.Close()
	}
	return closeMongo()
}
