package apiv2

import (
	"context"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
)

// Client holds the v2 API handler logic.
type Client struct {
	cfg            *model.Cfg
	log            *logger.Log
	tracer         *trace.Tracer
	datastoreStore db.DatastoreV2Store
}

// New creates a new v2 API client.
func New(ctx context.Context, dbService *db.Service, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:            cfg,
		log:            log.New("apiv2"),
		tracer:         tracer,
		datastoreStore: dbService.VCDatastoreV2Coll,
	}
	return c, nil
}
