package httphelpers

import (
	"context"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
)

// Client is the client object for httphelpers
type Client struct {
	tracer *trace.Tracer
	log    *logger.Log
	cfg    *model.Cfg

	Binding    *bindingHandler
	Middleware *middlewareHandler
	Rendering  *renderingHandler
	TLS        *tlsHandler
	Server     *serverHandler
	Validator  *validatorHandler
}

// New creates a new httphelpers client
func New(ctx context.Context, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		tracer: tracer,
		log:    log,
		cfg:    cfg,
	}

	c.Binding = &bindingHandler{client: c, log: log}
	c.Middleware = &middlewareHandler{client: c, log: log}
	c.Rendering = &renderingHandler{client: c, log: log}
	c.TLS = &tlsHandler{client: c, log: log}
	c.Server = &serverHandler{client: c, log: log}
	c.Validator = &validatorHandler{client: c, log: log}

	return c, nil
}
