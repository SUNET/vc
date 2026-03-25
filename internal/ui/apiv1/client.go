package apiv1

import (
	"context"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/vcclient"
)

// Client holds the public api object
type Client struct {
	cfg            *model.Cfg
	tracer         *trace.Tracer
	log            *logger.Log
	eventPublisher EventPublisher

	vcClient *vcclient.Client
}

// New creates a new instance of user interface web page
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, eventPublisher EventPublisher, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:            cfg,
		tracer:         tracer,
		log:            log.New("apiv1"),
		eventPublisher: eventPublisher,
	}

	vcClientConfig := &vcclient.Config{
		ApigwURL:    cfg.UI.Services.APIGW.BaseURL,
		MockASURL:   cfg.UI.Services.MockAS.BaseURL,
		VerifierURL: cfg.UI.Services.Verifier.BaseURL,
	}

	var err error
	c.vcClient, err = vcclient.New(vcClientConfig, c.log)
	if err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}
