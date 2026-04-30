package apiv1

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/brianvoe/gofakeit/v6"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	cfg                *model.Cfg
	log                *logger.Log
	tracer             *trace.Tracer
	httpClient         *http.Client
	deterministicMocks []uploadMock
	parisMocks         []model.CompleteDocument

	PDA1 *PDA1Service
	EHIC *EHICService
	PID  *PIDService
	ELM  *ELMService
}

// New creates a new instance of the public api
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:                cfg,
		log:                log.New("apiv1"),
		tracer:             tracer,
		httpClient:         &http.Client{},
		deterministicMocks: []uploadMock{},
		parisMocks:         []model.CompleteDocument{},
	}
	c.PDA1 = &PDA1Service{Client: c}
	c.EHIC = &EHICService{Client: c}
	c.PID = &PIDService{Client: c}
	c.ELM = &ELMService{Client: c}

	c.log.Info("Started")

	return c, nil
}

func (c *Client) randomISO31661Alpha2EU() string {
	return gofakeit.RandomString([]string{
		"AT", "BE", "BG", "HR", "CY",
		"CZ", "DK", "EE", "FI", "FR",
		"DE", "GR", "HU", "IE", "IT",
		"LV", "LT", "LU", "MT", "NL",
		"PL", "PT", "RO", "SK", "SI",
		"ES", "SE",
	})
}
