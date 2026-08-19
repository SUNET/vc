package apiv1

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"

	// swagger complains if this is not imported
	_ "github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/status"
)

// Status returns the readiness of the registry service.
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return c.statusAggregator.Reply(ctx), nil
}

func (c *Client) buildStatusAggregator() *status.Aggregator {
	a := status.New("registry").Register("mongo", c.dbService)
	if c.tokenStatusListIssuer != nil {
		a = a.Register("tokenstatuslist", c.tokenStatusListIssuer)
	} else {
		a = a.RegisterFunc("tokenstatuslist", func(context.Context) error {
			return errors.New("token status list issuer not initialized")
		})
	}
	return a
}
