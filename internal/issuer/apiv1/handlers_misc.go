package apiv1

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/status"
)

// Health returns the readiness of the issuer service.
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	_, span := c.tracer.Start(ctx, "apiv1:Health")
	defer span.End()
	return c.statusAggregator.Reply(ctx), nil
}

func (c *Client) buildStatusAggregator() *status.Aggregator {
	return status.New("issuer").
		RegisterFunc("signer", func(ctx context.Context) error {
			if c.signer == nil {
				return errors.New("signing key not loaded")
			}
			return nil
		})
}
