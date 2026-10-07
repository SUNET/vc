package apiv1

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/status"
)

// Health returns the readiness of the verifier service.
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	if c.statusAggregator == nil {
		return status.Probes{}.Check("verifier"), nil
	}
	return c.statusAggregator.Reply(ctx), nil
}

func (c *Client) buildStatusAggregator() *status.Aggregator {
	a := status.New("verifier").
		Register("db", c.db).
		RegisterFunc("signer", func(ctx context.Context) error {
			if c.pkiSigner == nil {
				return errors.New("signing key not loaded")
			}
			return nil
		})
	if c.notify != nil {
		a.Register("pubsub", c.notify)
	}
	return a
}
