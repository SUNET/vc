package apiv1

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/status"
)

// Health returns the readiness of the verifier service.
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return c.statusAggregator.Reply(ctx), nil
}

func (c *Client) buildStatusAggregator() *status.Aggregator {
	return status.New("verifier").
		Register("db", c.db).
		RegisterFunc("signer", func(ctx context.Context) error {
			if c.pkiSigner == nil {
				return errors.New("signing key not loaded")
			}
			return nil
		})
}
