package apiv1

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/status"
)

// Health returns the aggregated readiness of apigw and its downstream
// microservices. The Aggregator (built in New) caches results and single-
// flights concurrent callers so /health is cheap regardless of request rate.
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:Health")
	defer span.End()
	return c.statusAggregator.Reply(ctx), nil
}

// buildStatusAggregator wires local components and downstream services into
// the shared status.Aggregator. Called from New.
func (c *Client) buildStatusAggregator() *status.Aggregator {
	return status.New("apigw").
		Register("db", c.db).
		RegisterFunc("signer", func(ctx context.Context) error {
			if c.pkiSigner == nil {
				return errors.New("signing key not loaded")
			}
			return nil
		}).
		RegisterDownstream("issuer", func(ctx context.Context) (*apiv1_status.StatusReply, error) {
			if c.issuerClient == nil {
				return nil, errors.New("issuer client not initialized")
			}
			return c.issuerClient.Status(ctx, &apiv1_status.StatusRequest{})
		}).
		RegisterDownstream("registry", func(ctx context.Context) (*apiv1_status.StatusReply, error) {
			if c.registryClient == nil {
				return nil, errors.New("registry client not initialized")
			}
			return c.registryClient.Status(ctx, &apiv1_status.StatusRequest{})
		})
}
