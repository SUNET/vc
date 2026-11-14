package apiv1

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/status"
	"github.com/SUNET/vc/pkg/vc20/credential"
)

// Health returns the readiness of the issuer service.
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	_, span := c.tracer.Start(ctx, "apiv1:Health")
	defer span.End()
	if c.statusAggregator == nil {
		return status.Probes{}.Check("issuer"), nil
	}
	return c.statusAggregator.Reply(ctx), nil
}

func (c *Client) buildStatusAggregator() *status.Aggregator {
	a := status.New("issuer").
		RegisterFunc("signer", func(ctx context.Context) error {
			if c.signer == nil {
				return errors.New("signing key not loaded")
			}
			return nil
		})
	// Registered on the issuer too, although its default policy fails the
	// boot instead: an operator who sets common.jsonld_contexts
	// .startup_policy_per_service.issuer to best_effort has an issuer that
	// starts without a context it needs to SIGN, and readiness is then the
	// only thing standing between it and a request it cannot serve.
	if pinner := credential.GlobalPinner(); pinner != nil {
		a.Register("jsonld_contexts", pinner)
	}
	return a
}
