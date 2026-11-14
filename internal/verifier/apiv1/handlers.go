package apiv1

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/status"
	"github.com/SUNET/vc/pkg/vc20/credential"
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
	registerJSONLDContextProbe(a)
	return a
}

// registerJSONLDContextProbe reports the JSON-LD contexts this deployment
// is still waiting for.
//
// A verifier starting under the best_effort policy is RUNNING but cannot
// canonicalize a presentation of any credential type whose context has not
// loaded yet. Without this probe that verifier reports healthy and a load
// balancer sends it work it will fail - which is the whole reason it is
// allowed to start at all rather than crash-looping.
//
// Nil when nothing resolves contexts, and under the lazy policy the probe
// is registered but always passes, since nothing is pending by
// construction.
func registerJSONLDContextProbe(a *status.Aggregator) {
	if pinner := credential.GlobalPinner(); pinner != nil {
		a.Register("jsonld_contexts", pinner)
	}
}
