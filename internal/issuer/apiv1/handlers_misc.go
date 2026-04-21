package apiv1

import (
	"context"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/model"
)

// Health return health for this service and dependencies
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	_, span := c.tracer.Start(ctx, "apiv1:Health")
	defer span.End()

	c.log.Info("health handler")
	probes := model.Probes{}

	status := probes.Check("issuer")

	return status, nil
}
