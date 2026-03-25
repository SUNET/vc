package apiv1

import (
	"context"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"

	// swagger complains if this is not imported
	_ "github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
)

// Status return status for the registry service
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}

	status := probes.Check("registry")

	return status, nil
}
