package httpserver

import (
	"context"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
)

// Apiv1 interface
type Apiv1 interface {
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
