package httpserver

import (
	"context"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/vcclient"
)

// Apiv1 interface
type Apiv1 interface {
	MockNext(ctx context.Context, indata *vcclient.MockNextRequest) (*vcclient.MockNextReply, error)
	MockBulk(ctx context.Context, inData *vcclient.MockBulkRequest) (*vcclient.MockBulkReply, error)

	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
