package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/vcclient"
)

// Apiv1 interface
type Apiv1 interface {
	MockNext(ctx context.Context, indata *vcclient.MockNextRequest) (*vcclient.MockNextReply, error)
	MockBulk(ctx context.Context, inData *vcclient.MockBulkRequest) (*vcclient.MockBulkReply, error)

	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
