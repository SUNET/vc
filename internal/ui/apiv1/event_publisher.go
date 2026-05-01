package apiv1

import (
	"context"

	"github.com/SUNET/vc/pkg/vcclient"
)

type EventPublisher interface {
	MockNext(mockNextRequest *vcclient.MockNextRequest) error
	Close(ctx context.Context) error
}
