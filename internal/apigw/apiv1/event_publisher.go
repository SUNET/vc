package apiv1

import (
	"context"

	"github.com/SUNET/vc/pkg/vcclient"
)

type EventPublisher interface {
	Upload(uploadRequest *vcclient.UploadRequest) error
	Close(ctx context.Context) error
}
