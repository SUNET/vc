package httpserver

import (
	"context"

	"github.com/SUNET/vc/internal/apigw/apiv1"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

// endpointCredentialRevoke sets the status-list status for a credential
// subject's entries.
//
// It sits on the authenticated api/v1 group (SessionOrAPIAuth + CSRF), not
// on the unauthenticated root group: revoking somebody else's credential is
// exactly as damaging as issuing one.
func (s *Service) endpointCredentialRevoke(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointCredentialRevoke")
	defer span.End()

	request := &apiv1.RevokeCredentialRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.RevokeCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}
