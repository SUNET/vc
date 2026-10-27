package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-contrib/sessions"
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

	// Authorization, not authentication: the middleware says WHO the caller
	// is, this says what they may act on.
	//
	// Asked per entry, as ONE (authentic_source, scope) pair, and carrying
	// this endpoint's own method and path. The middleware's pre-computed
	// allowed-source and allowed-scope lists cannot be used for either:
	// they authorize the Cartesian product of the caller's grants, and they
	// say nothing about WHICH route was authorized - a rule for some other
	// api/v1 path would otherwise authorize revocation. The generic
	// resource-pair check in SessionOrAPIAuth does not fire here either,
	// because this request body carries no authentic_source/scope of its
	// own; the pairs only become known after the lookup.
	subject := revocationSubject(c)
	if subject == "" || s.spocpEngine == nil {
		span.SetStatus(codes.Error, "revocation is not authorized")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return nil, nil
	}
	method, path := c.Request.Method, c.FullPath()
	request.Authorize = func(authenticSource, scope string) bool {
		return s.spocpEngine.QueryElement(
			httphelpers.BuildSPOCPQuery("apigw", method, path, subject, authenticSource, scope))
	}

	reply, err := s.apiv1.RevokeCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

// revocationSubject returns the authenticated principal, whichever way it
// arrived: an admin session or a bearer JWT. An empty result means the
// request cannot be authorized and must be refused - never treated as an
// unconstrained caller.
func revocationSubject(c *gin.Context) string {
	if sub, ok := c.Get("jwt_subject"); ok {
		if s, ok := sub.(string); ok && s != "" {
			return s
		}
	}
	session := sessions.Default(c)
	if s, ok := session.Get("admin_subject").(string); ok {
		return s
	}
	return ""
}
