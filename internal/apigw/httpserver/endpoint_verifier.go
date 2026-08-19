package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// retrive Request object
func (s *Service) endpointVerificationRequestObject(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointVerificationRequestObject")
	defer span.End()

	s.log.Debug("verification request object", "req", c.Request.Body, "headers", c.Request.Header)

	request := &apiv1.VerificationRequestObjectRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.VerificationRequestObject(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// reply is the compact JAR (JWT-secured Authorization Request) string.
	// RFC 9101 §10.2 / OpenID4VP require this to be served as the raw
	// compact JWT with Content-Type "application/oauth-authz-req+jwt" --
	// not JSON-wrapped. Returning it through the generic content-negotiated
	// renderer (s.httpHelpers.Rendering.Content, used by RegEndpoint for a
	// plain `any` return) calls c.JSON on it, which quotes it as a JSON
	// string literal. Confirmed live (lpidproto PLAN.md workstream 7 task
	// 7.5, finding 11): the reference wallet requests
	// "Accept: application/oauth-authz-req+jwt", gets back the JSON-quoted
	// string anyway, and passes the literal body (quotes included) to its
	// compact-JWT parser, which fails with "Unable to decode base64
	// url-safe" on the now-invalid leading/trailing `"` characters. Same
	// fix pattern as endpointOpenIDFederationEntityConfig (raw c.Data,
	// bypassing the generic renderer entirely).
	c.Data(http.StatusOK, "application/oauth-authz-req+jwt", []byte(reply))
	return nil, nil
}

func (s *Service) endpointVerificationDirectPost(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointVerificationDirectPost")
	defer span.End()

	s.log.Debug("verification direct post", "headers", c.Request.Header)

	request := &apiv1.VerificationDirectPostRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.VerificationDirectPost(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}
