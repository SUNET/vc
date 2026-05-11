package httpserver

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/apigw/apiv1"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

var errForbidden = errors.New("forbidden: insufficient permissions for identity mapping")

func (s *Service) endpointIdentityMappingCreate(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointIdentityMappingCreate")
	defer span.End()

	request := &apiv1.IdentityMappingCreateRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.IdentityMappingCreate(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointIdentityMappingResolve(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointIdentityMappingResolve")
	defer span.End()

	request := &apiv1.IdentityMappingResolveRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.IdentityMappingResolve(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointIdentityMappingUpdate(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointIdentityMappingUpdate")
	defer span.End()

	request := &apiv1.IdentityMappingUpdateRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if err := s.apiv1.IdentityMappingUpdate(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointIdentityMappingDelete(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointIdentityMappingDelete")
	defer span.End()

	request := &apiv1.IdentityMappingDeleteRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if err := s.apiv1.IdentityMappingDelete(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointIdentityMappingSearch(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointIdentityMappingSearch")
	defer span.End()

	// Check that the user has the "identity_mapping" scope.
	// A nil slice means unrestricted access (wildcard rule).
	if allowed, ok := c.Get("spocp_allowed_scopes"); ok {
		if scopes, ok := allowed.([]string); ok && scopes != nil {
			hasScope := false
			for _, sc := range scopes {
				if sc == "identity_mapping" {
					hasScope = true
					break
				}
			}
			if !hasScope {
				return nil, errForbidden
			}
		}
	}

	request := &apiv1.IdentityMappingSearchRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Apply SPOCP-derived authentic_source filter for DB queries.
	if allowed, ok := c.Get("spocp_allowed_authentic_sources"); ok {
		if sources, ok := allowed.([]string); ok {
			request.AllowedAuthenticSources = sources
		}
	}

	reply, err := s.apiv1.IdentityMappingSearch(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointIdentityMappingBulkCreate(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointIdentityMappingBulkCreate")
	defer span.End()

	request := &apiv1.IdentityMappingBulkCreateRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.IdentityMappingBulkCreate(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}
