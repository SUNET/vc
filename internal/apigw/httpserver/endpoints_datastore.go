package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/vcclient"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointDatastoreUpload(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreUpload")
	defer span.End()

	request := &vcclient.UploadRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.cfg.Common.Kafka.Enable {
		if err := s.eventPublisher.Upload(request); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		return nil, nil
	}

	reply, err := s.apiv1.DatastoreUpload(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointDatastoreGet(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreGet")
	defer span.End()

	request := &apiv1.DatastoreGetByKeyRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.DatastoreGetByKey(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointDatastoreResolve(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreResolve")
	defer span.End()

	request := &apiv1.DatastoreResolveRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.DatastoreResolve(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointDatastoreDelete(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreDelete")
	defer span.End()

	request := &apiv1.DatastoreDeleteByKeyRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if err := s.apiv1.DatastoreDeleteByKey(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.Status(http.StatusNoContent)
	return nil, nil
}

func (s *Service) endpointDatastoreAddIdentity(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreAddIdentity")
	defer span.End()

	request := &apiv1.DatastoreAddIdentityRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if err := s.apiv1.DatastoreAddIdentity(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointDatastoreDeleteIdentity(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreDeleteIdentity")
	defer span.End()

	request := &apiv1.DatastoreDeleteIdentityRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if err := s.apiv1.DatastoreDeleteIdentity(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.Status(http.StatusNoContent)
	return nil, nil
}

func (s *Service) endpointDatastoreReplace(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreReplace")
	defer span.End()

	request := &vcclient.UploadRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if err := s.apiv1.DatastoreReplace(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointDatastoreList(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreList")
	defer span.End()

	request := &apiv1.DatastoreListRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.DatastoreList(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointDatastoreSearch(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreSearch")
	defer span.End()

	request := &apiv1.DatastoreSearchRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Apply SPOCP-derived authentic_source and scope filters for DB queries.
	if allowed, ok := c.Get("spocp_allowed_authentic_sources"); ok {
		if sources, ok := allowed.([]string); ok {
			request.AllowedAuthenticSources = sources
		}
	}
	if allowed, ok := c.Get("spocp_allowed_scopes"); ok {
		if scopes, ok := allowed.([]string); ok {
			request.AllowedScopes = scopes
		}
	}

	s.log.Info("datastore search",
		"search", request.Search, "authentic_source", request.AuthenticSource)

	reply, err := s.apiv1.DatastoreSearch(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointDatastoreBulkUpload(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastoreBulkUpload")
	defer span.End()

	request := &apiv1.DatastoreBulkUploadRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.DatastoreBulkUpload(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}
