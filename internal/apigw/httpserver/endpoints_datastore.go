package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
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

func (s *Service) endpointDatastorePreAuthOffer(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDatastorePreAuthOffer")
	defer span.End()

	// Refused before binding, because binding is where the two readings of
	// this body diverge: encoding/json matches members case-INSENSITIVELY
	// and lets a later one win, so {"scope":"a","Scope":"b"} binds "b"
	// while the authorization middleware reads the exact key "scope" and
	// sees "a". One request authorized for one scope, acted on for
	// another - and allow_preauth_offer is what makes the second scope
	// worth reaching. Same guard, same reasoning, as
	// endpointPrepareIssuance.
	if err := requireCanonicalJSONBody(c, "scope", "authentic_source", "document_id"); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "ambiguous request body")
		return nil, err
	}

	request := &apiv1.DatastorePreAuthOfferRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// An anonymous admin session may mint an offer for a GENUINE preauth
	// scope, and only for one.
	//
	// That combination is deliberate and supported: with the admin UI on
	// and no OIDC, /ui/login grants an anonymous session on purpose, and
	// checkPreAuthOfferExposure lets such a configuration start precisely
	// because preauth twins carry no login. Refusing it outright broke
	// that workflow - every Offer action returned 403 even where
	// allow_preauth_offer was never enabled.
	//
	// What was never sanctioned is an anonymous session minting a
	// LOGIN-GATED scope. Those are the ones this PR opened up, and a
	// cookie issued before the configuration changed stays valid for its
	// lifetime - session keys persist across restarts in HA - so the
	// startup check cannot revoke it and SessionOrAPIAuth still accepts
	// it in place of a bearer token.
	//
	// After binding, because which scope is being asked for is the whole
	// question.
	if isAnonymousAdminSession(c) && !isGenuinePreAuthScope(s.cfg, request.Scope) {
		err := helpers.NewErrorDetailsWithStatus("anonymous_session_not_allowed",
			"an anonymous admin session cannot create a pre-authorized offer for a login-gated scope", http.StatusForbidden)
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "anonymous admin session refused", "scope", request.Scope)
		return nil, err
	}

	reply, err := s.apiv1.DatastorePreAuthOffer(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

// isGenuinePreAuthScope reports whether a scope carries no login of its own -
// a preauth twin - as opposed to a login-gated scope that allow_preauth_offer
// merely lets an AUTHENTICATED operator mint an offer for. An unknown scope is
// not one; the handler refuses it anyway, and guessing in its favour here
// would be the wrong way to be wrong.
func isGenuinePreAuthScope(cfg *model.Cfg, scope string) bool {
	if cfg == nil || cfg.APIGW == nil {
		return false
	}
	entry, ok := cfg.APIGW.DataSources.Datastore.Scopes[scope]
	return ok && entry.AuthProvider == model.AuthProviderPreAuth
}
