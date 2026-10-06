package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/openid4vci"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointHealth")
	defer span.End()

	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// endpointTypeMetadata serves the raw VCTM JSON for locally-loaded credential types.
// Only scopes backed by a local file (vctm_file_path) are published here;
// scopes using an external vctm_url should be fetched from that URL directly.
func (s *Service) endpointTypeMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointTypeMetadata")
	defer span.End()

	request := &apiv1.TypeMetadataRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.TypeMetadata(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Write raw JSON directly; the generic Content renderer would corrupt
	// json.RawMessage ([]byte) when content-negotiation picks text/html,
	// because fmt "%v" renders bytes as decimal numbers.
	c.Data(http.StatusOK, "application/json; charset=utf-8", reply)
	return nil, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint
func (s *Service) endpointVCINonce(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointNonce")
	defer span.End()

	// Set Cache-Control unconditionally per spec requirement
	c.Header("Cache-Control", "no-store")

	reply, err := s.apiv1.VCINonce(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	c.Header("Cache-Control", "no-store")
	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-14.html#name-sending-credential-offer-by-
func (s *Service) endpointVCICredentialOfferURI(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointCredential")
	defer span.End()

	request := &openid4vci.CredentialOfferURIRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.VCICredentialOfferURI(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint
func (s *Service) endpointVCICredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointVCICredential")
	defer span.End()

	// An encrypted request (OpenID4VCI 1.0 §8.3) arrives as application/jwt;
	// this decrypts it in place so the binder below sees ordinary JSON.
	encrypted, err := s.acceptEncryptedRequest(c)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "credential request decryption error")
		return nil, err
	}

	request := &openid4vci.CredentialRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding error")
		return nil, &openid4vci.Error{Err: openid4vci.ErrInvalidCredentialRequest, ErrorDescription: err.Error()}
	}

	if err := s.checkResponseEncryption(request.CredentialResponseEncryption, encrypted); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "credential response encryption error")
		return nil, err
	}

	reply, err := s.apiv1.VCICredential(ctx, request)
	if err != nil {
		s.log.Error(err, "VCICredential error")
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if request.CredentialResponseEncryption != nil {
		return s.writeEncryptedReply(c, request.CredentialResponseEncryption, reply)
	}

	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoint
func (s *Service) endpointVCIDeferredCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDeferredCredential")
	defer span.End()

	encrypted, err := s.acceptEncryptedRequest(c)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "deferred credential request decryption error")
		return nil, err
	}

	request := &openid4vci.DeferredCredentialRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// §9.1: the parameters here are the ones used, "regardless of what was
	// sent in the initial Credential Request" - so this is read off the
	// deferred request and never carried over from the first one.
	if err := s.checkResponseEncryption(request.CredentialResponseEncryption, encrypted); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "deferred credential response encryption error")
		return nil, err
	}

	reply, err := s.apiv1.VCIDeferredCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if reply == nil {
		// Deferred issuance is not implemented: VCIDeferredCredential is a
		// stub that returns nothing. Saying so beats a 200 with an empty
		// body, and beats an encrypted "null", which a wallet cannot tell
		// from a credential it failed to read.
		err := errors.New("deferred credential issuance is not implemented by this Credential Issuer")
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if request.CredentialResponseEncryption != nil {
		return s.writeEncryptedReply(c, request.CredentialResponseEncryption, reply)
	}

	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint
func (s *Service) endpointVCINotification(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointNotification")
	defer span.End()

	request := &openid4vci.NotificationRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	err := s.apiv1.VCINotification(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	c.Status(204)
	return nil, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
func (s *Service) endpointVCIMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointMetadata")
	defer span.End()

	reply, err := s.apiv1.VCIMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	return reply, nil
}

// endpointIACAs serves IACA certificates for mDOC verification via the issuer gRPC service.
func (s *Service) endpointIACAs(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointIACAs")
	defer span.End()

	reply, err := s.apiv1.GetIACAs(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	return reply, nil
}

func (s *Service) endpointIndex(ctx context.Context, c *gin.Context) (any, error) {
	c.Redirect(http.StatusTemporaryRedirect, "/offers")

	return nil, nil
}

func (s *Service) endpointUICredentialOffers(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOffers")
	defer span.End()

	reply, err := s.apiv1.UICredentialOffers(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.log.Debug("endpopintUICredentialOffers", "metadata", reply)

	c.HTML(http.StatusOK, "offers.html", map[string]*apiv1.CredentialOfferLookupMetadata{
		"offers": reply,
	})

	return nil, nil
}

func (s *Service) endpointUICreateCredentialOffer(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUICreateCredentialOffer")
	defer span.End()

	request := &apiv1.UICredentialOfferRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.UICreateCredentialOffer(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")

	return reply, nil
}
