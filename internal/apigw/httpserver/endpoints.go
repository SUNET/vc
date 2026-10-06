package httpserver

import (
	"context"
	"net/http"
	"strings"

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

	request := &openid4vci.CredentialRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding error")
		return nil, &openid4vci.Error{Err: openid4vci.ErrInvalidCredentialRequest, ErrorDescription: err.Error()}
	}

	reply, err := s.apiv1.VCICredential(ctx, request)
	if err != nil {
		s.log.Error(err, "VCICredential error")
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoint
func (s *Service) endpointVCIDeferredCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDeferredCredential")
	defer span.End()

	request := &openid4vci.DeferredCredentialRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.VCIDeferredCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
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

// MediaTypeJWT is the media type OpenID4VCI 1.0 §12.2.2 gives the signed form
// of the Credential Issuer Metadata.
const MediaTypeJWT = "application/jwt"

// acceptedMediaTypes reduces an Accept header to its media ranges, folded to
// lower case and with parameters dropped, in the order the client listed
// them. Suitable for gin's NegotiateFormat, which compares byte by byte and
// ignores quality values.
func acceptedMediaTypes(header string) []string {
	var accepted []string
	for _, part := range strings.Split(header, ",") {
		if i := strings.IndexByte(part, ';'); i >= 0 {
			part = part[:i]
		}
		if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
			accepted = append(accepted, part)
		}
	}
	return accepted
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
//
// OpenID4VCI 1.0 §12.2.2 returns the metadata as EITHER an unsigned JSON
// document (application/json, which a Credential Issuer MUST support) OR a
// signed JWT carrying the same parameters (application/jwt, which it MAY
// support) - one or the other, chosen by the wallet's Accept header and
// declared in Content-Type. §12.2.4 defines no signed_metadata parameter, so
// returning the signed form as a member of the JSON document is a draft-era
// shape; see model.IssuerMetadata.IncludeSignedMetadataInJSON for the
// deployment that still needs it.
func (s *Service) endpointVCIMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointMetadata")
	defer span.End()

	reply, err := s.apiv1.VCIMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Held aside rather than read twice: whichever branch runs below, the JSON
	// document must not carry it unless the deployment asked for it.
	signed := reply.SignedMetadata
	reply.SignedMetadata = ""

	// Server preference is the unsigned form, because that is the one a wallet
	// is guaranteed to understand. Quality values are not weighted - gin
	// negotiates on the order the wallet listed, which is what wallets send.
	//
	// c.Accepted is set rather than left for gin to parse: media type tokens
	// are case-insensitive (RFC 9110 §8.3.1) and gin compares them byte by
	// byte, so a conforming wallet asking for "Application/JWT" would
	// silently get JSON.
	c.Accepted = acceptedMediaTypes(c.GetHeader("Accept"))
	switch c.NegotiateFormat(gin.MIMEJSON, MediaTypeJWT) {
	case MediaTypeJWT:
		if signed != "" {
			c.Data(http.StatusOK, MediaTypeJWT, []byte(signed))
			return nil, nil
		}
		// The signed form is a MAY and can be unavailable at runtime - the
		// issuer is unreachable, or no signing key is configured. The unsigned
		// form is a MUST, so fall through to it rather than refuse.
		s.log.Debug("signed metadata requested but unavailable; serving the unsigned document")
	case "":
		// The Accept header rules out both forms this endpoint can produce.
		c.AbortWithStatus(http.StatusNotAcceptable)
		return nil, nil
	}

	if s.cfg.IncludeSignedMetadataInIssuerMetadataJSON() {
		reply.SignedMetadata = signed
	}

	c.SetAccepted(gin.MIMEJSON)
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
