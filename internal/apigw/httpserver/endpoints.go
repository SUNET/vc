package httpserver

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/model"
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

// negotiateMediaType picks the client's most-preferred type among offered,
// following the quality values of RFC 9110 §12.5.1. offered is in server
// preference order, and is also the tie-break; the first entry answers an
// absent or empty header. "" means nothing offered is acceptable.
//
// Written out rather than handed to gin's NegotiateFormat, which strips
// every ";q=..." before comparing and compares case-sensitively - so
// "Accept: application/jwt;q=0" would have been served the JWT it refused,
// and "Application/JWT" would not have been served the JWT it asked for.
// Media type tokens are case-insensitive (§8.3.1) and q=0 means "not
// acceptable" (§12.4.2).
func negotiateMediaType(header string, offered ...string) string {
	ranges := parseAcceptHeader(header)
	if len(ranges) == 0 {
		return offered[0]
	}

	best, bestQ := "", 0.0
	for _, offer := range offered {
		// The most specific matching range sets the quality, per §12.5.1:
		// an exact type beats "type/*", which beats "*/*".
		q, specificity := 0.0, -1
		for _, r := range ranges {
			s := r.match(offer)
			if s > specificity {
				q, specificity = r.quality, s
			}
		}
		// Strictly greater, so a tie goes to the earlier - that is, to the
		// server's own preference.
		if specificity >= 0 && q > bestQ {
			best, bestQ = offer, q
		}
	}

	return best
}

// mediaRange is one entry of an Accept header: a media range and its quality.
type mediaRange struct {
	kind    string // "type" or "*"
	subtype string // "subtype" or "*"
	quality float64
}

// match reports how specifically this range matches a media type: 2 exact,
// 1 for "type/*", 0 for "*/*", -1 for no match or q=0 (RFC 9110 §12.4.2
// gives q=0 the meaning "not acceptable", so it can never match).
func (r mediaRange) match(mediaType string) int {
	if r.quality <= 0 {
		return -1
	}
	kind, subtype, _ := strings.Cut(mediaType, "/")
	switch {
	case r.kind == "*" && r.subtype == "*":
		return 0
	case r.kind == kind && r.subtype == "*":
		return 1
	case r.kind == kind && r.subtype == subtype:
		return 2
	default:
		return -1
	}
}

func parseAcceptHeader(header string) []mediaRange {
	var ranges []mediaRange
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		name := strings.ToLower(strings.TrimSpace(fields[0]))
		if name == "" {
			continue
		}
		kind, subtype, ok := strings.Cut(name, "/")
		if !ok {
			continue
		}

		quality := 1.0
		for _, param := range fields[1:] {
			key, value, ok := strings.Cut(param, "=")
			if !ok || strings.ToLower(strings.TrimSpace(key)) != "q" {
				continue
			}
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				quality = parsed
			}
		}

		ranges = append(ranges, mediaRange{kind: kind, subtype: subtype, quality: quality})
	}
	return ranges
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

	// The representation now depends on the request's Accept header, so every
	// answer has to say so: without this a shared cache can store the JSON
	// document and hand it to a wallet that asked for application/jwt, or the
	// other way round. Set before any branch below, including the 406.
	c.Header("Vary", "Accept")

	// Held aside rather than read twice: whichever branch runs below, the JSON
	// document must not carry it unless the deployment asked for it.
	signed := reply.SignedMetadata
	reply.SignedMetadata = ""

	// Server preference is the unsigned form, because that is the one a wallet
	// is guaranteed to understand; it is also the tie-break when the wallet
	// gives both the same quality.
	switch negotiateMediaType(c.GetHeader("Accept"), gin.MIMEJSON, MediaTypeJWT) {
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

	if model.BoolVal(s.cfg.APIGW.IssuerMetadata.IncludeSignedMetadataInJSON, false) {
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
