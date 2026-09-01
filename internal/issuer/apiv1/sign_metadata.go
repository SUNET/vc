package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// MetadataTypeVCIIssuer identifies OID4VCI Credential Issuer Metadata.
	MetadataTypeVCIIssuer = "vci-issuer"
	// MetadataTypeOAuth2 identifies OAuth 2.0 Authorization Server Metadata (RFC 8414).
	MetadataTypeOAuth2 = "oauth2-authorization-server"

	// maxMetadataJSONBytes bounds the size of the metadata_json payload accepted
	// by SignMetadata. This is an application-level guard, separate from gRPC's
	// own transport-level message-size limit (grpc-go defaults to 4 MiB and
	// neither the issuer's gRPC server nor the apigw client override it), so
	// that an oversized payload gets a clear, specific InvalidArgument error
	// here instead of a generic gRPC transport failure.
	//
	// A real deployment's Credential Issuer Metadata grows with the number of
	// configured VCTM/MDDL scopes (each contributing a CredentialConfigurationsSupported
	// entry with multi-language Display/ClaimDescription/ClaimDisplayProperties
	// per claim, see pkg/openid4vci/issuer_metadata.go), so a handful of
	// configured scopes can comfortably exceed a few hundred KB. 2 MiB leaves
	// generous headroom for that while staying well under gRPC's 4 MiB default,
	// so this check - not gRPC's - is the one that actually fires.
	maxMetadataJSONBytes = 2 * 1024 * 1024
)

// signableMetadata is implemented by metadata structs that can be
// validated and marshalled into JWT claims.
type signableMetadata interface {
	MarshalJWTClaims() (jwt.MapClaims, error)
	// MetadataIssuer returns the issuer identifier embedded in the metadata
	// (e.g. credential_issuer or issuer), so we can verify it matches req.iss.
	MetadataIssuer() string
}

// SignMetadata signs the provided metadata JSON with the issuer's own key
// (the same key advertised in JWKS). This ensures that signed_metadata
// is verifiable by looking up the signing key in JWKS.
//
// The incoming JSON is deserialized into a known struct for the requested typ,
// validated, and re-serialized before signing. This prevents callers from
// injecting arbitrary claims (e.g., custom aud/exp/scope) into the signed JWT.
func (c *Client) SignMetadata(ctx context.Context, req *apiv1_issuer.SignMetadataRequest) (*apiv1_issuer.SignMetadataReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:SignMetadata")
	defer span.End()

	c.log.Debug("SignMetadata", "metadata_type", req.GetMetadataType(), "iss", req.GetIss())

	if len(req.GetMetadataJson()) == 0 {
		return nil, grpcstatus.Error(codes.InvalidArgument, "metadata_json is required")
	}
	if len(req.GetMetadataJson()) > maxMetadataJSONBytes {
		return nil, grpcstatus.Error(codes.InvalidArgument, "metadata_json is too large")
	}
	if req.GetIss() != c.cfg.Issuer.IssuerURL {
		return nil, grpcstatus.Error(codes.InvalidArgument, "iss must equal configured issuer_url")
	}

	// Rate-limit after cheap validations so malformed requests don't consume tokens.
	if !c.signMetadataRL.Allow() {
		return nil, grpcstatus.Error(codes.ResourceExhausted, "SignMetadata rate limit exceeded")
	}

	// Pick the concrete struct and JWT typ for this metadata type.
	// Unmarshalling into it strips unknown/injected fields (struct-based whitelist).
	var (
		metadata signableMetadata
		jwtTyp   string
	)
	switch req.GetMetadataType() {
	case MetadataTypeVCIIssuer:
		metadata = &openid4vci.CredentialIssuerMetadataParameters{}
		jwtTyp = "openidvci-issuer-metadata+jwt"
	case MetadataTypeOAuth2:
		metadata = &oauth2.AuthorizationServerMetadata{}
		jwtTyp = "JWT"
	default:
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "unsupported metadata type: %q", req.GetMetadataType())
	}

	if err := json.Unmarshal(req.GetMetadataJson(), metadata); err != nil {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "failed to parse metadata: %v", err)
	}

	if err := helpers.CheckSimple(metadata); err != nil {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "metadata validation failed: %v", err)
	}

	// Verify the metadata's own issuer identifier matches req.iss to prevent
	// signing metadata that points to attacker-controlled endpoints.
	if metaIss := metadata.MetadataIssuer(); metaIss != req.GetIss() {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "metadata issuer %q does not match request iss %q", metaIss, req.GetIss())
	}

	body, err := metadata.MarshalJWTClaims()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Remove signed_metadata to avoid self-referencing in the JWT payload.
	delete(body, "signed_metadata")

	// Always override standard claims to prevent caller-supplied metadata_json
	// from injecting arbitrary iss/sub/iat values into the signed JWT.
	// For issuer/authorization-server metadata the subject must be the issuer
	// itself (RFC 8414 §2, OID4VCI §11.2.1). Reject any other value.
	if sub := req.GetSub(); sub != "" && sub != req.GetIss() {
		return nil, grpcstatus.Error(codes.InvalidArgument, "sub must be empty or equal to iss")
	}
	body["iat"] = time.Now().Unix()
	body["iss"] = req.GetIss()
	body["sub"] = req.GetIss()

	header := jwt.MapClaims{
		"typ": jwtTyp,
	}

	// Include the x5c chain of whatever key is signing this. Under an ARF
	// trust framework that is the access certificate (WRPAC), which is what
	// lets a wallet establish who the issuer is - JWKS is self-asserted and
	// establishes nothing on its own.
	if len(c.metadataChain) > 0 {
		header["x5c"] = c.metadataChain
	}

	signed, err := jose.MakeJWT(ctx, header, body, c.metadataSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to sign metadata: %w", err)
	}

	return &apiv1_issuer.SignMetadataReply{
		SignedMetadata: signed,
	}, nil
}
