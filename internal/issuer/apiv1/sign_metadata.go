package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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
)

// signableMetadata is implemented by metadata structs that can be
// validated and marshalled into JWT claims.
type signableMetadata interface {
	MarshalJWTClaims() (jwt.MapClaims, error)
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

	c.log.Debug("SignMetadata", "typ", req.GetTyp(), "iss", req.GetIss())

	if !c.signMetadataRL.Allow() {
		return nil, fmt.Errorf("SignMetadata rate limit exceeded")
	}

	if len(req.GetMetadataJson()) == 0 {
		return nil, fmt.Errorf("metadata_json is required")
	}
	if len(req.GetMetadataJson()) > 64*1024 {
		return nil, fmt.Errorf("metadata_json is too large")
	}
	if req.GetIss() != c.cfg.Issuer.IssuerURL {
		return nil, fmt.Errorf("iss must equal configured issuer_url")
	}

	// Pick the concrete struct and JWT typ for this metadata type.
	// Unmarshalling into it strips unknown/injected fields (struct-based whitelist).
	var (
		metadata signableMetadata
		jwtTyp   string
	)
	switch req.GetTyp() {
	case MetadataTypeVCIIssuer:
		metadata = &openid4vci.CredentialIssuerMetadataParameters{}
		jwtTyp = "openidvci-issuer-metadata+jwt"
	case MetadataTypeOAuth2:
		metadata = &oauth2.AuthorizationServerMetadata{}
		jwtTyp = "JWT"
	default:
		return nil, fmt.Errorf("unsupported metadata type: %q", req.GetTyp())
	}

	if err := json.Unmarshal(req.GetMetadataJson(), metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	if err := helpers.CheckSimple(metadata); err != nil {
		return nil, fmt.Errorf("metadata validation failed: %w", err)
	}

	body, err := metadata.MarshalJWTClaims()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Remove signed_metadata to avoid self-referencing in the JWT payload.
	delete(body, "signed_metadata")

	// Always override standard claims to prevent caller-supplied metadata_json
	// from injecting arbitrary iss/sub/iat values into the signed JWT.
	body["iat"] = time.Now().Unix()
	body["iss"] = req.GetIss()
	sub := req.GetSub()
	if sub == "" {
		sub = req.GetIss()
	}
	body["sub"] = sub

	header := jwt.MapClaims{
		"typ": jwtTyp,
	}

	// Include x5c certificate chain if the issuer has one configured
	if len(c.signerChain) > 0 {
		header["x5c"] = c.signerChain
	}

	signed, err := jose.MakeJWT(ctx, header, body, c.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign metadata: %w", err)
	}

	return &apiv1_issuer.SignMetadataReply{
		SignedMetadata: signed,
	}, nil
}
