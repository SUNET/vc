package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/jose"

	"github.com/golang-jwt/jwt/v5"
)

// SignMetadata signs the provided metadata JSON with the issuer's own key
// (the same key advertised in JWKS). This ensures that signed_metadata
// is verifiable by looking up the signing key in JWKS.
func (c *Client) SignMetadata(ctx context.Context, req *apiv1_issuer.SignMetadataRequest) (*apiv1_issuer.SignMetadataReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:SignMetadata")
	defer span.End()

	c.log.Debug("SignMetadata", "typ", req.GetTyp(), "iss", req.GetIss())

	if len(req.GetMetadataJson()) == 0 {
		return nil, fmt.Errorf("metadata_json is required")
	}
	if req.GetTyp() == "" {
		return nil, fmt.Errorf("typ is required")
	}

	header := jwt.MapClaims{
		"typ": req.GetTyp(),
	}

	// Include x5c certificate chain if the issuer has one configured
	if len(c.signerChain) > 0 {
		header["x5c"] = c.signerChain
	}

	// Parse the metadata JSON into claims
	body := jwt.MapClaims{}
	if err := json.Unmarshal(req.GetMetadataJson(), &body); err != nil {
		return nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	body["iat"] = time.Now().Unix()
	if req.GetIss() != "" {
		body["iss"] = req.GetIss()
	}
	if req.GetSub() != "" {
		body["sub"] = req.GetSub()
	}

	// Remove signed_metadata from the JWT payload to avoid self-referencing
	delete(body, "signed_metadata")

	signed, err := jose.MakeJWT(ctx, header, body, c.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign metadata: %w", err)
	}

	return &apiv1_issuer.SignMetadataReply{
		SignedMetadata: signed,
	}, nil
}
