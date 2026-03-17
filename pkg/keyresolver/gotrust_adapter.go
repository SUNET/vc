package keyresolver

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
)

// GoTrustResolver uses go-trust authzenclient for key resolution via AuthZEN protocol.
// It implements the Resolver interface and provides both resolution-only requests
// (to fetch DID documents/entity configurations) and full trust evaluation.
type GoTrustResolver struct {
	client *authzenclient.Client
}

// NewGoTrustResolver creates a resolver using go-trust authzenclient with a known PDP URL.
func NewGoTrustResolver(baseURL string) *GoTrustResolver {
	client := authzenclient.New(baseURL)
	return &GoTrustResolver{client: client}
}

// NewGoTrustResolverWithDiscovery creates a resolver using AuthZEN discovery.
// It fetches the PDP configuration from .well-known/authzen-configuration.
func NewGoTrustResolverWithDiscovery(ctx context.Context, baseURL string) (*GoTrustResolver, error) {
	client, err := authzenclient.Discover(ctx, baseURL)
	if err != nil {
		return nil, fmt.Errorf("authzen discovery failed: %w", err)
	}
	return &GoTrustResolver{client: client}, nil
}

// NewGoTrustResolverWithClient creates a resolver using an existing authzenclient.Client.
// This allows for custom configuration of the underlying client.
func NewGoTrustResolverWithClient(client *authzenclient.Client) *GoTrustResolver {
	return &GoTrustResolver{client: client}
}

// resolveAndExtractMetadata is a helper that performs the common resolution pattern.
// It resolves the identifier via the PDP and returns the trust_metadata if successful.
func (g *GoTrustResolver) resolveAndExtractMetadata(ctx context.Context, identifier string) (any, error) {
	resp, err := g.client.Resolve(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("resolution request failed: %w", err)
	}

	if !resp.Decision {
		reason := "unknown"
		if resp.Context != nil && resp.Context.Reason != nil {
			if r, ok := resp.Context.Reason["error"].(string); ok {
				reason = r
			}
		}
		return nil, fmt.Errorf("resolution denied for %s: %s", identifier, reason)
	}

	if resp.Context == nil || resp.Context.TrustMetadata == nil {
		return nil, fmt.Errorf("no trust_metadata in response for %s", identifier)
	}

	return resp.Context.TrustMetadata, nil
}

// ResolveEd25519 resolves an Ed25519 public key from a verification method identifier.
// It sends a resolution-only request to the PDP and extracts the key from the returned
// trust_metadata (DID document or entity configuration).
func (g *GoTrustResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	ctx := context.Background()
	return g.ResolveEd25519WithContext(ctx, verificationMethod)
}

// ResolveEd25519WithContext resolves an Ed25519 key with a provided context.
func (g *GoTrustResolver) ResolveEd25519WithContext(ctx context.Context, verificationMethod string) (ed25519.PublicKey, error) {
	metadata, err := g.resolveAndExtractMetadata(ctx, verificationMethod)
	if err != nil {
		return nil, err
	}
	return ExtractEd25519FromMetadata(metadata, verificationMethod)
}

// ResolveECDSA resolves an ECDSA public key from a verification method identifier.
func (g *GoTrustResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	ctx := context.Background()
	return g.ResolveECDSAWithContext(ctx, verificationMethod)
}

// ResolveECDSAWithContext resolves an ECDSA key with a provided context.
func (g *GoTrustResolver) ResolveECDSAWithContext(ctx context.Context, verificationMethod string) (*ecdsa.PublicKey, error) {
	metadata, err := g.resolveAndExtractMetadata(ctx, verificationMethod)
	if err != nil {
		return nil, err
	}
	return ExtractECDSAFromMetadata(metadata, verificationMethod)
}

// EvaluateTrustEd25519 validates an Ed25519 key binding via go-trust.
// This sends a full trust evaluation request (not resolution-only).
func (g *GoTrustResolver) EvaluateTrustEd25519(ctx context.Context, subjectID string, publicKey ed25519.PublicKey, role string) (bool, error) {
	jwk := Ed25519ToJWK(publicKey)

	var action *authzen.Action
	if role != "" {
		action = &authzen.Action{Name: role}
	}

	resp, err := g.client.EvaluateJWK(ctx, subjectID, jwk, action)
	if err != nil {
		return false, fmt.Errorf("trust evaluation failed: %w", err)
	}

	return resp.Decision, nil
}

// EvaluateTrustECDSA validates an ECDSA key binding via go-trust.
func (g *GoTrustResolver) EvaluateTrustECDSA(ctx context.Context, subjectID string, publicKey *ecdsa.PublicKey, role string) (bool, error) {
	jwk, err := ECDSAToJWK(publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to convert key to JWK: %w", err)
	}

	var action *authzen.Action
	if role != "" {
		action = &authzen.Action{Name: role}
	}

	resp, err := g.client.EvaluateJWK(ctx, subjectID, jwk, action)
	if err != nil {
		return false, fmt.Errorf("trust evaluation failed: %w", err)
	}

	return resp.Decision, nil
}

// GetClient returns the underlying authzenclient.Client for advanced usage.
func (g *GoTrustResolver) GetClient() *authzenclient.Client {
	return g.client
}

// ResolveX25519 resolves an X25519 key agreement key via go-trust.
// This extracts the keyAgreement keys from the trust_metadata returned by the PDP.
func (g *GoTrustResolver) ResolveX25519(did string) (*ecdh.PublicKey, error) {
	ctx := context.Background()
	return g.ResolveX25519WithContext(ctx, did)
}

// ResolveX25519WithContext resolves an X25519 key with a provided context.
func (g *GoTrustResolver) ResolveX25519WithContext(ctx context.Context, did string) (*ecdh.PublicKey, error) {
	metadata, err := g.resolveAndExtractMetadata(ctx, did)
	if err != nil {
		return nil, err
	}
	return ExtractX25519FromMetadata(metadata, did)
}

// ResolveService resolves a DIDCommMessaging service endpoint via go-trust.
// This extracts service endpoints from the trust_metadata returned by the PDP.
func (g *GoTrustResolver) ResolveService(did string) (*DIDCommService, error) {
	ctx := context.Background()
	return g.ResolveServiceWithContext(ctx, did)
}

// ResolveServiceWithContext resolves a service with a provided context.
func (g *GoTrustResolver) ResolveServiceWithContext(ctx context.Context, did string) (*DIDCommService, error) {
	metadata, err := g.resolveAndExtractMetadata(ctx, did)
	if err != nil {
		return nil, err
	}
	return ExtractServiceFromMetadata(metadata, did)
}

// ResolveMetadata resolves the full trust_metadata for a DID.
// This is useful when you need access to the full DID document or entity configuration.
func (g *GoTrustResolver) ResolveMetadata(ctx context.Context, did string) (map[string]any, error) {
	metadata, err := g.resolveAndExtractMetadata(ctx, did)
	if err != nil {
		return nil, err
	}

	doc, ok := metadata.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid trust_metadata format: expected map, got %T", metadata)
	}

	return doc, nil
}

// Ed25519ToJWK converts an Ed25519 public key to JWK format.
func Ed25519ToJWK(publicKey ed25519.PublicKey) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(publicKey),
	}
}

// JWKToEd25519 extracts an Ed25519 public key from a JWK.
func JWKToEd25519(jwk map[string]any) (ed25519.PublicKey, error) {
	kty, ok := jwk["kty"].(string)
	if !ok || kty != "OKP" {
		return nil, fmt.Errorf("invalid key type, expected OKP, got %v", jwk["kty"])
	}

	crv, ok := jwk["crv"].(string)
	if !ok || crv != "Ed25519" {
		return nil, fmt.Errorf("invalid curve, expected Ed25519, got %v", jwk["crv"])
	}

	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, expected %d", len(pubBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(pubBytes), nil
}

// ECDSAToJWK converts an ECDSA public key to JWK format.
func ECDSAToJWK(publicKey *ecdsa.PublicKey) (map[string]any, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	var crv string
	switch publicKey.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	default:
		return nil, fmt.Errorf("unsupported curve: %v", publicKey.Curve.Params().Name)
	}

	// Get the byte size for the curve
	byteLen := (publicKey.Curve.Params().BitSize + 7) / 8

	// Pad coordinates to the correct length
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	return map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}, nil
}

// JWKToECDSA extracts an ECDSA public key from a JWK.
func JWKToECDSA(jwk map[string]any) (*ecdsa.PublicKey, error) {
	kty, ok := jwk["kty"].(string)
	if !ok || kty != "EC" {
		return nil, fmt.Errorf("invalid key type, expected EC, got %v", jwk["kty"])
	}

	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing curve")
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}

	yStr, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing y coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("point is not on curve")
	}

	return pubKey, nil
}
