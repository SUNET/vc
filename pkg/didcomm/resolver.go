//go:build didcomm && vc20

package didcomm

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"vc/pkg/keyresolver"
)

// Resolver provides DID resolution for DIDComm operations.
// It wraps the existing keyresolver.SmartResolver with DIDComm-specific functionality.
type Resolver struct {
	smart *keyresolver.SmartResolver
}

// NewResolver creates a DIDComm resolver using AuthZEN-based DID resolution.
// The pdpURL is the URL of the AuthZEN Policy Decision Point for trust evaluation.
func NewResolver(pdpURL string) *Resolver {
	goTrust := keyresolver.NewGoTrustResolver(pdpURL)
	return &Resolver{
		smart: keyresolver.NewSmartResolver(goTrust),
	}
}

// NewResolverWithBase creates a DIDComm resolver with a custom base resolver.
// This allows using different resolution backends.
func NewResolverWithBase(base keyresolver.Resolver) *Resolver {
	return &Resolver{
		smart: keyresolver.NewSmartResolver(base),
	}
}

// KeyAgreementKey represents a key that can be used for key agreement (encryption).
type KeyAgreementKey struct {
	// ID is the key ID (verification method ID)
	ID string

	// Type is the key type (e.g., "X25519KeyAgreementKey2020", "JsonWebKey2020")
	Type string

	// Controller is the DID that controls this key
	Controller string

	// PublicKey is the raw public key material
	// Type depends on the curve: *ecdh.PublicKey for X25519/P-256/P-384
	PublicKey any
}

// VerificationKey represents a key that can be used for verification (signing).
type VerificationKey struct {
	// ID is the key ID (verification method ID)
	ID string

	// Type is the key type (e.g., "Ed25519VerificationKey2020", "JsonWebKey2020")
	Type string

	// Controller is the DID that controls this key
	Controller string

	// PublicKey is the raw public key material
	// Type: ed25519.PublicKey for EdDSA, *ecdsa.PublicKey for ES256/ES256K/ES384
	PublicKey any
}

// DIDCommService represents a DIDCommMessaging service endpoint from a DID document.
type DIDCommService struct {
	// ID is the service ID
	ID string

	// ServiceEndpoint is the URI or DID for message delivery
	ServiceEndpoint string

	// RoutingKeys are the keys to use for routing/mediation
	RoutingKeys []string

	// Accept lists the accepted media types
	Accept []string
}

// ResolveKeyAgreement resolves key agreement keys for a DID.
// These keys are used for encryption (ECDH key exchange).
func (r *Resolver) ResolveKeyAgreement(ctx context.Context, did string) ([]KeyAgreementKey, error) {
	// For now, we use the existing resolver to get the DID document
	// and extract key agreement keys from it.
	// This is a simplified implementation that will be expanded.

	// Try to resolve as Ed25519 first (many DIDs use Ed25519 for both signing and key agreement via conversion)
	edKey, err := r.smart.ResolveEd25519(did)
	if err == nil {
		// Convert Ed25519 to X25519 for key agreement
		x25519Key, err := ed25519PublicKeyToX25519(edKey)
		if err == nil {
			return []KeyAgreementKey{
				{
					ID:         did + "#key-agreement-1",
					Type:       "X25519KeyAgreementKey2020",
					Controller: did,
					PublicKey:  x25519Key,
				},
			}, nil
		}
	}

	// Try ECDSA resolver for P-256/P-384 via SmartResolver's ResolveECDSA method
	ecKey, err := r.smart.ResolveECDSA(did)
	if err == nil {
		ecdhKey, err := ecdsaPublicKeyToECDH(ecKey)
		if err == nil {
			return []KeyAgreementKey{
				{
					ID:         did + "#key-agreement-1",
					Type:       "JsonWebKey2020",
					Controller: did,
					PublicKey:  ecdhKey,
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("%w: no key agreement keys found for %s", ErrKeyAgreementNotFound, did)
}

// ResolveVerification resolves verification keys for a DID.
// These keys are used for signature verification.
func (r *Resolver) ResolveVerification(ctx context.Context, did string) ([]VerificationKey, error) {
	var keys []VerificationKey

	// Try Ed25519
	edKey, err := r.smart.ResolveEd25519(did)
	if err == nil {
		keys = append(keys, VerificationKey{
			ID:         did + "#key-1",
			Type:       "Ed25519VerificationKey2020",
			Controller: did,
			PublicKey:  edKey,
		})
	}

	// Try ECDSA via SmartResolver
	ecKey, err := r.smart.ResolveECDSA(did)
	if err == nil {
		keys = append(keys, VerificationKey{
			ID:         did + "#key-2",
			Type:       "JsonWebKey2020",
			Controller: did,
			PublicKey:  ecKey,
		})
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no verification keys found for %s", ErrKeyNotFound, did)
	}

	return keys, nil
}

// ResolveService resolves DIDCommMessaging service endpoints for a DID.
func (r *Resolver) ResolveService(ctx context.Context, did string) (*DIDCommService, error) {
	// This requires full DID document resolution.
	// For now, return an error indicating service resolution is not yet implemented.
	// Full implementation will parse the DID document and extract DIDCommMessaging services.
	return nil, fmt.Errorf("%w: service resolution not yet implemented", ErrServiceNotFound)
}

// ed25519PublicKeyToX25519 converts an Ed25519 public key to X25519 for key agreement.
// This is done by interpreting the Ed25519 key as a point on the Edwards curve
// and converting to the Montgomery form used by X25519.
func ed25519PublicKeyToX25519(edPub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size")
	}

	// The conversion from Ed25519 to X25519 requires careful handling.
	// For proper implementation, we should use a dedicated library.
	// This is a placeholder that returns an error until proper conversion is implemented.

	// TODO: Implement proper Ed25519 -> X25519 conversion
	// Options:
	// 1. Use filippo.io/edwards25519 for proper point conversion
	// 2. Use golang.org/x/crypto/curve25519 with proper point transformation

	return nil, fmt.Errorf("Ed25519 to X25519 conversion not yet implemented")
}

// ecdsaPublicKeyToECDH converts an ECDSA public key to ECDH format.
func ecdsaPublicKeyToECDH(ecPub *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	return ecPub.ECDH()
}

// DIDDocument represents a W3C DID Document.
// This is a subset of the full DID Document structure, containing fields relevant to DIDComm.
type DIDDocument struct {
	Context            []string            `json:"@context,omitempty"`
	ID                 string              `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	KeyAgreement       []any               `json:"keyAgreement,omitempty"`
	Service            []Service           `json:"service,omitempty"`
}

// VerificationMethod represents a verification method in a DID Document.
type VerificationMethod struct {
	ID                 string          `json:"id"`
	Type               string          `json:"type"`
	Controller         string          `json:"controller"`
	PublicKeyJwk       json.RawMessage `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string          `json:"publicKeyMultibase,omitempty"`
}

// Service represents a service in a DID Document.
type Service struct {
	ID              string   `json:"id"`
	Type            string   `json:"type"`
	ServiceEndpoint any      `json:"serviceEndpoint"`
	RoutingKeys     []string `json:"routingKeys,omitempty"`
	Accept          []string `json:"accept,omitempty"`
}
