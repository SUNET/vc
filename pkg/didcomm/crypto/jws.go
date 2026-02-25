//go:build didcomm && vc20

package crypto

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// SignedMessage represents a DIDComm signed message (JWS).
type SignedMessage struct {
	// Payload is the base64url-encoded message
	Payload string `json:"payload"`

	// Signatures contains one or more signatures
	Signatures []Signature `json:"signatures"`
}

// Signature represents a single JWS signature.
type Signature struct {
	// Protected is the base64url-encoded protected header
	Protected string `json:"protected"`

	// Signature is the base64url-encoded signature value
	Signature string `json:"signature"`
}

// JWSHeader represents the protected header of a JWS.
type JWSHeader struct {
	// Algorithm is the signing algorithm (EdDSA, ES256, ES256K)
	Algorithm string `json:"alg"`

	// KeyID identifies the signing key
	KeyID string `json:"kid,omitempty"`

	// Type is the media type (should be "didcomm-signed+json")
	Type string `json:"typ,omitempty"`
}

// SignOptions configures signing behavior.
type SignOptions struct {
	// Algorithm is the signing algorithm. If empty, inferred from key type.
	Algorithm string

	// Detached indicates whether to use detached payload
	Detached bool
}

// Sign creates a JWS signature over the plaintext using the private key.
func Sign(ctx context.Context, plaintext []byte, privateKey jwk.Key, opts SignOptions) ([]byte, error) {
	// Determine algorithm from key if not specified
	alg, err := determineSigningAlgorithm(privateKey, opts.Algorithm)
	if err != nil {
		return nil, err
	}

	signOpts := []jws.SignOption{
		jws.WithKey(alg, privateKey),
	}

	if opts.Detached {
		signOpts = append(signOpts, jws.WithDetachedPayload(plaintext))
	}

	signed, err := jws.Sign(plaintext, signOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	return signed, nil
}

// Verify verifies a JWS signature using the public key.
// Returns the verified payload.
func Verify(ctx context.Context, signed []byte, publicKey jwk.Key) ([]byte, error) {
	// Determine algorithm from key
	alg, err := determineSigningAlgorithm(publicKey, "")
	if err != nil {
		return nil, err
	}

	payload, err := jws.Verify(signed, jws.WithKey(alg, publicKey))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	return payload, nil
}

// VerifyWithResolver verifies a JWS using a resolver to fetch the public key.
func VerifyWithResolver(ctx context.Context, signed []byte, resolver KeyResolver) ([]byte, error) {
	// Parse the JWS to get the key ID from the header
	msg, err := jws.Parse(signed)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse JWS: %v", ErrInvalidJWS, err)
	}

	// Get signatures
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, fmt.Errorf("%w: no signatures found", ErrInvalidJWS)
	}

	// Try the first signature
	sig := sigs[0]
	headers := sig.ProtectedHeaders()

	var kid string
	if err := headers.Get("kid", &kid); err != nil {
		return nil, fmt.Errorf("%w: no kid in signature header", ErrInvalidJWS)
	}

	publicKey, err := resolver.ResolveKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to resolve key %s: %v", ErrVerificationFailed, kid, err)
	}

	return Verify(ctx, signed, publicKey)
}

// KeyResolver resolves public keys by key ID.
type KeyResolver interface {
	ResolveKey(ctx context.Context, kid string) (jwk.Key, error)
}

// determineSigningAlgorithm determines the JWA signing algorithm from a key.
func determineSigningAlgorithm(key jwk.Key, hint string) (jwa.SignatureAlgorithm, error) {
	if hint != "" {
		return parseSigningAlgorithm(hint)
	}

	// Infer from key type using KeyType() method (jwa.KeyType, not string)
	kty := key.KeyType()

	switch kty {
	case jwa.OKP():
		// Assume Ed25519 for OKP keys
		return jwa.EdDSA(), nil
	case jwa.EC():
		// Get curve - use jwa.EllipticCurveAlgorithm type
		var crv jwa.EllipticCurveAlgorithm
		if err := key.Get("crv", &crv); err != nil {
			return jwa.ES256(), fmt.Errorf("%w: EC key missing crv", ErrInvalidKey)
		}
		switch crv {
		case jwa.P256():
			return jwa.ES256(), nil
		case jwa.P384():
			return jwa.ES384(), nil
		default:
			// Check string representation for secp256k1 (requires jwx_es256k build tag)
			if crv.String() == "secp256k1" {
				return jwa.ES256K(), nil
			}
			return jwa.ES256(), fmt.Errorf("%w: unsupported curve %v", ErrUnsupportedAlgorithm, crv)
		}
	default:
		return jwa.EdDSA(), fmt.Errorf("%w: unsupported key type %v", ErrUnsupportedAlgorithm, kty)
	}
}

// parseSigningAlgorithm converts a string algorithm name to jwa.SignatureAlgorithm.
func parseSigningAlgorithm(alg string) (jwa.SignatureAlgorithm, error) {
	switch alg {
	case "EdDSA":
		return jwa.EdDSA(), nil
	case "ES256":
		return jwa.ES256(), nil
	case "ES256K":
		return jwa.ES256K(), nil
	case "ES384":
		return jwa.ES384(), nil
	default:
		return jwa.EdDSA(), fmt.Errorf("%w: unknown algorithm %s", ErrUnsupportedAlgorithm, alg)
	}
}
