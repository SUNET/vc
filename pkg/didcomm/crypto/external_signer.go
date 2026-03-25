// Package crypto provides HSM and external signer support for DIDComm operations.
package crypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	vccrypto "github.com/SUNET/vc/pkg/vc20/crypto"
)

// ExternalSigner wraps a VCSigner for use with DIDComm JWS operations.
// This enables HSM-backed keys and other external signers to be used with DIDComm.
type ExternalSigner struct {
	signer    vccrypto.VCSigner
	kid       string
	algorithm jwa.SignatureAlgorithm
}

// NewExternalSigner creates a DIDComm-compatible signer from a VCSigner.
// The kid parameter should be the DID URL of the verification method.
func NewExternalSigner(signer vccrypto.VCSigner, kid string) (*ExternalSigner, error) {
	alg, err := algorithmForVCSigner(signer)
	if err != nil {
		return nil, err
	}

	return &ExternalSigner{
		signer:    signer,
		kid:       kid,
		algorithm: alg,
	}, nil
}

// algorithmForVCSigner determines the JWA algorithm from the VCSigner.
func algorithmForVCSigner(signer vccrypto.VCSigner) (jwa.SignatureAlgorithm, error) {
	switch signer.Algorithm() {
	case "ES256":
		return jwa.ES256(), nil
	case "ES384":
		return jwa.ES384(), nil
	case "ES512":
		return jwa.ES512(), nil
	case "EdDSA", "Ed25519":
		return jwa.EdDSA(), nil
	default:
		return jwa.NoSignature(), fmt.Errorf("unsupported algorithm: %s", signer.Algorithm())
	}
}

// Sign creates a JWS using the external signer.
func (es *ExternalSigner) Sign(ctx context.Context, plaintext []byte, opts SignOptions) ([]byte, error) {
	// Create a JWK from the public key for use in the header
	pubKeyJWK, err := es.publicJWK()
	if err != nil {
		return nil, fmt.Errorf("failed to create public key JWK: %w", err)
	}

	// Build protected header as a map
	header := map[string]any{
		"alg": es.algorithm.String(),
	}
	if es.kid != "" {
		header["kid"] = es.kid
	}

	// Create signing input: BASE64URL(header) || '.' || BASE64URL(payload)
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadB64 := ""
	if !opts.Detached {
		payloadB64 = base64.RawURLEncoding.EncodeToString(plaintext)
	}

	signingInput := []byte(headerB64 + "." + payloadB64)

	// Hash the signing input according to the algorithm
	digest, err := hashForAlgorithm(es.algorithm, signingInput)
	if err != nil {
		return nil, fmt.Errorf("failed to hash signing input: %w", err)
	}

	// Sign using the external signer
	signature, err := es.signer.SignDigest(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("external signer failed: %w", err)
	}

	// Encode signature
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Return compact serialization: header.payload.signature
	result := headerB64 + "." + payloadB64 + "." + sigB64

	// Verify the signature works by using the public key
	_, err = jws.Verify([]byte(result), jws.WithKey(es.algorithm, pubKeyJWK))
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return []byte(result), nil
}

// hashForAlgorithm computes the appropriate hash for the signing algorithm.
func hashForAlgorithm(alg jwa.SignatureAlgorithm, data []byte) ([]byte, error) {
	var hashFunc crypto.Hash

	switch alg {
	case jwa.ES256():
		hashFunc = crypto.SHA256
	case jwa.ES384():
		hashFunc = crypto.SHA384
	case jwa.ES512():
		hashFunc = crypto.SHA512
	case jwa.EdDSA():
		// EdDSA doesn't use pre-hashing - return the data as-is
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm for hashing: %s", alg)
	}

	if !hashFunc.Available() {
		return nil, fmt.Errorf("hash function not available: %s", hashFunc)
	}

	h := hashFunc.New()
	h.Write(data)
	return h.Sum(nil), nil
}

// publicJWK creates a JWK from the signer's public key.
func (es *ExternalSigner) publicJWK() (jwk.Key, error) {
	pubKey := es.signer.PublicKey()

	switch pk := pubKey.(type) {
	case *ecdsa.PublicKey:
		return jwk.Import(pk)
	case ed25519.PublicKey:
		return jwk.Import(pk)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// KeyID returns the key identifier.
func (es *ExternalSigner) KeyID() string {
	return es.kid
}

// Algorithm returns the JWA signature algorithm.
func (es *ExternalSigner) Algorithm() jwa.SignatureAlgorithm {
	return es.algorithm
}

// PublicKey returns the public key.
func (es *ExternalSigner) PublicKey() crypto.PublicKey {
	return es.signer.PublicKey()
}

// SignMessage wraps Sign with DIDComm standard options.
// This is a convenience method for typical DIDComm signing.
func (es *ExternalSigner) SignMessage(ctx context.Context, message []byte) ([]byte, error) {
	return es.Sign(ctx, message, SignOptions{})
}

// VCSignerAdapter wraps a pki.RawSigner to implement VCSigner.
// This enables HSM keys configured through pki to be used with both VC20 and DIDComm.
type VCSignerAdapter struct {
	algorithm string
	pubKey    crypto.PublicKey
	signFn    func(ctx context.Context, digest []byte) ([]byte, error)
}

// NewVCSignerFromRawSigner creates a VCSigner from a pki.RawSigner.
// This bridges the pki HSM configuration to the VCSigner interface.
func NewVCSignerFromECDSA(key *ecdsa.PrivateKey) vccrypto.VCSigner {
	return vccrypto.NewECDSAKeyWrapper(key)
}

// NewVCSignerFromEdDSA creates a VCSigner from an Ed25519 private key.
func NewVCSignerFromEdDSA(key ed25519.PrivateKey) vccrypto.VCSigner {
	return vccrypto.NewEdDSAKeyWrapper(key)
}

// Algorithms returns the JWA algorithm for a given curve.
func ECDSAAlgorithmForCurve(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "ES256"
	case elliptic.P384():
		return "ES384"
	case elliptic.P521():
		return "ES512"
	default:
		return ""
	}
}
