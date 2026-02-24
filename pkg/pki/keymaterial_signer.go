package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// KeyMaterialSigner implements the Signer interface using KeyMaterial.
// It provides a concrete implementation for services that need signing capabilities.
type KeyMaterialSigner struct {
	km    *KeyMaterial
	keyID string
}

// NewKeyMaterialSigner creates a new Signer from KeyMaterial.
// The keyID is automatically determined from the certificate if available,
// or generated from the public key hash.
func NewKeyMaterialSigner(km *KeyMaterial) *KeyMaterialSigner {
	keyID := determineKeyID(km)
	return &KeyMaterialSigner{
		km:    km,
		keyID: keyID,
	}
}

// Sign signs the provided data using the private key.
func (s *KeyMaterialSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	// Use the correct hash algorithm based on the signing method
	hash := getHashForAlgorithm(s.km.SigningMethod.Alg())
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	switch key := s.km.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// Sign using ECDSA
		r, sigS, err := ecdsa.Sign(rand.Reader, key, hashed)
		if err != nil {
			return nil, err
		}
		// Convert to IEEE P1363 format (fixed-size R||S concatenation) as required by JWT RFC 7518
		return EncodeECDSASignature(r, sigS, key.Curve)
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.km.PrivateKey)
	}
}

// SignDigest signs a pre-computed digest without additional hashing.
// This is useful for protocols like W3C Data Integrity that control the hashing process.
func (s *KeyMaterialSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	switch key := s.km.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// Sign the digest directly using ECDSA
		r, sigS, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		// Convert to IEEE P1363 format (fixed-size R||S concatenation)
		return EncodeECDSASignature(r, sigS, key.Curve)
	case *rsa.PrivateKey:
		// Use crypto.Signer interface for RSA signing. This is PKCS#1 v1.5 signature
		// (not encryption), a standard scheme for JWT RS256/RS384/RS512.
		hash := getHashForAlgorithm(s.km.SigningMethod.Alg())
		return key.Sign(rand.Reader, digest, hash)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.km.PrivateKey)
	}
}

// Algorithm returns the JWT algorithm name based on the key type.
func (s *KeyMaterialSigner) Algorithm() string {
	return s.km.SigningMethod.Alg()
}

// KeyID returns the key identifier for JWT headers.
func (s *KeyMaterialSigner) KeyID() string {
	return s.keyID
}

// PublicKey returns the public key for verification.
func (s *KeyMaterialSigner) PublicKey() any {
	switch key := s.km.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		return key.Public()
	case *rsa.PrivateKey:
		return key.Public()
	default:
		return nil
	}
}

// PrivateKey returns the underlying private key.
// This is useful when integrating with libraries that need the raw crypto.PrivateKey.
func (s *KeyMaterialSigner) PrivateKey() crypto.PrivateKey {
	return s.km.PrivateKey
}

// determineKeyID extracts or generates a key identifier.
func determineKeyID(km *KeyMaterial) string {
	// Use certificate CN if available
	if km.Cert != nil {
		return km.Cert.Subject.CommonName
	}

	// Generate key ID from public key hash
	var pubKey crypto.PublicKey
	switch key := km.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		pubKey = key.Public()
	case *rsa.PrivateKey:
		pubKey = key.Public()
	default:
		return "default-key"
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "default-key"
	}

	hash := sha256.Sum256(pubBytes)
	return hex.EncodeToString(hash[:8])
}

// SigningMethod returns the JWT signing method for this key material.
func (s *KeyMaterialSigner) SigningMethod() jwt.SigningMethod {
	return s.km.SigningMethod
}

// GetCertificate returns the certificate if available.
func (s *KeyMaterialSigner) GetCertificate() *x509.Certificate {
	return s.km.Cert
}

// GetCertificateChain returns the certificate chain if available.
func (s *KeyMaterialSigner) GetCertificateChain() []string {
	return s.km.Chain
}
