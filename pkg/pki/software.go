package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// SoftwareSigner implements Signer using software-based keys.
type SoftwareSigner struct {
	privateKey crypto.PrivateKey
	publicKey  any
	algorithm  string
	keyID      string
}

// NewSoftwareSigner creates a new SoftwareSigner from a private key.
func NewSoftwareSigner(privateKey crypto.PrivateKey, keyID string) (*SoftwareSigner, error) {
	// Get algorithm using shared detection logic
	method, err := getSigningMethod(privateKey)
	if err != nil {
		return nil, err
	}

	// Extract public key before creating the signer
	var publicKey any
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &key.PublicKey
	default:
		return nil, fmt.Errorf("unsupported key type for public key extraction: %T", privateKey)
	}

	// Create signer only after all validation passes
	s := &SoftwareSigner{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
		algorithm:  method.Alg(),
	}

	return s, nil
}

// Sign signs data using the software key.
func (s *SoftwareSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	hash := getHashForAlgorithm(s.algorithm)
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
	case *ecdsa.PrivateKey:
		// Sign using ECDSA
		r, sigS, err := ecdsa.Sign(rand.Reader, key, hashed)
		if err != nil {
			return nil, err
		}
		// Convert to IEEE P1363 format (fixed-size R||S concatenation) as required by JWT RFC 7518
		return EncodeECDSASignature(r, sigS, key.Curve)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.privateKey)
	}
}

// SignDigest signs a pre-computed digest without additional hashing.
// This is useful for protocols like W3C Data Integrity that control the hashing process.
func (s *SoftwareSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		// Use crypto.Signer interface for RSA signing. This is PKCS#1 v1.5 signature
		// (not encryption), a standard scheme for JWT RS256/RS384/RS512.
		hash := getHashForAlgorithm(s.algorithm)
		return key.Sign(rand.Reader, digest, hash)
	case *ecdsa.PrivateKey:
		// Sign the digest directly using ECDSA
		r, sigS, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		// Convert to IEEE P1363 format (fixed-size R||S concatenation)
		return EncodeECDSASignature(r, sigS, key.Curve)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.privateKey)
	}
}

// Algorithm returns the JWT algorithm name.
func (s *SoftwareSigner) Algorithm() string {
	return s.algorithm
}

// KeyID returns the key identifier.
func (s *SoftwareSigner) KeyID() string {
	return s.keyID
}

// PublicKey returns the public key.
func (s *SoftwareSigner) PublicKey() any {
	return s.publicKey
}

// Hash selection mapping for optimal performance
var algorithmHashMap = map[string]crypto.Hash{
	"RS256": crypto.SHA256,
	"RS384": crypto.SHA384,
	"RS512": crypto.SHA512,
	"ES256": crypto.SHA256,
	"ES384": crypto.SHA384,
	"ES512": crypto.SHA512,
}

// getHashForAlgorithm returns the hash function for a JWT algorithm.
// Uses map lookup for O(1) performance.
func getHashForAlgorithm(algorithm string) crypto.Hash {
	if hash, ok := algorithmHashMap[algorithm]; ok {
		return hash
	}
	return crypto.SHA256 // Safe default
}
