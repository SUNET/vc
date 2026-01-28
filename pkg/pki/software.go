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

	s := &SoftwareSigner{
		privateKey: privateKey,
		keyID:      keyID,
		algorithm:  method.Alg(),
	}

	// Extract public key
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		s.publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		s.publicKey = &key.PublicKey
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
		return encodeECDSASignature(r, sigS, key.Curve)
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
