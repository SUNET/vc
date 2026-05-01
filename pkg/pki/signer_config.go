package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// SignerConfig provides a high-level interface for cryptographic operations
// without requiring services to directly handle KeyMaterial. It supports both
// file-based keys and HSM-based keys through PKCS#11.
type SignerConfig struct {
	// KeyConfig contains the underlying key configuration
	KeyConfig

	// Internal state for lazy loading
	keyMaterial *KeyMaterial
	once        sync.Once
	initErr     error
}

// NewSignerConfig creates a new SignerConfig with the specified configuration.
// Keys are loaded lazily on first use.
func NewSignerConfig(config *KeyConfig) *SignerConfig {
	return &SignerConfig{
		KeyConfig: *config,
	}
}

// initialize loads the key material if not already loaded (thread-safe)
func (sc *SignerConfig) initialize() error {
	sc.once.Do(func() {
		keyLoader := NewKeyLoader()
		sc.keyMaterial, sc.initErr = keyLoader.LoadKeyMaterial(&sc.KeyConfig)
	})
	return sc.initErr
}

// Sign signs the provided data using the configured key.
// The signature algorithm is automatically determined from the key type.
func (sc *SignerConfig) Sign(data []byte) ([]byte, error) {
	if err := sc.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize key material: %w", err)
	}

	signer, ok := sc.keyMaterial.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	// Determine hash algorithm from key type and size
	hashAlg := getHashAlgorithmForKey(signer.Public())

	// Hash the data
	hasher := hashAlg.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, fmt.Errorf("failed to hash data: %w", err)
	}
	digest := hasher.Sum(nil)

	// Sign the digest
	signature, err := signer.Sign(nil, digest, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

// SignJWT signs a JWT with the specified claims using the configured key.
func (sc *SignerConfig) SignJWT(claims jwt.Claims) (string, error) {
	if err := sc.initialize(); err != nil {
		return "", fmt.Errorf("failed to initialize key material: %w", err)
	}

	// Use the signing method from KeyMaterial
	method := sc.keyMaterial.SigningMethod

	// Create and sign token
	token := jwt.NewWithClaims(method, claims)

	// Set key ID if certificate is available
	if sc.keyMaterial.Cert != nil {
		token.Header["kid"] = getCertificateKeyID(sc.keyMaterial.Cert)
	}

	tokenString, err := token.SignedString(sc.keyMaterial.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// GetJWK returns the public key as a JSON Web Key (JWK).
// The kid is derived using the same logic as KeyMaterialSigner.KeyID()
// to ensure consistency between JWT headers and JWKS endpoints.
func (sc *SignerConfig) GetJWK() (*jose.JSONWebKey, error) {
	if err := sc.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize key material: %w", err)
	}

	signer, ok := sc.keyMaterial.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	// Use the same kid derivation as KeyMaterialSigner to ensure
	// JWT header kid and JWKS kid are always consistent.
	kid := determineKeyID(sc.keyMaterial)

	jwk := &jose.JSONWebKey{
		Key:       signer.Public(),
		KeyID:     kid,
		Algorithm: sc.keyMaterial.SigningMethod.Alg(),
		Use:       "sig",
	}

	// Add certificate chain if available
	if sc.keyMaterial.Cert != nil {
		jwk.Certificates = []*x509.Certificate{sc.keyMaterial.Cert}
	}

	return jwk, nil
}

// GetCertificate returns the X.509 certificate associated with the key.
func (sc *SignerConfig) GetCertificate() (*x509.Certificate, error) {
	if err := sc.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize key material: %w", err)
	}

	if sc.keyMaterial.Cert == nil {
		return nil, fmt.Errorf("no certificate available")
	}

	return sc.keyMaterial.Cert, nil
}

// GetCertificateChain returns the full certificate chain as base64-encoded DER.
func (sc *SignerConfig) GetCertificateChain() ([]string, error) {
	if err := sc.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize key material: %w", err)
	}

	return sc.keyMaterial.Chain, nil
}

// GetPrivateKey returns the underlying private key.
// This method should be used sparingly - prefer using Sign() or SignJWT() instead.
func (sc *SignerConfig) GetPrivateKey() (crypto.PrivateKey, error) {
	if err := sc.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize key material: %w", err)
	}

	return sc.keyMaterial.PrivateKey, nil
}

// GetKeyMaterial returns the underlying KeyMaterial.
// This method should be used sparingly - prefer using the specific methods instead.
func (sc *SignerConfig) GetKeyMaterial() (*KeyMaterial, error) {
	if err := sc.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize key material: %w", err)
	}

	return sc.keyMaterial, nil
}

// RawSigner returns a RawSigner interface for advanced signing operations.
// This is useful for protocols like W3C Data Integrity that need to sign pre-computed digests.
func (sc *SignerConfig) RawSigner() (RawSigner, error) {
	if err := sc.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize key material: %w", err)
	}

	return NewKeyMaterialSigner(sc.keyMaterial), nil
}

// getHashAlgorithmForKey returns the appropriate hash algorithm for a given public key.
func getHashAlgorithmForKey(pubKey crypto.PublicKey) crypto.Hash {
	switch k := pubKey.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 521:
			return crypto.SHA512
		case 384:
			return crypto.SHA384
		default:
			return crypto.SHA256
		}
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		switch {
		case bits >= 4096:
			return crypto.SHA512
		case bits >= 3072:
			return crypto.SHA384
		default:
			return crypto.SHA256
		}
	default:
		return crypto.SHA256
	}
}

// getCertificateKeyID generates a key ID from an X.509 certificate.
// Uses SHA-256 hash of the certificate's public key.
func getCertificateKeyID(cert *x509.Certificate) string {
	// Use subject key identifier if available
	if len(cert.SubjectKeyId) > 0 {
		return hex.EncodeToString(cert.SubjectKeyId)
	}

	// Fall back to hashing the public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		// If marshaling fails, use serial number
		return cert.SerialNumber.Text(16)
	}

	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:])
}
