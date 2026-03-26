package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-cryptoutil"
)

// ErrPKCS11NotSupported is returned when PKCS#11 support is not compiled in.
var ErrPKCS11NotSupported = errors.New("PKCS#11 support not compiled in; rebuild with -tags=pkcs11")

// KeyMaterial holds a private key with its optional certificate and chain
type KeyMaterial struct {
	PrivateKey    crypto.PrivateKey
	Cert          *x509.Certificate
	Chain         []string          // Base64-encoded DER certificates for x5c
	SigningMethod jwt.SigningMethod // JWT signing method determined from key type
}

// KeySource indicates where keys are loaded from
type KeySource int

const (
	// KeySourceFile loads from filesystem
	KeySourceFile KeySource = iota
	// KeySourceHSM loads from HSM
	KeySourceHSM
)

// KeyConfig holds configuration for loading keys from various sources.
// Supports both file-based and HSM-based keys with explicit control.
type KeyConfig struct {
	// File-based configuration
	PrivateKeyPath string `yaml:"private_key_path" validate:"required_without=PKCS11"` // Path to PEM key file
	ChainPath      string `yaml:"chain_path"`                                          // Path to certificate chain (optional)

	// HSM-based configuration
	PKCS11 *PKCS11Config `yaml:"pkcs11" validate:"required_without=PrivateKeyPath"` // PKCS#11 HSM config (optional)

	// Source selection (determines which config to use)
	// If empty, tries in order: File (if FilePath set), then HSM (if HSM set)
	Source KeySource `yaml:"source"`

	// EnableFile enables file-based key loading (default: true if FilePath set)
	EnableFile bool `yaml:"enable_file"`
	// EnableHSM enables HSM-based key loading (default: true if HSM set)
	EnableHSM bool `yaml:"enable_hsm"`

	// Priority defines fallback order when both are enabled
	// If nil, uses Source field or auto-detects based on what's configured
	Priority []KeySource `yaml:"priority" doc_example:"[\"hsm\", \"file\"]"`
}

// KeyLoader provides centralized key and certificate loading functionality.
// Methods are safe for concurrent use after initialization.
type KeyLoader struct {
	// CryptoExt provides extended algorithm and certificate support
	// (e.g. brainpool curves). Must be set before concurrent use and
	// not mutated afterwards.
	CryptoExt *cryptoutil.Extensions
}

// NewKeyLoader creates a new KeyLoader instance.
func NewKeyLoader() *KeyLoader {
	return &KeyLoader{}
}

// NewKeyLoaderWithExtensions creates a new KeyLoader with crypto extensions.
func NewKeyLoaderWithExtensions(ext *cryptoutil.Extensions) *KeyLoader {
	return &KeyLoader{CryptoExt: ext}
}

// LoadPrivateKey loads a private key from a PEM file.
// Supports PKCS#8, PKCS#1 (RSA), and SEC1 (EC) formats.
func (kl *KeyLoader) LoadPrivateKey(path string) (crypto.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("key path is empty")
	}

	pemData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
	}

	block, rest := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("key file %s contains extra data after PEM block", path)
	}

	var key crypto.PrivateKey

	// Try parsing in order of likelihood
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format (most common modern format)
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key from %s: %w", path, err)
		}

	case "EC PRIVATE KEY":
		// SEC1/EC format
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key from %s: %w", path, err)
		}

	case "RSA PRIVATE KEY":
		// PKCS#1 RSA format
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key from %s: %w", path, err)
		}

	default:
		return nil, fmt.Errorf("unsupported key type '%s' in %s", block.Type, path)
	}

	return key, nil
}

// LoadCertificateChain loads a certificate chain from a PEM file.
// Returns the certificates and their base64-encoded DER format for x5c.
func (kl *KeyLoader) LoadCertificateChain(path string) ([]*x509.Certificate, []string, error) {
	if path == "" {
		return nil, nil, nil // Empty path is valid, means no chain
	}

	pemData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate chain file %s: %w", path, err)
	}

	var certs []*x509.Certificate
	var x5c []string

	rest := pemData
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM block type '%s' in chain file %s", block.Type, path)
		}

		cert, err := ParseCertificate(block.Bytes, kl.CryptoExt)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse certificate in chain file %s: %w", path, err)
		}

		certs = append(certs, cert)
		x5c = append(x5c, base64.StdEncoding.EncodeToString(block.Bytes))

		rest = remaining
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in chain file %s", path)
	}

	return certs, x5c, nil
}

// LoadKeyMaterial loads a private key based on the provided configuration.
// The config determines whether to load from file, HSM, or try multiple sources.
func (kl *KeyLoader) LoadKeyMaterial(config *KeyConfig) (*KeyMaterial, error) {
	if config == nil {
		return nil, fmt.Errorf("key config is nil")
	}

	// Determine what's enabled
	enableFile := config.EnableFile || (config.PrivateKeyPath != "" && !config.EnableHSM)
	enableHSM := config.EnableHSM || (config.PKCS11 != nil && !config.EnableFile)

	// If neither explicitly enabled, auto-enable based on what's configured
	if !config.EnableFile && !config.EnableHSM {
		enableFile = config.PrivateKeyPath != ""
		enableHSM = config.PKCS11 != nil
	}

	// Determine priority order
	var sources []KeySource
	if len(config.Priority) > 0 {
		sources = config.Priority
	} else {
		// Use explicit Source field or default order
		if enableHSM && enableFile {
			// Both enabled, try HSM first by default
			sources = []KeySource{KeySourceHSM, KeySourceFile}
		} else if enableHSM {
			sources = []KeySource{KeySourceHSM}
		} else if enableFile {
			sources = []KeySource{KeySourceFile}
		} else {
			return nil, fmt.Errorf("no key source configured")
		}
	}

	// Try sources in priority order
	var lastErr error
	for _, source := range sources {
		var km *KeyMaterial
		var err error

		switch source {
		case KeySourceFile:
			if !enableFile || config.PrivateKeyPath == "" {
				continue
			}
			km, err = kl.loadKeyMaterialFromFile(config.PrivateKeyPath, config.ChainPath)

		case KeySourceHSM:
			if !enableHSM || config.PKCS11 == nil {
				continue
			}
			km, err = kl.loadKeyMaterialFromHSMWithConfig(config.PKCS11)

		default:
			return nil, fmt.Errorf("unknown key source: %d", source)
		}

		if err == nil {
			return km, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to load key from any source: %w", lastErr)
	}
	return nil, fmt.Errorf("no valid key source available")
}

// loadKeyMaterialFromFile loads key material from filesystem (internal implementation).
func (kl *KeyLoader) loadKeyMaterialFromFile(keyPath string, chainPath string) (*KeyMaterial, error) {
	key, err := kl.LoadPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}

	// Determine signing method from key type
	signingMethod, err := getSigningMethod(key)
	if err != nil {
		return nil, err
	}

	km := &KeyMaterial{
		PrivateKey:    key,
		SigningMethod: signingMethod,
	}

	if chainPath != "" {
		certs, x5c, err := kl.LoadCertificateChain(chainPath)
		if err != nil {
			return nil, err
		}

		if len(certs) > 0 {
			km.Cert = certs[0] // First cert is the signing cert
			km.Chain = x5c
		}
	}

	return km, nil
}

// ValidateKeyType checks if the private key is of the expected type
func (kl *KeyLoader) ValidateKeyType(key crypto.PrivateKey, expectedType string) error {
	switch expectedType {
	case "RSA":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("expected RSA key, got %T", key)
		}
	case "ECDSA", "EC":
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("expected ECDSA key, got %T", key)
		}
	case "":
		// No validation
	default:
		return fmt.Errorf("unknown key type validation: %s", expectedType)
	}
	return nil
}

// GetKeyAlgorithm returns the algorithm name for a given key
func (kl *KeyLoader) GetKeyAlgorithm(key crypto.PrivateKey) (string, error) {
	method, err := getSigningMethod(key)
	if err != nil {
		return "", err
	}
	return method.Alg(), nil
}

// getSigningMethod determines the appropriate JWT signing method for a key.
// Uses optimized lookup tables for ECDSA and RSA keys.
func getSigningMethod(key crypto.PrivateKey) (jwt.SigningMethod, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		bits := getCurveBits(k.Curve)
		if method := getECSigningMethod(bits); method != nil {
			return method, nil
		}
		return nil, fmt.Errorf("unsupported ECDSA curve: %s (%d bits)", k.Curve.Params().Name, bits)

	case *rsa.PrivateKey:
		return getRSASigningMethod(k.N.BitLen()), nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// getCurveBits normalizes curve identification by bit size
func getCurveBits(curve elliptic.Curve) int {
	switch curve {
	case elliptic.P256():
		return 256
	case elliptic.P384():
		return 384
	case elliptic.P521():
		return 521
	default:
		return curve.Params().BitSize
	}
}

// getRSASigningMethod selects appropriate RSA signing method based on key size
func getRSASigningMethod(bits int) jwt.SigningMethod {
	switch {
	case bits >= 4096:
		return jwt.SigningMethodRS512
	case bits >= 3072:
		return jwt.SigningMethodRS384
	default:
		return jwt.SigningMethodRS256
	}
}

// getECSigningMethod selects appropriate ECDSA signing method based on curve size
func getECSigningMethod(bits int) jwt.SigningMethod {
	switch bits {
	case 256:
		return jwt.SigningMethodES256
	case 384:
		return jwt.SigningMethodES384
	case 521:
		return jwt.SigningMethodES512
	default:
		return nil
	}
}
