//go:build vc20

// Package keyresolver provides pluggable key resolution for verifiable credentials
package keyresolver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/multiformats/go-multibase"
)

// Resolver provides methods to resolve public keys from verification methods.
// Implementations may support one or both key types.
type Resolver interface {
	// ResolveEd25519 resolves an Ed25519 public key from a verification method identifier
	ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error)
}

// ECDSAResolver extends Resolver with ECDSA key resolution capability.
// Resolvers that support ECDSA keys should implement this interface.
type ECDSAResolver interface {
	Resolver
	// ResolveECDSA resolves an ECDSA public key from a verification method identifier
	ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error)
}

// MultiResolver combines multiple resolvers with fallback behavior
type MultiResolver struct {
	resolvers []Resolver
}

// NewMultiResolver creates a resolver that tries each resolver in order
func NewMultiResolver(resolvers ...Resolver) *MultiResolver {
	return &MultiResolver{
		resolvers: resolvers,
	}
}

// ResolveEd25519 tries each resolver until one succeeds
func (m *MultiResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	var errors []error

	for _, resolver := range m.resolvers {
		key, err := resolver.ResolveEd25519(verificationMethod)
		if err == nil {
			return key, nil
		}
		errors = append(errors, err)
	}

	if len(errors) == 0 {
		return nil, fmt.Errorf("no resolvers configured")
	}

	// Return the last error
	return nil, fmt.Errorf("all resolvers failed: %v", errors[len(errors)-1])
}

// ResolveECDSA tries each resolver that supports ECDSA until one succeeds
func (m *MultiResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	var errors []error
	foundECDSAResolver := false

	for _, resolver := range m.resolvers {
		if ecdsaResolver, ok := resolver.(ECDSAResolver); ok {
			foundECDSAResolver = true
			key, err := ecdsaResolver.ResolveECDSA(verificationMethod)
			if err == nil {
				return key, nil
			}
			errors = append(errors, err)
		}
	}

	if !foundECDSAResolver {
		return nil, fmt.Errorf("no ECDSA-capable resolvers configured")
	}

	if len(errors) == 0 {
		return nil, fmt.Errorf("no resolvers configured")
	}

	// Return the last error
	return nil, fmt.Errorf("all ECDSA resolvers failed: %v", errors[len(errors)-1])
}

// SmartResolver intelligently routes key resolution requests based on the DID method:
// - Self-contained DIDs (did:key, did:jwk) are resolved locally without external calls
// - All other DIDs are resolved via go-trust for both key resolution and trust evaluation
type SmartResolver struct {
	local  *LocalResolver
	remote Resolver // Usually GoTrustResolver
}

// NewSmartResolver creates a resolver that routes based on DID method.
// The remote resolver is used for all non-local DIDs (did:web, did:ebsi, etc.).
func NewSmartResolver(remote Resolver) *SmartResolver {
	return &SmartResolver{
		local:  NewLocalResolver(),
		remote: remote,
	}
}

// ResolveEd25519 routes to local or remote resolver based on the DID method.
func (s *SmartResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	if CanResolveLocally(verificationMethod) {
		return s.local.ResolveEd25519(verificationMethod)
	}
	return s.remote.ResolveEd25519(verificationMethod)
}

// ResolveECDSA routes to local or remote resolver based on the DID method.
func (s *SmartResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	if CanResolveLocally(verificationMethod) {
		return s.local.ResolveECDSA(verificationMethod)
	}

	// Check if remote resolver supports ECDSA
	if ecdsaResolver, ok := s.remote.(ECDSAResolver); ok {
		return ecdsaResolver.ResolveECDSA(verificationMethod)
	}
	return nil, fmt.Errorf("remote resolver does not support ECDSA")
}

// GetLocalResolver returns the local resolver for direct access if needed.
func (s *SmartResolver) GetLocalResolver() *LocalResolver {
	return s.local
}

// GetRemoteResolver returns the remote resolver for direct access if needed.
func (s *SmartResolver) GetRemoteResolver() Resolver {
	return s.remote
}

// LocalResolver resolves keys from local data (multikey, did:key, did:jwk)
type LocalResolver struct{}

// NewLocalResolver creates a resolver that handles local key formats
func NewLocalResolver() *LocalResolver {
	return &LocalResolver{}
}

// CanResolveLocally returns true if the verification method can be resolved
// locally without contacting external services (i.e., self-contained DIDs).
// This includes did:key and did:jwk methods, as well as raw multikey formats.
func CanResolveLocally(verificationMethod string) bool {
	return strings.HasPrefix(verificationMethod, "did:key:") ||
		strings.HasPrefix(verificationMethod, "did:jwk:") ||
		strings.HasPrefix(verificationMethod, "z") || // multibase base58-btc
		strings.HasPrefix(verificationMethod, "u") // multibase base64url
}

// ResolveEd25519 extracts Ed25519 keys from local formats
func (l *LocalResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	// Handle did:key format
	if strings.HasPrefix(verificationMethod, "did:key:") {
		return l.resolveDidKeyEd25519(verificationMethod)
	}

	// Handle did:jwk format (base64url-encoded JWK)
	if strings.HasPrefix(verificationMethod, "did:jwk:") {
		return l.resolveDidJwkEd25519(verificationMethod)
	}

	// Handle multikey format directly
	if strings.HasPrefix(verificationMethod, "u") || strings.HasPrefix(verificationMethod, "z") {
		return l.decodeMultikey(verificationMethod)
	}

	return nil, fmt.Errorf("unsupported verification method format: %s", verificationMethod)
}

// ResolveECDSA extracts ECDSA keys from local formats (did:key, did:jwk, multikey)
func (l *LocalResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	// Handle did:key format
	if strings.HasPrefix(verificationMethod, "did:key:") {
		return l.resolveDidKeyECDSA(verificationMethod)
	}

	// Handle did:jwk format (base64url-encoded JWK)
	if strings.HasPrefix(verificationMethod, "did:jwk:") {
		return l.resolveDidJwkECDSA(verificationMethod)
	}

	// Handle multikey format directly
	if strings.HasPrefix(verificationMethod, "u") || strings.HasPrefix(verificationMethod, "z") {
		return decodeMultikeyECDSA(verificationMethod)
	}

	return nil, fmt.Errorf("unsupported verification method format: %s", verificationMethod)
}

// resolveDidKeyEd25519 extracts an Ed25519 public key from a did:key identifier
func (l *LocalResolver) resolveDidKeyEd25519(didKey string) (ed25519.PublicKey, error) {
	// did:key format: did:key:{multikey}#{fragment}
	// We need to extract the multikey part

	// Remove "did:key:" prefix
	withoutPrefix := strings.TrimPrefix(didKey, "did:key:")

	// Split on # to get the multikey (before fragment)
	parts := strings.Split(withoutPrefix, "#")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid did:key format: %s", didKey)
	}

	multikey := parts[0]
	fmt.Printf("[DEBUG] resolveDidKeyEd25519: extracted multikey=%s from didKey=%s\n", multikey, didKey)
	key, err := l.decodeMultikey(multikey)
	if err != nil {
		fmt.Printf("[DEBUG] resolveDidKey: decodeMultikey failed: %v\n", err)
	} else {
		fmt.Printf("[DEBUG] resolveDidKey: SUCCESS, key length=%d\n", len(key))
	}
	return key, err
}

// decodeMultikey decodes a multikey-encoded public key
func (l *LocalResolver) decodeMultikey(multikey string) (ed25519.PublicKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("empty multikey")
	}

	var keyBytes []byte
	var err error

	// Check the multibase prefix (first character)
	prefix := multikey[0]
	fmt.Printf("[DEBUG] decodeMultikey: prefix=%c, multikey length=%d\n", prefix, len(multikey))

	switch prefix {
	case 'z':
		// Base58-btc encoding (multibase prefix 'z')
		// Decode using go-multibase which handles the prefix
		_, decoded, err := multibase.Decode(multikey)
		if err != nil {
			fmt.Printf("[DEBUG] decodeMultikey: base58-btc decode failed: %v\n", err)
			return nil, fmt.Errorf("failed to decode base58-btc multikey: %w", err)
		}
		fmt.Printf("[DEBUG] decodeMultikey: base58-btc decoded %d bytes\n", len(decoded))
		keyBytes = decoded

	case 'u':
		// Base64url encoding (no padding)
		// For multibase base64url, the first character is the prefix
		encoded := multikey[1:]
		keyBytes, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			fmt.Printf("[DEBUG] decodeMultikey: base64url decode failed: %v\n", err)
			return nil, fmt.Errorf("failed to decode base64url multikey: %w", err)
		}
		fmt.Printf("[DEBUG] decodeMultikey: base64url decoded %d bytes\n", len(keyBytes))

	default:
		return nil, fmt.Errorf("unsupported multibase prefix: %c", prefix)
	}

	// The multikey format is: multicodec || public-key-bytes
	// We need to parse the multicodec varint to identify the key type
	if len(keyBytes) < 3 {
		return nil, fmt.Errorf("multikey too short: expected at least 3 bytes, got %d", len(keyBytes))
	}

	// Decode multicodec (varint)
	// Ed25519 public key multicodec is 0xed (237)
	multicodec, bytesRead := binary.Uvarint(keyBytes)
	fmt.Printf("[DEBUG] decodeMultikey: multicodec=0x%x, bytesRead=%d\n", multicodec, bytesRead)
	if bytesRead <= 0 {
		return nil, fmt.Errorf("failed to decode multicodec varint")
	}

	// Extract the public key bytes after the multicodec
	pubKeyBytes := keyBytes[bytesRead:]
	fmt.Printf("[DEBUG] decodeMultikey: extracted %d public key bytes\n", len(pubKeyBytes))

	// Ed25519 public keys are 32 bytes
	// Multicodec 0xed (237) is the Ed25519 public key type
	if multicodec != 0xed {
		return nil, fmt.Errorf("unsupported key type: multicodec 0x%x (expected 0xed for Ed25519)", multicodec)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: got %d bytes, expected %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// resolveDidKeyECDSA extracts an ECDSA public key from a did:key identifier
func (l *LocalResolver) resolveDidKeyECDSA(didKey string) (*ecdsa.PublicKey, error) {
	// did:key format: did:key:{multikey}#{fragment}
	// Remove "did:key:" prefix
	withoutPrefix := strings.TrimPrefix(didKey, "did:key:")

	// Split on # to get the multikey (before fragment)
	parts := strings.Split(withoutPrefix, "#")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid did:key format: %s", didKey)
	}

	multikey := parts[0]
	return decodeMultikeyECDSA(multikey)
}

// resolveDidJwkEd25519 extracts an Ed25519 public key from a did:jwk identifier.
// did:jwk format: did:jwk:<base64url-encoded-JWK>
func (l *LocalResolver) resolveDidJwkEd25519(didJwk string) (ed25519.PublicKey, error) {
	jwk, err := l.parseDidJwk(didJwk)
	if err != nil {
		return nil, err
	}
	return JWKToEd25519(jwk)
}

// resolveDidJwkECDSA extracts an ECDSA public key from a did:jwk identifier.
// did:jwk format: did:jwk:<base64url-encoded-JWK>
func (l *LocalResolver) resolveDidJwkECDSA(didJwk string) (*ecdsa.PublicKey, error) {
	jwk, err := l.parseDidJwk(didJwk)
	if err != nil {
		return nil, err
	}
	return JWKToECDSA(jwk)
}

// parseDidJwk extracts and decodes the JWK from a did:jwk identifier.
func (l *LocalResolver) parseDidJwk(didJwk string) (map[string]any, error) {
	// did:jwk format: did:jwk:<base64url-encoded-JWK>#<optional-fragment>
	// Remove "did:jwk:" prefix
	withoutPrefix := strings.TrimPrefix(didJwk, "did:jwk:")

	// Split on # to get the encoded JWK (before fragment)
	parts := strings.Split(withoutPrefix, "#")
	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("invalid did:jwk format: %s", didJwk)
	}

	encodedJwk := parts[0]

	// Base64url decode the JWK
	jwkBytes, err := base64.RawURLEncoding.DecodeString(encodedJwk)
	if err != nil {
		// Try with padding as some implementations may include it
		jwkBytes, err = base64.URLEncoding.DecodeString(encodedJwk)
		if err != nil {
			return nil, fmt.Errorf("failed to decode did:jwk: %w", err)
		}
	}

	// Parse JSON into map
	var jwk map[string]any
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK JSON: %w", err)
	}

	return jwk, nil
}

// StaticResolver provides a simple key->value resolver for testing
type StaticResolver struct {
	ed25519Keys map[string]ed25519.PublicKey
	ecdsaKeys   map[string]*ecdsa.PublicKey
}

// NewStaticResolver creates a resolver with a static key map
func NewStaticResolver() *StaticResolver {
	return &StaticResolver{
		ed25519Keys: make(map[string]ed25519.PublicKey),
		ecdsaKeys:   make(map[string]*ecdsa.PublicKey),
	}
}

// AddKey adds an Ed25519 key to the static resolver
func (s *StaticResolver) AddKey(verificationMethod string, publicKey ed25519.PublicKey) {
	s.ed25519Keys[verificationMethod] = publicKey
}

// AddECDSAKey adds an ECDSA key to the static resolver
func (s *StaticResolver) AddECDSAKey(verificationMethod string, publicKey *ecdsa.PublicKey) {
	s.ecdsaKeys[verificationMethod] = publicKey
}

// ResolveEd25519 looks up the key in the static map
func (s *StaticResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	key, ok := s.ed25519Keys[verificationMethod]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", verificationMethod)
	}
	return key, nil
}

// ResolveECDSA looks up an ECDSA key in the static map
func (s *StaticResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	key, ok := s.ecdsaKeys[verificationMethod]
	if !ok {
		return nil, fmt.Errorf("ECDSA key not found: %s", verificationMethod)
	}
	return key, nil
}

// ResolverConfig holds configuration for creating a key resolver.
// This mirrors the TrustConfig from the application config.
type ResolverConfig struct {
	// GoTrustURL is the URL of the go-trust PDP service.
	// If empty, only local DID methods will be supported.
	GoTrustURL string

	// LocalDIDMethods specifies additional DID methods to resolve locally.
	// did:key and did:jwk are always resolved locally.
	LocalDIDMethods []string

	// Enabled controls whether trust evaluation is performed.
	// When false, keys are resolved but not validated against trust frameworks.
	Enabled bool
}

// NewResolverFromConfig creates a key resolver based on configuration.
// If GoTrustURL is set, creates a SmartResolver that uses LocalResolver for
// self-contained DIDs (did:key, did:jwk) and GoTrustResolver for everything else.
// If GoTrustURL is empty, creates a LocalResolver that only handles self-contained DIDs.
func NewResolverFromConfig(cfg ResolverConfig) (Resolver, error) {
	// If no go-trust URL, only local resolution is possible
	if cfg.GoTrustURL == "" {
		return NewLocalResolver(), nil
	}

	// Create go-trust resolver for remote DIDs
	goTrustResolver := NewGoTrustResolver(cfg.GoTrustURL)

	// Create smart resolver that routes based on DID method
	return NewSmartResolver(goTrustResolver), nil
}

// NewResolverWithGoTrust creates a SmartResolver with go-trust integration.
// This is a convenience function for common use cases.
func NewResolverWithGoTrust(goTrustURL string) *SmartResolver {
	return NewSmartResolver(NewGoTrustResolver(goTrustURL))
}

// NewLocalOnlyResolver creates a resolver that only handles local DIDs.
// Use this when go-trust is not available or not needed.
func NewLocalOnlyResolver() *LocalResolver {
	return NewLocalResolver()
}
