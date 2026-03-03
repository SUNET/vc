//go:build vc20

// Package keyresolver provides pluggable key resolution for verifiable credentials
package keyresolver

import (
	"crypto/ecdh"
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

// X25519Resolver extends Resolver with X25519 key agreement key resolution.
// This is used for DIDComm encryption (ECDH-ES key agreement).
type X25519Resolver interface {
	Resolver
	// ResolveX25519 resolves an X25519 key agreement key from a DID or verification method
	ResolveX25519(did string) (*ecdh.PublicKey, error)
}

// ServiceResolver provides service endpoint resolution from DID documents.
type ServiceResolver interface {
	// ResolveService resolves a DIDCommMessaging service endpoint for a DID
	ResolveService(did string) (*DIDCommService, error)
}

// DIDCommService represents a DIDCommMessaging service endpoint from a DID document.
type DIDCommService struct {
	// ID is the service ID
	ID string
	// ServiceEndpoint is the URI for message delivery
	ServiceEndpoint string
	// RoutingKeys are the keys to use for routing/mediation
	RoutingKeys []string
	// Accept lists the accepted media types
	Accept []string
}

// FullResolver combines all resolution capabilities.
type FullResolver interface {
	Resolver
	ECDSAResolver
	X25519Resolver
	ServiceResolver
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

// ResolveX25519 resolves an X25519 key agreement key.
// Local DIDs are resolved locally; all network DIDs delegate to go-trust.
func (s *SmartResolver) ResolveX25519(did string) (*ecdh.PublicKey, error) {
	if CanResolveLocally(did) {
		return s.local.ResolveX25519(did)
	}

	// Delegate to remote resolver (go-trust)
	if x25519Resolver, ok := s.remote.(X25519Resolver); ok {
		return x25519Resolver.ResolveX25519(did)
	}
	return nil, fmt.Errorf("remote resolver does not support X25519")
}

// ResolveService resolves DIDCommMessaging service endpoints.
// Local DIDs (did:peer) can have inline services; network DIDs delegate to go-trust.
func (s *SmartResolver) ResolveService(did string) (*DIDCommService, error) {
	if CanResolveLocally(did) {
		return s.local.ResolveService(did)
	}

	// Delegate to remote resolver (go-trust)
	if serviceResolver, ok := s.remote.(ServiceResolver); ok {
		return serviceResolver.ResolveService(did)
	}
	return nil, fmt.Errorf("remote resolver does not support service resolution")
}

// DID method prefixes
const (
	didPeerPrefix  = "did:peer:"
	didPeer0Prefix = "did:peer:0"
	didPeer2Prefix = "did:peer:2"
)

// LocalResolver resolves keys from local data (multikey, did:key, did:jwk)
type LocalResolver struct{}

// NewLocalResolver creates a resolver that handles local key formats
func NewLocalResolver() *LocalResolver {
	return &LocalResolver{}
}

// CanResolveLocally returns true if the verification method can be resolved
// locally without contacting external services (i.e., self-contained DIDs).
// This includes did:key, did:jwk, and did:peer methods, as well as raw multikey formats.
func CanResolveLocally(verificationMethod string) bool {
	return strings.HasPrefix(verificationMethod, "did:key:") ||
		strings.HasPrefix(verificationMethod, "did:jwk:") ||
		strings.HasPrefix(verificationMethod, didPeerPrefix) ||
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

	// Handle did:peer format
	if strings.HasPrefix(verificationMethod, didPeerPrefix) {
		return l.resolveDidPeerEd25519(verificationMethod)
	}

	// Handle multikey format directly
	if strings.HasPrefix(verificationMethod, "u") || strings.HasPrefix(verificationMethod, "z") {
		return l.decodeMultikey(verificationMethod)
	}

	return nil, fmt.Errorf("unsupported verification method format: %s", verificationMethod)
}

// ResolveECDSA extracts ECDSA keys from local formats (did:key, did:jwk, did:peer, multikey)
func (l *LocalResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	// Handle did:key format
	if strings.HasPrefix(verificationMethod, "did:key:") {
		return l.resolveDidKeyECDSA(verificationMethod)
	}

	// Handle did:jwk format (base64url-encoded JWK)
	if strings.HasPrefix(verificationMethod, "did:jwk:") {
		return l.resolveDidJwkECDSA(verificationMethod)
	}

	// Handle did:peer format
	if strings.HasPrefix(verificationMethod, didPeerPrefix) {
		return l.resolveDidPeerECDSA(verificationMethod)
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

// =============================================================================
// did:peer Resolution
// =============================================================================

// resolveDidPeerEd25519 extracts an Ed25519 public key from a did:peer identifier.
// Supports did:peer:0 (equivalent to did:key) and did:peer:2 (inline keys with purpose codes).
func (l *LocalResolver) resolveDidPeerEd25519(didPeer string) (ed25519.PublicKey, error) {
	// Extract fragment if present (e.g., "did:peer:2.Vz6Mk...#key-1")
	var fragment string
	if idx := strings.Index(didPeer, "#"); idx > 0 {
		fragment = didPeer[idx+1:]
		didPeer = didPeer[:idx]
	}

	// Handle did:peer:0 (equivalent to did:key)
	if strings.HasPrefix(didPeer, didPeer0Prefix) {
		multikey := strings.TrimPrefix(didPeer, didPeer0Prefix)
		return l.decodeMultikey(multikey)
	}

	// Handle did:peer:2 (inline keys with purpose codes)
	if strings.HasPrefix(didPeer, didPeer2Prefix) {
		keys, err := parseDidPeer2Keys(didPeer)
		if err != nil {
			return nil, err
		}

		// If fragment specified, find matching key
		if fragment != "" {
			return l.findEd25519KeyByFragment(keys, fragment)
		}

		// Default: return first authentication (V) key
		for _, key := range keys {
			if key.Purpose == 'V' {
				return l.decodeMultikey(key.Multikey)
			}
		}

		return nil, fmt.Errorf("no authentication key found in did:peer:2: %s", didPeer)
	}

	return nil, fmt.Errorf("unsupported did:peer format: %s", didPeer)
}

// resolveDidPeerECDSA extracts an ECDSA public key from a did:peer identifier.
func (l *LocalResolver) resolveDidPeerECDSA(didPeer string) (*ecdsa.PublicKey, error) {
	// Extract fragment if present
	var fragment string
	if idx := strings.Index(didPeer, "#"); idx > 0 {
		fragment = didPeer[idx+1:]
		didPeer = didPeer[:idx]
	}

	// Handle did:peer:0 (equivalent to did:key)
	if strings.HasPrefix(didPeer, didPeer0Prefix) {
		multikey := strings.TrimPrefix(didPeer, didPeer0Prefix)
		return decodeMultikeyECDSA(multikey)
	}

	// Handle did:peer:2
	if strings.HasPrefix(didPeer, didPeer2Prefix) {
		keys, err := parseDidPeer2Keys(didPeer)
		if err != nil {
			return nil, err
		}

		// If fragment specified, find matching key
		if fragment != "" {
			return findECDSAKeyByFragment(keys, fragment)
		}

		// Default: return first authentication (V) key
		for _, key := range keys {
			if key.Purpose == 'V' {
				return decodeMultikeyECDSA(key.Multikey)
			}
		}

		return nil, fmt.Errorf("no authentication key found in did:peer:2: %s", didPeer)
	}

	return nil, fmt.Errorf("unsupported did:peer format: %s", didPeer)
}

// didPeerKey represents a key extracted from a did:peer:2 identifier.
type didPeerKey struct {
	Purpose  byte   // V=verification, E=encryption, A=assertion, etc.
	Multikey string // The multibase-encoded key
	Index    int    // Position index for fragment generation (key-1, key-2, etc.)
}

// parseDidPeer2Keys extracts all keys from a did:peer:2 identifier.
// Format: did:peer:2.{element}.{element}...
// where element is {purposeCode}{multikey} or S{base64url-json} for services
func parseDidPeer2Keys(didPeer string) ([]didPeerKey, error) {
	// Remove "did:peer:2" prefix
	content := strings.TrimPrefix(didPeer, "did:peer:2")
	if content == "" {
		return nil, fmt.Errorf("empty did:peer:2 identifier")
	}

	// Split by "." (each element starts with ".")
	parts := strings.Split(content, ".")
	var keys []didPeerKey
	keyIndex := 1

	for _, part := range parts {
		if len(part) == 0 {
			continue
		}

		purpose := part[0]
		data := part[1:]

		// Skip service entries (S)
		if purpose == 'S' {
			continue
		}

		// Valid key purpose codes: V, E, A, I, D
		if purpose == 'V' || purpose == 'E' || purpose == 'A' || purpose == 'I' || purpose == 'D' {
			keys = append(keys, didPeerKey{
				Purpose:  purpose,
				Multikey: data,
				Index:    keyIndex,
			})
			keyIndex++
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found in did:peer:2: %s", didPeer)
	}

	return keys, nil
}

// findEd25519KeyByFragment finds an Ed25519 key by its fragment identifier (e.g., "key-1").
func (l *LocalResolver) findEd25519KeyByFragment(keys []didPeerKey, fragment string) (ed25519.PublicKey, error) {
	// Parse fragment as "key-N"
	var keyIndex int
	if _, err := fmt.Sscanf(fragment, "key-%d", &keyIndex); err != nil {
		return nil, fmt.Errorf("invalid key fragment format: %s", fragment)
	}

	for _, key := range keys {
		if key.Index == keyIndex {
			return l.decodeMultikey(key.Multikey)
		}
	}

	return nil, fmt.Errorf("key not found: #%s", fragment)
}

// findECDSAKeyByFragment finds an ECDSA key by its fragment identifier.
func findECDSAKeyByFragment(keys []didPeerKey, fragment string) (*ecdsa.PublicKey, error) {
	var keyIndex int
	if _, err := fmt.Sscanf(fragment, "key-%d", &keyIndex); err != nil {
		return nil, fmt.Errorf("invalid key fragment format: %s", fragment)
	}

	for _, key := range keys {
		if key.Index == keyIndex {
			return decodeMultikeyECDSA(key.Multikey)
		}
	}

	return nil, fmt.Errorf("key not found: #%s", fragment)
}

// ResolveX25519 resolves an X25519 key agreement key from a local DID.
// For did:peer:2, this extracts the E (encryption) purpose key.
// For did:key with Ed25519, this converts to X25519.
func (l *LocalResolver) ResolveX25519(did string) (*ecdh.PublicKey, error) {
	// Extract fragment if present
	baseDID := did
	if idx := strings.Index(did, "#"); idx > 0 {
		baseDID = did[:idx]
	}

	// Handle did:peer:2 - look for E (encryption) purpose keys
	if strings.HasPrefix(baseDID, didPeer2Prefix) {
		keys, err := parseDidPeer2Keys(baseDID)
		if err != nil {
			return nil, err
		}

		// Find encryption (E) purpose key
		for _, key := range keys {
			if key.Purpose == 'E' {
				return decodeMultikeyX25519(key.Multikey)
			}
		}
		// Fallback: try to convert first V key from Ed25519 to X25519
		for _, key := range keys {
			if key.Purpose == 'V' {
				edKey, err := l.decodeMultikey(key.Multikey)
				if err == nil {
					return ed25519ToX25519(edKey)
				}
			}
		}
		return nil, fmt.Errorf("no key agreement key found in did:peer:2: %s", baseDID)
	}

	// Handle did:peer:0 and did:key - convert Ed25519 to X25519
	if strings.HasPrefix(baseDID, didPeer0Prefix) {
		multikey := strings.TrimPrefix(baseDID, didPeer0Prefix)
		edKey, err := l.decodeMultikey(multikey)
		if err == nil {
			return ed25519ToX25519(edKey)
		}
		// Try as direct X25519
		return decodeMultikeyX25519(multikey)
	}

	if strings.HasPrefix(baseDID, "did:key:") {
		multikey := strings.TrimPrefix(baseDID, "did:key:")
		edKey, err := l.decodeMultikey(multikey)
		if err == nil {
			return ed25519ToX25519(edKey)
		}
		// Try as direct X25519
		return decodeMultikeyX25519(multikey)
	}

	// Handle did:jwk
	if strings.HasPrefix(baseDID, "did:jwk:") {
		jwk, err := l.parseDidJwk(baseDID)
		if err != nil {
			return nil, err
		}
		return JWKToX25519(jwk)
	}

	return nil, fmt.Errorf("cannot resolve X25519 key from: %s", did)
}

// ResolveService resolves a DIDCommMessaging service from a local DID.
// For did:peer:2, this extracts inline service endpoints (S purpose).
func (l *LocalResolver) ResolveService(did string) (*DIDCommService, error) {
	// Extract base DID without fragment
	baseDID := did
	if idx := strings.Index(did, "#"); idx > 0 {
		baseDID = did[:idx]
	}

	// Only did:peer:2 has inline services
	if !strings.HasPrefix(baseDID, didPeer2Prefix) {
		return nil, fmt.Errorf("service resolution not supported for: %s (only did:peer:2 has inline services)", did)
	}

	// Parse service entries from did:peer:2
	return parseDidPeer2Service(baseDID)
}

// parseDidPeer2Service extracts the first DIDCommMessaging service from a did:peer:2 identifier.
func parseDidPeer2Service(didPeer string) (*DIDCommService, error) {
	// Remove "did:peer:2" prefix
	content := strings.TrimPrefix(didPeer, "did:peer:2")
	if content == "" {
		return nil, fmt.Errorf("empty did:peer:2 identifier")
	}

	// Split by "." (each element starts with ".")
	parts := strings.Split(content, ".")

	for _, part := range parts {
		if len(part) == 0 {
			continue
		}

		purpose := part[0]
		data := part[1:]

		// S = Service entry (base64url-encoded JSON)
		if purpose == 'S' {
			return parseServiceEntry(didPeer, data)
		}
	}

	return nil, fmt.Errorf("no service entry found in did:peer:2: %s", didPeer)
}

// parseServiceEntry decodes a base64url-encoded service entry from did:peer:2.
func parseServiceEntry(did, encodedService string) (*DIDCommService, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encodedService)
	if err != nil {
		return nil, fmt.Errorf("failed to decode service entry: %w", err)
	}

	var svc struct {
		Type            string   `json:"t"`
		ServiceEndpoint string   `json:"s"`
		RoutingKeys     []string `json:"r,omitempty"`
		Accept          []string `json:"a,omitempty"`
	}
	if err := json.Unmarshal(decoded, &svc); err != nil {
		return nil, fmt.Errorf("failed to parse service entry: %w", err)
	}

	// Check for DIDCommMessaging service type
	if svc.Type != "dm" && svc.Type != "DIDCommMessaging" {
		return nil, fmt.Errorf("not a DIDCommMessaging service: %s", svc.Type)
	}

	return &DIDCommService{
		ID:              did + "#service-1",
		ServiceEndpoint: svc.ServiceEndpoint,
		RoutingKeys:     svc.RoutingKeys,
		Accept:          svc.Accept,
	}, nil
}

// ed25519ToX25519 converts an Ed25519 public key to X25519 for key agreement.
func ed25519ToX25519(edPub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, want %d", len(edPub), ed25519.PublicKeySize)
	}

	// Import edwards25519 for the conversion
	// The conversion uses the birational equivalence between Ed25519 and X25519
	// u = (1 + y) / (1 - y) where y is the Edwards y-coordinate
	//
	// For now, we use a simplified approach that works for most keys
	// by interpreting the Ed25519 key bytes directly
	// A full implementation would use filippo.io/edwards25519
	
	// This is a placeholder - the actual conversion should use proper curve math
	// For production, import filippo.io/edwards25519 and use BytesMontgomery()
	return nil, fmt.Errorf("Ed25519 to X25519 conversion requires curve arithmetic - use native X25519 keys")
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
