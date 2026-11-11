// Package did provides a generic DID resolution framework and implementspackage did

// various DID method resolvers.
//
// This package provides:
// - A DIDResolver interface for pluggable DID method implementations
// - A GenericDIDRegistry that wraps DID resolvers in a TrustRegistry interface
// - Built-in support for the did:key method
//
// The implementation follows the W3C DID Core specification:
// https://www.w3.org/TR/did-core/
package did

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// DIDDocument represents a W3C DID Document.
// See https://www.w3.org/TR/did-core/#did-documents
type DIDDocument struct {
	Context              interface{}          `json:"@context,omitempty"`
	ID                   string               `json:"id"`
	Controller           interface{}          `json:"controller,omitempty"`
	VerificationMethod   []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication       interface{}          `json:"authentication,omitempty"`
	AssertionMethod      interface{}          `json:"assertionMethod,omitempty"`
	KeyAgreement         interface{}          `json:"keyAgreement,omitempty"`
	CapabilityInvocation interface{}          `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation interface{}          `json:"capabilityDelegation,omitempty"`
	Service              interface{}          `json:"service,omitempty"`
}

// VerificationMethod represents a verification method in a DID document.
type VerificationMethod struct {
	ID                 string                 `json:"id"`
	Type               string                 `json:"type"`
	Controller         string                 `json:"controller"`
	PublicKeyJwk       map[string]interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string                 `json:"publicKeyMultibase,omitempty"`
}

// DIDResolver defines the interface for resolving DIDs to DID documents.
type DIDResolver interface {
	// Resolve resolves a DID to a DID document.
	Resolve(ctx context.Context, did string) (*DIDDocument, error)

	// Method returns the DID method this resolver handles (e.g., "key", "web").
	Method() string
}

// GenericDIDRegistry provides a TrustRegistry implementation that uses
// pluggable DID resolvers to support multiple DID methods.
type GenericDIDRegistry struct {
	resolvers   map[string]DIDResolver
	mu          sync.RWMutex
	description string
}

// GenericDIDRegistryConfig holds configuration for the GenericDIDRegistry.
type GenericDIDRegistryConfig struct {
	Description string `json:"description,omitempty"`
}

// NewGenericDIDRegistry creates a new GenericDIDRegistry.
func NewGenericDIDRegistry(config GenericDIDRegistryConfig) *GenericDIDRegistry {
	description := config.Description
	if description == "" {
		description = "Generic DID Resolution Registry"
	}

	return &GenericDIDRegistry{
		resolvers:   make(map[string]DIDResolver),
		description: description,
	}
}

// RegisterResolver registers a DID resolver for a specific DID method.
func (r *GenericDIDRegistry) RegisterResolver(resolver DIDResolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolvers[resolver.Method()] = resolver
}

// Evaluate implements TrustRegistry.Evaluate by resolving DIDs and validating key bindings.
func (r *GenericDIDRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	startTime := time.Now()

	// Parse the DID to extract the method
	method, err := extractDIDMethod(req.Subject.ID)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("invalid DID format: %v", err),
				},
			},
		}, nil
	}

	// Find the appropriate resolver
	r.mu.RLock()
	resolver, exists := r.resolvers[method]
	r.mu.RUnlock()

	if !exists {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":             fmt.Sprintf("no resolver registered for DID method: %s", method),
					"supported_methods": r.getSupportedMethods(),
				},
			},
		}, nil
	}

	// Resolve the DID document
	didDoc, err := resolver.Resolve(ctx, req.Subject.ID)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         fmt.Sprintf("failed to resolve DID: %v", err),
					"resolution_ms": time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	// Check policy constraints from request context (set by policy mapper)
	if denial := checkDIDPolicyConstraints(req, didDoc, startTime); denial != nil {
		return denial, nil
	}

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"did":                  didDoc.ID,
					"resolution_only":      true,
					"resolution_ms":        time.Since(startTime).Milliseconds(),
					"verification_methods": len(didDoc.VerificationMethod),
				},
				TrustMetadata: didDocumentToTrustMetadata(didDoc),
			},
		}, nil
	}

	// For full evaluation, validate the key binding
	matched, matchedMethod, err := verifyKeyBinding(req, didDoc)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         err.Error(),
					"resolution_ms": time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	if !matched {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":                "no matching verification method found in DID document",
					"verification_methods": len(didDoc.VerificationMethod),
					"resolution_ms":        time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"did":                  didDoc.ID,
				"verification_method":  matchedMethod.ID,
				"key_type":             matchedMethod.Type,
				"resolution_ms":        time.Since(startTime).Milliseconds(),
				"verification_methods": len(didDoc.VerificationMethod),
			},
			TrustMetadata: didDocumentToTrustMetadata(didDoc),
		},
	}
	registry.AddDIDVerifierID(resp, req, didDoc.ID)
	return resp, nil
}

// checkDIDPolicyConstraints validates DID policy constraints from request context.
// These constraints are injected by the policy mapper based on role (action.name).
func checkDIDPolicyConstraints(req *authzen.EvaluationRequest, didDoc *DIDDocument, startTime time.Time) *authzen.EvaluationResponse {
	if req.Context == nil {
		return nil
	}

	// Check allowed_domains: restrict DIDs to specific domains
	if allowedDomains := extractStringSliceFromCtx(req.Context, "allowed_domains"); len(allowedDomains) > 0 {
		domain := extractDomainFromDID(req.Subject.ID)
		if domain != "" && !domainMatchesPatterns(domain, allowedDomains) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":           "DID domain not in allowed domains for this role",
						"domain":          domain,
						"allowed_domains": allowedDomains,
						"resolution_ms":   time.Since(startTime).Milliseconds(),
					},
				},
			}
		}
	}

	// Check required_verification_methods: the DID document must contain every
	// listed verificationMethod[].type (exact match, like required_services).
	if resolverVMDenial := registry.DenyMissingVerificationMethods(req.Context, didDoc.VerificationMethod, verificationMethodType, startTime); resolverVMDenial != nil {
		return resolverVMDenial
	}

	// Check required_services: DID document must have specific service types
	if requiredServices := extractStringSliceFromCtx(req.Context, "required_services"); len(requiredServices) > 0 {
		if !didDocServicesMatch(didDoc.Service, requiredServices) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":             "DID document missing required services for this role",
						"required_services": requiredServices,
						"resolution_ms":     time.Since(startTime).Milliseconds(),
					},
				},
			}
		}
	}

	return nil
}

// extractStringSliceFromCtx extracts a []string from a context map value.
func extractStringSliceFromCtx(ctx map[string]interface{}, key string) []string {
	v, ok := ctx[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// extractDomainFromDID extracts a domain from a DID if the method encodes one.
// Currently supports did:web and did:webvh formats.
func extractDomainFromDID(did string) string {
	if strings.HasPrefix(did, "did:web:") {
		rest := strings.TrimPrefix(did, "did:web:")
		parts := strings.SplitN(rest, ":", 2)
		domain := parts[0]
		domain = strings.ReplaceAll(domain, "%3A", ":")
		domain = strings.ReplaceAll(domain, "%3a", ":")
		return domain
	}
	if strings.HasPrefix(did, "did:webvh:") {
		rest := strings.TrimPrefix(did, "did:webvh:")
		parts := strings.SplitN(rest, ":", 3)
		if len(parts) >= 2 {
			domain := parts[1]
			domain = strings.ReplaceAll(domain, "%3A", ":")
			domain = strings.ReplaceAll(domain, "%3a", ":")
			return domain
		}
	}
	// For other DID methods (e.g., did:key), no domain to extract
	return ""
}

// domainMatchesPatterns checks if a domain matches any of the allowed domain patterns.
// Supports wildcards: "*.example.com" matches "sub.example.com".
func domainMatchesPatterns(domain string, allowedDomains []string) bool {
	for _, allowed := range allowedDomains {
		if allowed == domain {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) && domain != suffix[1:] {
				return true
			}
		}
	}
	return false
}

// didDocServicesMatch checks if the DID document services include all required service types.
func didDocServicesMatch(service interface{}, requiredTypes []string) bool {
	if service == nil {
		return false
	}

	services, ok := service.([]interface{})
	if !ok {
		return false
	}

	presentTypes := make(map[string]bool)
	for _, svc := range services {
		if svcMap, ok := svc.(map[string]interface{}); ok {
			if svcType, ok := svcMap["type"].(string); ok {
				presentTypes[svcType] = true
			}
		}
	}

	for _, required := range requiredTypes {
		if !presentTypes[required] {
			return false
		}
	}
	return true
}

// SupportedResourceTypes returns the resource types this registry can handle.
func (r *GenericDIDRegistry) SupportedResourceTypes() []string {
	// "kid" accompanies a key identifier rather than key material, which is
	// how a DID-based client_id names the method that signed a request.
	return []string{"jwk", "kid"}
}

// SupportsResolutionOnly returns true as DID resolution supports resolution-only requests.
func (r *GenericDIDRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *GenericDIDRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:         "generic-did-registry",
		Type:         "did",
		Description:  r.description,
		Version:      "1.0.0",
		TrustAnchors: r.getSupportedMethods(),
	}
}

// Healthy returns true if the registry is operational.
func (r *GenericDIDRegistry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.resolvers) > 0
}

// Refresh is a no-op for DID resolution.
func (r *GenericDIDRegistry) Refresh(ctx context.Context) error {
	return nil
}

// getSupportedMethods returns the list of supported DID methods.
func (r *GenericDIDRegistry) getSupportedMethods() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	methods := make([]string, 0, len(r.resolvers))
	for method := range r.resolvers {
		methods = append(methods, "did:"+method)
	}
	return methods
}

// extractDIDMethod extracts the DID method from a DID string.
// For example, "did:web:example.com" returns "web".
func extractDIDMethod(did string) (string, error) {
	if !strings.HasPrefix(did, "did:") {
		return "", fmt.Errorf("not a valid DID: must start with 'did:'")
	}

	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 {
		return "", fmt.Errorf("not a valid DID: missing method-specific identifier")
	}

	return parts[1], nil
}

// didDocumentToTrustMetadata converts a DIDDocument to the trust_metadata format.
func didDocumentToTrustMetadata(didDoc *DIDDocument) map[string]interface{} {
	trustMeta := map[string]interface{}{
		"@context": didDoc.Context,
		"id":       didDoc.ID,
	}

	if didDoc.Controller != nil {
		trustMeta["controller"] = didDoc.Controller
	}

	if len(didDoc.VerificationMethod) > 0 {
		verificationMethods := make([]map[string]interface{}, len(didDoc.VerificationMethod))
		for i, vm := range didDoc.VerificationMethod {
			method := map[string]interface{}{
				"id":         vm.ID,
				"type":       vm.Type,
				"controller": vm.Controller,
			}
			if vm.PublicKeyJwk != nil {
				method["publicKeyJwk"] = vm.PublicKeyJwk
			}
			if vm.PublicKeyMultibase != "" {
				method["publicKeyMultibase"] = vm.PublicKeyMultibase
			}
			verificationMethods[i] = method
		}
		trustMeta["verificationMethod"] = verificationMethods
	}

	if didDoc.Authentication != nil {
		trustMeta["authentication"] = didDoc.Authentication
	}
	if didDoc.AssertionMethod != nil {
		trustMeta["assertionMethod"] = didDoc.AssertionMethod
	}
	if didDoc.KeyAgreement != nil {
		trustMeta["keyAgreement"] = didDoc.KeyAgreement
	}
	if didDoc.CapabilityInvocation != nil {
		trustMeta["capabilityInvocation"] = didDoc.CapabilityInvocation
	}
	if didDoc.CapabilityDelegation != nil {
		trustMeta["capabilityDelegation"] = didDoc.CapabilityDelegation
	}
	if didDoc.Service != nil {
		trustMeta["service"] = didDoc.Service
	}

	return trustMeta
}

// verifyKeyBinding verifies that the request key matches one of the DID document's verification methods.
func verifyKeyBinding(req *authzen.EvaluationRequest, didDoc *DIDDocument) (bool, *VerificationMethod, error) {
	if len(req.Resource.Key) == 0 {
		return false, nil, fmt.Errorf("resource.key must not be empty")
	}

	switch key := req.Resource.Key[0].(type) {
	case map[string]interface{}:
		for i := range didDoc.VerificationMethod {
			vm := &didDoc.VerificationMethod[i]
			if vm.PublicKeyJwk != nil && registry.JWKsMatch(key, vm.PublicKeyJwk) {
				return true, vm, nil
			}
		}
		return false, nil, nil

	case string:
		// A `kid` names a verification method instead of carrying key
		// material, which is the normal shape for a DID-based client_id: the
		// signer points at the method in its own document rather than
		// inlining a key the verifier could already resolve.
		//
		// Like the JWK branch above, this establishes membership -- that the
		// document really declares the method the signer named -- and not
		// that any signature is valid. Verifying the signature against the
		// resolved key remains the caller's job in both branches.
		if vm := findVerificationMethodByKid(didDoc, key); vm != nil {
			return true, vm, nil
		}
		return false, nil, nil

	default:
		return false, nil, fmt.Errorf("resource.key[0] must be a JWK object or a key identifier")
	}
}

// findVerificationMethodByKid resolves a `kid` against a DID document's
// verification methods, accepting the three spellings seen in practice: the
// absolute DID URL, a relative fragment such as "#0", and the bare DID when
// the document leaves no ambiguity about which method is meant.
func findVerificationMethodByKid(didDoc *DIDDocument, kid string) *VerificationMethod {
	if kid == "" {
		return nil
	}

	for i := range didDoc.VerificationMethod {
		if didDoc.VerificationMethod[i].ID == kid {
			return &didDoc.VerificationMethod[i]
		}
	}

	if strings.HasPrefix(kid, "#") {
		// A relative reference resolves against the document's own DID. It is
		// resolved and compared whole rather than matched as a suffix: a
		// document may embed a method belonging to another controller, and
		// "#0" must not bind did:other:xyz#0 just because the fragments agree.
		absolute := didDoc.ID + kid
		for i := range didDoc.VerificationMethod {
			if didDoc.VerificationMethod[i].ID == absolute {
				return &didDoc.VerificationMethod[i]
			}
		}
		return nil
	}

	// Some signers set `kid` to the DID itself. That only names a method when
	// the document declares exactly one, so it is accepted only then rather
	// than guessing at the first of several.
	if kid == didDoc.ID && len(didDoc.VerificationMethod) == 1 {
		return &didDoc.VerificationMethod[0]
	}

	return nil
}

// DIDKeyResolver implements the did:key method.
// See https://w3c-ccg.github.io/did-method-key/
type DIDKeyResolver struct{}

// NewDIDKeyResolver creates a new did:key resolver.
func NewDIDKeyResolver() *DIDKeyResolver {
	return &DIDKeyResolver{}
}

// Method returns "key" as this resolver handles did:key DIDs.
func (r *DIDKeyResolver) Method() string {
	return "key"
}

// Resolve resolves a did:key identifier to a DID document.
// The did:key method encodes the public key directly in the DID.
func (r *DIDKeyResolver) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
	if !strings.HasPrefix(did, "did:key:") {
		return nil, fmt.Errorf("invalid did:key identifier: must start with 'did:key:'")
	}

	// Extract the multibase-encoded public key
	multibaseKey := strings.TrimPrefix(did, "did:key:")
	if multibaseKey == "" {
		return nil, fmt.Errorf("invalid did:key identifier: missing key material")
	}

	// Parse the multibase-encoded multicodec key
	keyType, publicKeyJwk, err := decodeMultibaseKey(multibaseKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Build the DID document
	vmID := did + "#" + multibaseKey
	verificationMethod := VerificationMethod{
		ID:           vmID,
		Type:         keyType,
		Controller:   did,
		PublicKeyJwk: publicKeyJwk,
	}

	return &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID:                 did,
		VerificationMethod: []VerificationMethod{verificationMethod},
		Authentication:     []interface{}{vmID},
		AssertionMethod:    []interface{}{vmID},
	}, nil
}

// Multicodec prefixes for different key types
const (
	// Ed25519 public key multicodec prefix (0xed01)
	multicodecEd25519Pub = 0xed
	// P-256 public key multicodec prefix (0x1200)
	multicodecP256Pub = 0x80
	// P-384 public key multicodec prefix (0x1201)
	multicodecP384Pub = 0x81
	// secp256k1 public key multicodec prefix (0xe7)
	multicodecSecp256k1Pub = 0xe7
)

// decodeMultibaseKey decodes a multibase-encoded multicodec public key.
func decodeMultibaseKey(multibaseKey string) (string, map[string]interface{}, error) {
	if len(multibaseKey) < 2 {
		return "", nil, fmt.Errorf("multibase key too short")
	}

	// First character is the multibase encoding identifier
	// 'z' = base58btc
	encoding := multibaseKey[0]
	encodedKey := multibaseKey[1:]

	var keyBytes []byte
	var err error

	switch encoding {
	case 'z':
		// Base58btc encoding
		keyBytes, err = base58Decode(encodedKey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode base58btc: %w", err)
		}
	default:
		return "", nil, fmt.Errorf("unsupported multibase encoding: %c", encoding)
	}

	if len(keyBytes) < 2 {
		return "", nil, fmt.Errorf("decoded key too short")
	}

	// First byte(s) are the multicodec identifier
	multicodec := keyBytes[0]
	var publicKeyBytes []byte

	switch multicodec {
	case multicodecEd25519Pub:
		// Ed25519 public key (32 bytes)
		if len(keyBytes) < 34 {
			return "", nil, fmt.Errorf("Ed25519 key too short: expected 34 bytes, got %d", len(keyBytes))
		}
		publicKeyBytes = keyBytes[2:34]
		return "Ed25519VerificationKey2020", map[string]interface{}{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(publicKeyBytes),
		}, nil

	case multicodecSecp256k1Pub:
		// secp256k1 public key (33 bytes compressed)
		if len(keyBytes) < 35 {
			return "", nil, fmt.Errorf("secp256k1 key too short: expected 35 bytes, got %d", len(keyBytes))
		}
		publicKeyBytes = keyBytes[2:35]
		// For secp256k1, we need to decompress the key to get x and y
		x, y, err := decompressSecp256k1(publicKeyBytes)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decompress secp256k1 key: %w", err)
		}
		return "EcdsaSecp256k1VerificationKey2019", map[string]interface{}{
			"kty": "EC",
			"crv": "secp256k1",
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		}, nil

	default:
		// Check for 2-byte multicodec prefixes
		if len(keyBytes) >= 2 {
			twoByteCodec := (uint16(keyBytes[0]) << 8) | uint16(keyBytes[1])
			switch twoByteCodec {
			case 0x8024: // P-256 (compressed)
				publicKeyBytes = keyBytes[2:]
				x, y, err := decompressP256(publicKeyBytes)
				if err != nil {
					return "", nil, fmt.Errorf("failed to decompress P-256 key: %w", err)
				}
				return "JsonWebKey2020", map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   base64.RawURLEncoding.EncodeToString(x),
					"y":   base64.RawURLEncoding.EncodeToString(y),
				}, nil

			case 0x8124: // P-384 (compressed)
				publicKeyBytes = keyBytes[2:]
				x, y, err := decompressP384(publicKeyBytes)
				if err != nil {
					return "", nil, fmt.Errorf("failed to decompress P-384 key: %w", err)
				}
				return "JsonWebKey2020", map[string]interface{}{
					"kty": "EC",
					"crv": "P-384",
					"x":   base64.RawURLEncoding.EncodeToString(x),
					"y":   base64.RawURLEncoding.EncodeToString(y),
				}, nil
			}
		}

		return "", nil, fmt.Errorf("unsupported multicodec: 0x%x", multicodec)
	}
}

// DecodeMultibaseKeyJWK decodes a multibase-encoded multicodec public key (the publicKeyMultibase of a
// Multikey or Ed25519VerificationKey2020 verification method) into its public JWK.
func DecodeMultibaseKeyJWK(multibaseKey string) (map[string]interface{}, error) {
	_, jwk, err := decodeMultibaseKey(multibaseKey)
	return jwk, err
}

// Base58btc alphabet
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Decode decodes a base58btc encoded string.
func base58Decode(input string) ([]byte, error) {
	// Build the reverse alphabet map
	alphabetMap := make(map[rune]int)
	for i, c := range base58Alphabet {
		alphabetMap[c] = i
	}

	result := make([]byte, 0, len(input))

	// Process each character
	for _, c := range input {
		idx, ok := alphabetMap[c]
		if !ok {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}

		// Multiply existing result by 58 and add the new digit
		carry := idx
		for i := len(result) - 1; i >= 0; i-- {
			carry += int(result[i]) * 58
			result[i] = byte(carry % 256)
			carry /= 256
		}

		for carry > 0 {
			result = append([]byte{byte(carry % 256)}, result...)
			carry /= 256
		}
	}

	// Handle leading zeros
	for _, c := range input {
		if c != '1' {
			break
		}
		result = append([]byte{0}, result...)
	}

	return result, nil
}

// secp256k1 domain parameters (SEC 2): y^2 = x^3 + 7 over the field of order p.
var secp256k1P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

// decompressSecp256k1 decompresses a compressed secp256k1 public key into fixed-width x and y.
// The standard library has no secp256k1, so y is recovered from the curve equation: p = 3 (mod 4), hence
// y = (x^3 + 7)^((p+1)/4) mod p, taken with the parity the prefix byte names.
func decompressSecp256k1(compressed []byte) ([]byte, []byte, error) {
	if len(compressed) != 33 {
		return nil, nil, fmt.Errorf("invalid compressed key length: expected 33, got %d", len(compressed))
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		return nil, nil, fmt.Errorf("invalid compressed key prefix 0x%02x", compressed[0])
	}
	p := secp256k1P
	x := new(big.Int).SetBytes(compressed[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil, fmt.Errorf("x coordinate is not a field element")
	}
	rhs := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs.Add(rhs, big.NewInt(7)).Mod(rhs, p)
	y := new(big.Int).Exp(rhs, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2), p)
	if new(big.Int).Exp(y, big.NewInt(2), p).Cmp(rhs) != 0 {
		return nil, nil, fmt.Errorf("x coordinate is not on the secp256k1 curve")
	}
	if y.Bit(0) != uint(compressed[0]&1) {
		y.Sub(p, y)
	}
	return x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32)), nil
}

// decompressP256 decompresses a compressed P-256 public key.
func decompressP256(compressed []byte) ([]byte, []byte, error) {
	if len(compressed) != 33 {
		return nil, nil, fmt.Errorf("invalid compressed key length: expected 33, got %d", len(compressed))
	}

	// Use Go's elliptic curve library
	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, nil, fmt.Errorf("failed to decompress P-256 key")
	}

	// Fixed-width, as a JWK carries them: Bytes() would drop a leading zero byte.
	return x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32)), nil
}

// decompressP384 decompresses a compressed P-384 public key.
func decompressP384(compressed []byte) ([]byte, []byte, error) {
	if len(compressed) != 49 {
		return nil, nil, fmt.Errorf("invalid compressed key length: expected 49, got %d", len(compressed))
	}

	// Use Go's elliptic curve library
	curve := elliptic.P384()
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, nil, fmt.Errorf("failed to decompress P-384 key")
	}

	return x.FillBytes(make([]byte, 48)), y.FillBytes(make([]byte, 48)), nil
}

// NewGenericDIDRegistryWithKeyMethod creates a GenericDIDRegistry with the did:key resolver registered.
func NewGenericDIDRegistryWithKeyMethod(config GenericDIDRegistryConfig) *GenericDIDRegistry {
	registry := NewGenericDIDRegistry(config)
	registry.RegisterResolver(NewDIDKeyResolver())
	return registry
}

// Ensure interfaces are implemented
var _ DIDResolver = (*DIDKeyResolver)(nil)
var _ registry.TrustRegistry = (*GenericDIDRegistry)(nil)

// Suppress unused warning for ed25519 import (used for key type reference)
var _ = ed25519.PublicKeySize

// verificationMethodType returns the verification method's type string.
func verificationMethodType(m VerificationMethod) string { return m.Type }
