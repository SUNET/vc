//go:build vc20

package keyresolver

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/multiformats/go-multibase"
)

// Multicodec constants for public key types.
// These are varint-encoded multicodec values as defined in the multicodec table.
// See: https://github.com/multiformats/multicodec
const (
	// multicodecEd25519Byte1 and multicodecEd25519Byte2 form the Ed25519 public key multicodec (0xed01).
	multicodecEd25519Byte1 = 0xed
	multicodecEd25519Byte2 = 0x01

	// multicodecX25519Byte1 and multicodecX25519Byte2 form the X25519 public key multicodec (0xec01).
	multicodecX25519Byte1 = 0xec
	multicodecX25519Byte2 = 0x01

	// ECDSA P-256 multicodec (0x1200) varint-encoded as 0x80 0x24.
	multicodecP256Byte1 = 0x80
	multicodecP256Byte2 = 0x24

	// ECDSA P-384 multicodec (0x1201) varint-encoded as 0x81 0x24.
	multicodecP384Byte1 = 0x81
	multicodecP384Byte2 = 0x24

	// ECDSA P-521 multicodec (0x1202) varint-encoded as 0x82 0x24.
	multicodecP521Byte1 = 0x82
	multicodecP521Byte2 = 0x24

	// multicodecPrefixLen is the length of the multicodec prefix (2 bytes).
	multicodecPrefixLen = 2

	// ed25519MultibaseKeyLen is the expected length for Ed25519/X25519 multibase keys:
	// 2 bytes multicodec prefix + 32 bytes key.
	ed25519MultibaseKeyLen = 34
)

// findMatchingVerificationMethod finds a verification method in metadata that matches the given identifier.
// Returns the verification method map if found, nil otherwise.
func findMatchingVerificationMethod(metadata any, verificationMethod string) (map[string]any, error) {
	doc, ok := metadata.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: expected map, got %T", metadata)
	}

	vms, err := getVerificationMethods(doc)
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		vmMap, ok := vm.(map[string]any)
		if !ok {
			continue
		}
		if matchesVerificationMethod(vmMap, verificationMethod, doc) {
			return vmMap, nil
		}
	}
	return nil, nil
}

// ExtractEd25519FromMetadata extracts an Ed25519 public key from a DID document
// or entity configuration returned in the trust_metadata field of an AuthZEN response.
func ExtractEd25519FromMetadata(metadata any, verificationMethod string) (ed25519.PublicKey, error) {
	vmMap, err := findMatchingVerificationMethod(metadata, verificationMethod)
	if err != nil {
		return nil, err
	}
	if vmMap == nil {
		return nil, fmt.Errorf("Ed25519 verification method not found: %s", verificationMethod)
	}

	// Try publicKeyMultibase first (preferred for Ed25519)
	if multibase, ok := vmMap["publicKeyMultibase"].(string); ok {
		if key, err := decodeMultikeyEd25519(multibase); err == nil {
			return key, nil
		}
	}
	// Try publicKeyJwk
	if jwk, ok := vmMap["publicKeyJwk"].(map[string]any); ok {
		if key, err := JWKToEd25519(jwk); err == nil {
			return key, nil
		}
	}
	// Try publicKeyBase58 (legacy format)
	if keyBase58, ok := vmMap["publicKeyBase58"].(string); ok {
		if key, err := decodeBase58Ed25519(keyBase58); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("Ed25519 verification method not found: %s", verificationMethod)
}

// ExtractECDSAFromMetadata extracts an ECDSA public key from a DID document
// or entity configuration returned in the trust_metadata field.
func ExtractECDSAFromMetadata(metadata any, verificationMethod string) (*ecdsa.PublicKey, error) {
	vmMap, err := findMatchingVerificationMethod(metadata, verificationMethod)
	if err != nil {
		return nil, err
	}
	if vmMap == nil {
		return nil, fmt.Errorf("ECDSA verification method not found: %s", verificationMethod)
	}

	// Try publicKeyJwk (preferred for ECDSA)
	if jwk, ok := vmMap["publicKeyJwk"].(map[string]any); ok {
		if key, err := JWKToECDSA(jwk); err == nil {
			return key, nil
		}
	}
	// Try publicKeyMultibase (P-256 multicodec is 0x1200)
	if multibase, ok := vmMap["publicKeyMultibase"].(string); ok {
		if key, err := decodeMultikeyECDSA(multibase); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("ECDSA verification method not found: %s", verificationMethod)
}

// ExtractX25519FromMetadata extracts an X25519 key agreement key from trust_metadata.
// It looks for keys in the keyAgreement section of the DID document.
func ExtractX25519FromMetadata(metadata any, did string) (*ecdh.PublicKey, error) {
	doc, ok := metadata.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: expected map, got %T", metadata)
	}

	// Get keyAgreement section
	keyAgreement, err := getKeyAgreementMethods(doc)
	if err != nil {
		return nil, err
	}

	for _, ka := range keyAgreement {
		kaMap, ok := ka.(map[string]any)
		if !ok {
			continue
		}

		// Try publicKeyJwk (preferred for X25519)
		if jwk, ok := kaMap["publicKeyJwk"].(map[string]any); ok {
			key, err := JWKToX25519(jwk)
			if err == nil {
				return key, nil
			}
		}

		// Try publicKeyMultibase (X25519 multicodec is 0xec)
		if multibase, ok := kaMap["publicKeyMultibase"].(string); ok {
			key, err := decodeMultikeyX25519(multibase)
			if err == nil {
				return key, nil
			}
		}
	}

	return nil, fmt.Errorf("X25519 key agreement key not found for: %s", did)
}

// ExtractServiceFromMetadata extracts a DIDCommMessaging service from trust_metadata.
func ExtractServiceFromMetadata(metadata any, did string) (*DIDCommService, error) {
	doc, ok := metadata.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: expected map, got %T", metadata)
	}

	// Get service section
	services, err := getServices(doc)
	if err != nil {
		return nil, err
	}

	// Find DIDCommMessaging service
	for _, svc := range services {
		svcMap, ok := svc.(map[string]any)
		if !ok {
			continue
		}

		svcType, _ := svcMap["type"].(string)
		if svcType != "DIDCommMessaging" {
			continue
		}

		return parseServiceMap(svcMap)
	}

	return nil, fmt.Errorf("DIDCommMessaging service not found for: %s", did)
}

// getKeyAgreementMethods extracts the keyAgreement section from a DID document.
func getKeyAgreementMethods(doc map[string]any) ([]any, error) {
	// Direct array of verification methods
	if kas, ok := doc["keyAgreement"].([]any); ok {
		return resolveKeyAgreementRefs(kas, doc)
	}

	// Try as array of maps
	if kas, ok := doc["keyAgreement"].([]map[string]any); ok {
		result := make([]any, len(kas))
		for i, ka := range kas {
			result[i] = ka
		}
		return result, nil
	}

	return nil, fmt.Errorf("no keyAgreement section found in metadata")
}

// resolveKeyAgreementRefs resolves keyAgreement references to full verification methods.
// keyAgreement can contain either full verification methods or string references.
// References can be:
//   - Full ID: "did:example:123#key-1"
//   - Fragment only: "#key-1"
//   - Bare fragment: "key-1" (legacy)
func resolveKeyAgreementRefs(kas []any, doc map[string]any) ([]any, error) {
	vms, _ := getVerificationMethods(doc)
	docID, _ := doc["id"].(string)
	result := make([]any, 0, len(kas))

	for _, ka := range kas {
		switch ref := ka.(type) {
		case map[string]any:
			// Already a full verification method
			result = append(result, ref)
		case string:
			// Reference to a verification method - resolve it
			for _, vm := range vms {
				vmMap, ok := vm.(map[string]any)
				if !ok {
					continue
				}
				id, ok := vmMap["id"].(string)
				if !ok {
					continue
				}
				// Match using same logic as matchesVerificationMethod:
				// 1. Direct ID match
				if id == ref {
					result = append(result, vmMap)
					break
				}
				// 2. ref is a fragment reference (#key-1) and id is the full ID
				if strings.HasPrefix(ref, "#") && strings.HasSuffix(id, ref) {
					result = append(result, vmMap)
					break
				}
				// 3. id is a fragment (#key-1) and ref is the full ID
				if strings.HasPrefix(id, "#") && docID+id == ref {
					result = append(result, vmMap)
					break
				}
				// 4. ref is just the fragment part without # (legacy)
				if strings.HasSuffix(id, "#"+ref) {
					result = append(result, vmMap)
					break
				}
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no keyAgreement methods resolved")
	}

	return result, nil
}

// getServices extracts the service section from a DID document.
func getServices(doc map[string]any) ([]any, error) {
	// Direct array
	if svcs, ok := doc["service"].([]any); ok {
		return svcs, nil
	}

	// Try as array of maps
	if svcs, ok := doc["service"].([]map[string]any); ok {
		result := make([]any, len(svcs))
		for i, svc := range svcs {
			result[i] = svc
		}
		return result, nil
	}

	return nil, fmt.Errorf("no service section found in metadata")
}

// parseServiceMap parses a DIDCommMessaging service entry from a map.
func parseServiceMap(svcMap map[string]any) (*DIDCommService, error) {
	svc := &DIDCommService{}

	// ID
	if id, ok := svcMap["id"].(string); ok {
		svc.ID = id
	}

	// ServiceEndpoint can be string, array, or object
	// Also extract routingKeys/accept from serviceEndpoint object if present
	switch ep := svcMap["serviceEndpoint"].(type) {
	case string:
		svc.ServiceEndpoint = ep
	case []any:
		if len(ep) > 0 {
			if s, ok := ep[0].(string); ok {
				svc.ServiceEndpoint = s
			} else if obj, ok := ep[0].(map[string]any); ok {
				if uri, ok := obj["uri"].(string); ok {
					svc.ServiceEndpoint = uri
				}
				// Extract routingKeys/accept from object endpoint
				extractRoutingKeysAccept(obj, svc)
			}
		}
	case map[string]any:
		if uri, ok := ep["uri"].(string); ok {
			svc.ServiceEndpoint = uri
		}
		// Extract routingKeys/accept from object endpoint
		extractRoutingKeysAccept(ep, svc)
	}

	// Also check for routingKeys/accept at service level (fallback)
	if len(svc.RoutingKeys) == 0 {
		if rks, ok := svcMap["routingKeys"].([]any); ok {
			for _, rk := range rks {
				if s, ok := rk.(string); ok {
					svc.RoutingKeys = append(svc.RoutingKeys, s)
				}
			}
		}
	}

	if len(svc.Accept) == 0 {
		if accepts, ok := svcMap["accept"].([]any); ok {
			for _, a := range accepts {
				if s, ok := a.(string); ok {
					svc.Accept = append(svc.Accept, s)
				}
			}
		}
	}

	if svc.ServiceEndpoint == "" {
		return nil, fmt.Errorf("service has no endpoint")
	}

	return svc, nil
}

// extractRoutingKeysAccept extracts routingKeys and accept from a serviceEndpoint object.
func extractRoutingKeysAccept(epObj map[string]any, svc *DIDCommService) {
	if rks, ok := epObj["routingKeys"].([]any); ok {
		for _, rk := range rks {
			if s, ok := rk.(string); ok {
				svc.RoutingKeys = append(svc.RoutingKeys, s)
			}
		}
	}
	if accepts, ok := epObj["accept"].([]any); ok {
		for _, a := range accepts {
			if s, ok := a.(string); ok {
				svc.Accept = append(svc.Accept, s)
			}
		}
	}
}

// JWKToX25519 extracts an X25519 public key from a JWK.
func JWKToX25519(jwk map[string]any) (*ecdh.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	if kty != "OKP" || crv != "X25519" {
		return nil, fmt.Errorf("not an X25519 JWK: kty=%s, crv=%s", kty, crv)
	}

	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate in X25519 JWK")
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	return ecdh.X25519().NewPublicKey(pubBytes)
}

// decodeMultikeyX25519 decodes an X25519 key from multibase format.
// X25519 multicodec is 0xec (236), varint encoded as 0xec 0x01
func decodeMultikeyX25519(multikey string) (*ecdh.PublicKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("empty multikey")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(multikey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multibase: %w", err)
	}

	// Check length (2 bytes multicodec + 32 bytes key)
	if len(decoded) != ed25519MultibaseKeyLen {
		return nil, fmt.Errorf("invalid multikey length: expected %d, got %d", ed25519MultibaseKeyLen, len(decoded))
	}

	// Check X25519 multicodec prefix
	if decoded[0] != multicodecX25519Byte1 || decoded[1] != multicodecX25519Byte2 {
		return nil, fmt.Errorf("not an X25519 multikey: multicodec 0x%02x%02x", decoded[0], decoded[1])
	}

	return ecdh.X25519().NewPublicKey(decoded[multicodecPrefixLen:])
}

// getVerificationMethods extracts the verification methods array from a DID document.
func getVerificationMethods(doc map[string]any) ([]any, error) {
	// Standard DID document format
	if vms, ok := doc["verificationMethod"].([]any); ok {
		return vms, nil
	}

	// Try as array of maps (some serializations)
	if vms, ok := doc["verificationMethod"].([]map[string]any); ok {
		result := make([]any, len(vms))
		for i, vm := range vms {
			result[i] = vm
		}
		return result, nil
	}

	// OpenID Federation entity configuration - check for JWKS in metadata
	// The structure is: metadata -> openid_relying_party/openid_provider -> jwks -> keys
	if result := extractOpenIDFederationKeys(doc); len(result) > 0 {
		return result, nil
	}

	return nil, fmt.Errorf("no verification methods found in metadata")
}

// extractOpenIDFederationKeys extracts JWKs from OpenID Federation entity configuration.
// Returns an empty slice if no keys are found (not an error - the document may be a regular DID doc).
func extractOpenIDFederationKeys(doc map[string]any) []any {
	metadata, ok := doc["metadata"].(map[string]any)
	if !ok {
		return nil
	}

	entityTypes := []string{"openid_relying_party", "openid_provider", "federation_entity"}
	for _, entityType := range entityTypes {
		if keys := getJWKSFromEntityMetadata(metadata, entityType); len(keys) > 0 {
			return keys
		}
	}
	return nil
}

// getJWKSFromEntityMetadata extracts JWKS keys from a specific entity type's metadata.
func getJWKSFromEntityMetadata(metadata map[string]any, entityType string) []any {
	entityMeta, ok := metadata[entityType].(map[string]any)
	if !ok {
		return nil
	}

	jwks, ok := entityMeta["jwks"].(map[string]any)
	if !ok {
		return nil
	}

	keys, ok := jwks["keys"].([]any)
	if !ok {
		return nil
	}

	return convertJWKsToVerificationMethods(keys)
}

// convertJWKsToVerificationMethods wraps JWKs in pseudo verification method format.
func convertJWKsToVerificationMethods(keys []any) []any {
	result := make([]any, 0, len(keys))
	for _, key := range keys {
		keyMap, ok := key.(map[string]any)
		if !ok {
			continue
		}
		vm := map[string]any{
			"id":           keyMap["kid"],
			"publicKeyJwk": keyMap,
		}
		result = append(result, vm)
	}
	return result
}

// matchesVerificationMethod checks if a verification method entry matches the requested ID.
func matchesVerificationMethod(vmMap map[string]any, verificationMethod string, doc map[string]any) bool {
	// Direct ID match
	if id, ok := vmMap["id"].(string); ok {
		if id == verificationMethod {
			return true
		}
		// Also match if verificationMethod is just the fragment
		if strings.HasSuffix(verificationMethod, "#"+id) {
			return true
		}
		// Match if the VM id is a fragment and we're looking for the full ID
		if strings.HasPrefix(id, "#") {
			docID, _ := doc["id"].(string)
			if docID+id == verificationMethod {
				return true
			}
		}
	}

	// Match by kid (for JWKs)
	if kid, ok := vmMap["kid"].(string); ok {
		if kid == verificationMethod || strings.HasSuffix(verificationMethod, "#"+kid) {
			return true
		}
	}

	return false
}

// decodeMultikeyEd25519 decodes a multikey-encoded Ed25519 public key.
// Multikey format: multibase(multicodec || raw-key-bytes)
// Ed25519 multicodec is 0xed (237)
func decodeMultikeyEd25519(multikey string) (ed25519.PublicKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("empty multikey")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(multikey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multibase: %w", err)
	}

	// Check length (2 bytes multicodec + 32 bytes key)
	if len(decoded) != ed25519MultibaseKeyLen {
		return nil, fmt.Errorf("invalid multikey length: expected %d, got %d", ed25519MultibaseKeyLen, len(decoded))
	}

	// Check Ed25519 multicodec prefix
	if decoded[0] != multicodecEd25519Byte1 || decoded[1] != multicodecEd25519Byte2 {
		return nil, fmt.Errorf("not an Ed25519 multikey: multicodec 0x%02x%02x", decoded[0], decoded[1])
	}

	return ed25519.PublicKey(decoded[multicodecPrefixLen:]), nil
}

// decodeMultikeyECDSA decodes a multikey-encoded ECDSA public key.
// P-256 multicodec is 0x1200, P-384 is 0x1201
// Multicodec uses varint encoding, so 0x1200 becomes 0x80 0x24 in varint
func decodeMultikeyECDSA(multikey string) (*ecdsa.PublicKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("empty multikey")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(multikey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multibase: %w", err)
	}

	if len(decoded) < 3 {
		return nil, fmt.Errorf("multikey too short")
	}

	// Check multicodec prefix for ECDSA curves
	var curve elliptic.Curve
	var keyData []byte

	if len(decoded) >= multicodecPrefixLen && decoded[0] == multicodecP256Byte1 && decoded[1] == multicodecP256Byte2 {
		// P-256 compressed public key
		curve = elliptic.P256()
		keyData = decoded[multicodecPrefixLen:]
	} else if len(decoded) >= multicodecPrefixLen && decoded[0] == multicodecP384Byte1 && decoded[1] == multicodecP384Byte2 {
		// P-384 compressed public key
		curve = elliptic.P384()
		keyData = decoded[multicodecPrefixLen:]
	} else if len(decoded) >= multicodecPrefixLen && decoded[0] == multicodecP521Byte1 && decoded[1] == multicodecP521Byte2 {
		// P-521 compressed public key
		curve = elliptic.P521()
		keyData = decoded[multicodecPrefixLen:]
	} else {
		// Not a recognized ECDSA multicodec
		return nil, fmt.Errorf("unrecognized ECDSA multicodec: 0x%02x 0x%02x", decoded[0], decoded[1])
	}

	// Parse compressed point format (33 bytes for P-256, 49 for P-384, 67 for P-521)
	x, y := elliptic.UnmarshalCompressed(curve, keyData)
	if x == nil {
		return nil, fmt.Errorf("failed to unmarshal compressed ECDSA point")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// decodeBase58Ed25519 decodes a base58-encoded Ed25519 public key (legacy format).
func decodeBase58Ed25519(encoded string) (ed25519.PublicKey, error) {
	// Use multibase with 'z' prefix for base58-btc decoding
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try base58
		_, decoded, err = multibase.Decode("z" + encoded)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base58: %w", err)
		}
	}

	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", ed25519.PublicKeySize, len(decoded))
	}

	return ed25519.PublicKey(decoded), nil
}

// ExtractDIDFromVerificationMethod extracts the DID from a verification method ID.
// For example: "did:web:example.com#key-1" -> "did:web:example.com"
func ExtractDIDFromVerificationMethod(verificationMethod string) string {
	if idx := strings.Index(verificationMethod, "#"); idx > 0 {
		return verificationMethod[:idx]
	}
	return verificationMethod
}

// ExtractFragmentFromVerificationMethod extracts the fragment from a verification method ID.
// For example: "did:web:example.com#key-1" -> "key-1"
func ExtractFragmentFromVerificationMethod(verificationMethod string) string {
	if idx := strings.Index(verificationMethod, "#"); idx >= 0 && idx < len(verificationMethod)-1 {
		return verificationMethod[idx+1:]
	}
	return ""
}
