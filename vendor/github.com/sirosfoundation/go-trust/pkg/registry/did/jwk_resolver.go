package did

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// privateJWKParams are JWK members that only ever appear on a private or
// symmetric key. A DID is a public identifier, so a key carrying any of these
// is rejected rather than published in a DID document.
//
// "d" covers EC/OKP private keys and the RSA private exponent, "p" through
// "oth" the remaining RSA private values, and "k" the symmetric key of an
// oct JWK — which has no meaning as a verification method in the first place.
var privateJWKParams = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// DIDJwkResolver implements the did:jwk method.
// See https://github.com/quartzjer/did-jwk/blob/main/spec.md
//
// did:jwk encodes a single public JWK directly in the identifier, so
// resolution is entirely local: decode the method-specific identifier and the
// key is already in hand. There is no network access, no caching, and nothing
// to trust beyond the DID string itself — which means resolving a did:jwk
// says nothing about whether the key should be trusted. That judgement
// belongs to the policy layer above, exactly as it does for did:key.
type DIDJwkResolver struct{}

// NewDIDJwkResolver creates a new did:jwk resolver.
func NewDIDJwkResolver() *DIDJwkResolver {
	return &DIDJwkResolver{}
}

// Method returns "jwk" as this resolver handles did:jwk DIDs.
//
// Note this is distinct from the did:jwks method implemented in
// pkg/registry/didjwks, which encodes a JWKS *endpoint* to be fetched rather
// than a key to be decoded.
func (r *DIDJwkResolver) Method() string {
	return "jwk"
}

// Resolve resolves a did:jwk identifier to a DID document.
func (r *DIDJwkResolver) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
	if !strings.HasPrefix(did, "did:jwk:") {
		return nil, fmt.Errorf("invalid did:jwk identifier: must start with 'did:jwk:'")
	}

	encoded := strings.TrimPrefix(did, "did:jwk:")

	// A fragment or query belongs to the DID URL, not to the method-specific
	// identifier, so it is stripped before decoding. The document's own `id`
	// is then the bare DID, which is what the spec requires.
	if i := strings.IndexAny(encoded, "#?"); i >= 0 {
		encoded = encoded[:i]
		did = did[:strings.IndexAny(did, "#?")]
	}
	if encoded == "" {
		return nil, fmt.Errorf("invalid did:jwk identifier: missing key material")
	}

	// The spec mandates unpadded base64url; RawURLEncoding rejects padding
	// rather than tolerating it, so two different strings can never resolve
	// to the same key.
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid did:jwk identifier: not unpadded base64url: %w", err)
	}

	var jwk map[string]interface{}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("invalid did:jwk identifier: not a JSON JWK: %w", err)
	}

	if kty, _ := jwk["kty"].(string); kty == "" {
		return nil, fmt.Errorf("invalid did:jwk identifier: JWK has no 'kty'")
	}

	for _, param := range privateJWKParams {
		if _, present := jwk[param]; present {
			return nil, fmt.Errorf("invalid did:jwk identifier: JWK contains private key parameter %q", param)
		}
	}

	vmID := did + "#0"
	verificationMethod := VerificationMethod{
		ID:           vmID,
		Type:         "JsonWebKey2020",
		Controller:   did,
		PublicKeyJwk: jwk,
	}

	doc := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID:                 did,
		VerificationMethod: []VerificationMethod{verificationMethod},
	}

	// The `use` member, when present, restricts which verification
	// relationships the key may appear in: a signing key must not be offered
	// for key agreement, and an encryption key must not be accepted for
	// authentication or assertion.
	use, _ := jwk["use"].(string)
	switch use {
	case "enc":
		doc.KeyAgreement = []interface{}{vmID}
	case "sig":
		doc.Authentication = []interface{}{vmID}
		doc.AssertionMethod = []interface{}{vmID}
		doc.CapabilityInvocation = []interface{}{vmID}
		doc.CapabilityDelegation = []interface{}{vmID}
	default:
		doc.Authentication = []interface{}{vmID}
		doc.AssertionMethod = []interface{}{vmID}
		doc.CapabilityInvocation = []interface{}{vmID}
		doc.CapabilityDelegation = []interface{}{vmID}
		doc.KeyAgreement = []interface{}{vmID}
	}

	return doc, nil
}

// NewGenericDIDRegistryWithLocalMethods creates a GenericDIDRegistry with every
// self-contained DID method registered: did:key and did:jwk. Both resolve
// purely from the identifier and neither performs network access.
func NewGenericDIDRegistryWithLocalMethods(config GenericDIDRegistryConfig) *GenericDIDRegistry {
	registry := NewGenericDIDRegistry(config)
	registry.RegisterResolver(NewDIDKeyResolver())
	registry.RegisterResolver(NewDIDJwkResolver())
	return registry
}

// LocalMethods names the DID methods this package resolves without network
// access. did:web and did:webvh are deliberately absent: they need fetching
// and caching, and have registries of their own.
var LocalMethods = []string{"key", "jwk"}

// ResolverForMethod returns the built-in resolver for a DID method name as it
// appears in configuration. Both "key" and "did:key" spellings are accepted.
func ResolverForMethod(method string) (DIDResolver, error) {
	switch strings.TrimPrefix(method, "did:") {
	case "key":
		return NewDIDKeyResolver(), nil
	case "jwk":
		return NewDIDJwkResolver(), nil
	default:
		return nil, fmt.Errorf("unknown DID method %q: supported methods are %s",
			method, strings.Join(LocalMethods, ", "))
	}
}

// NewGenericDIDRegistryForMethods creates a GenericDIDRegistry with the named
// methods registered. An empty list registers every method in LocalMethods.
//
// An unknown method is an error rather than a warning: silently ignoring it
// would leave the registry running with less resolution than was asked for,
// which surfaces much later as an unresolvable DID.
func NewGenericDIDRegistryForMethods(config GenericDIDRegistryConfig, methods []string) (*GenericDIDRegistry, error) {
	if len(methods) == 0 {
		return NewGenericDIDRegistryWithLocalMethods(config), nil
	}

	registry := NewGenericDIDRegistry(config)
	for _, method := range methods {
		resolver, err := ResolverForMethod(method)
		if err != nil {
			return nil, err
		}
		registry.RegisterResolver(resolver)
	}
	return registry, nil
}

// Ensure interfaces are implemented
var _ DIDResolver = (*DIDJwkResolver)(nil)
