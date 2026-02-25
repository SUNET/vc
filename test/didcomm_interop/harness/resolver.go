//go:build didcomm_interop

package harness

import (
	"context"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// MockResolver provides DID resolution for interoperability tests.
// It holds pre-configured DID Documents with verification methods and key agreement keys.
type MockResolver struct {
	documents map[string]*MockDIDDocument
	keys      map[string]jwk.Key
}

// MockDIDDocument represents a simplified DID Document for testing.
type MockDIDDocument struct {
	ID                 string
	KeyAgreement       []MockVerificationMethod
	Authentication     []MockVerificationMethod
	AssertionMethod    []MockVerificationMethod
	VerificationMethod []MockVerificationMethod
	Service            []MockService
}

// MockVerificationMethod represents a verification method in a DID Document.
type MockVerificationMethod struct {
	ID           string
	Type         string
	Controller   string
	PublicKeyJWK jwk.Key
}

// MockService represents a service endpoint in a DID Document.
type MockService struct {
	ID              string
	Type            string
	ServiceEndpoint string
}

// NewMockResolver creates a new mock resolver with the given test keys.
func NewMockResolver(testKeys *TestKeys) (*MockResolver, error) {
	r := &MockResolver{
		documents: make(map[string]*MockDIDDocument),
		keys:      make(map[string]jwk.Key),
	}

	// Build Alice's DID Document
	aliceDoc := &MockDIDDocument{
		ID: AliceDID,
		KeyAgreement: []MockVerificationMethod{
			{
				ID:           testKeys.AliceX25519.KID,
				Type:         "X25519KeyAgreementKey2020",
				Controller:   AliceDID,
				PublicKeyJWK: testKeys.AliceX25519.PublicJWK,
			},
			{
				ID:           testKeys.AliceP256.KID,
				Type:         "JsonWebKey2020",
				Controller:   AliceDID,
				PublicKeyJWK: testKeys.AliceP256.PublicJWK,
			},
			{
				ID:           testKeys.AliceP384.KID,
				Type:         "JsonWebKey2020",
				Controller:   AliceDID,
				PublicKeyJWK: testKeys.AliceP384.PublicJWK,
			},
		},
		Authentication: []MockVerificationMethod{
			{
				ID:           testKeys.AliceEdSign.KID,
				Type:         "Ed25519VerificationKey2020",
				Controller:   AliceDID,
				PublicKeyJWK: testKeys.AliceEdSign.PublicJWK,
			},
		},
		AssertionMethod: []MockVerificationMethod{
			{
				ID:           testKeys.AliceEdSign.KID,
				Type:         "Ed25519VerificationKey2020",
				Controller:   AliceDID,
				PublicKeyJWK: testKeys.AliceEdSign.PublicJWK,
			},
		},
		Service: []MockService{
			{
				ID:              AliceDID + "#didcomm-1",
				Type:            "DIDCommMessaging",
				ServiceEndpoint: "https://alice.example.com/didcomm",
			},
		},
	}
	r.documents[AliceDID] = aliceDoc

	// Register Alice's keys
	r.keys[testKeys.AliceX25519.KID] = testKeys.AliceX25519.PublicJWK
	r.keys[testKeys.AliceP256.KID] = testKeys.AliceP256.PublicJWK
	r.keys[testKeys.AliceP384.KID] = testKeys.AliceP384.PublicJWK
	r.keys[testKeys.AliceEdSign.KID] = testKeys.AliceEdSign.PublicJWK

	// Build Bob's DID Document
	bobDoc := &MockDIDDocument{
		ID: BobDID,
		KeyAgreement: []MockVerificationMethod{
			{
				ID:           testKeys.BobX25519.KID,
				Type:         "X25519KeyAgreementKey2020",
				Controller:   BobDID,
				PublicKeyJWK: testKeys.BobX25519.PublicJWK,
			},
			{
				ID:           testKeys.BobP256.KID,
				Type:         "JsonWebKey2020",
				Controller:   BobDID,
				PublicKeyJWK: testKeys.BobP256.PublicJWK,
			},
			{
				ID:           testKeys.BobP384.KID,
				Type:         "JsonWebKey2020",
				Controller:   BobDID,
				PublicKeyJWK: testKeys.BobP384.PublicJWK,
			},
		},
		Authentication: []MockVerificationMethod{
			{
				ID:           testKeys.BobEdSign.KID,
				Type:         "Ed25519VerificationKey2020",
				Controller:   BobDID,
				PublicKeyJWK: testKeys.BobEdSign.PublicJWK,
			},
		},
		AssertionMethod: []MockVerificationMethod{
			{
				ID:           testKeys.BobEdSign.KID,
				Type:         "Ed25519VerificationKey2020",
				Controller:   BobDID,
				PublicKeyJWK: testKeys.BobEdSign.PublicJWK,
			},
		},
		Service: []MockService{
			{
				ID:              BobDID + "#didcomm-1",
				Type:            "DIDCommMessaging",
				ServiceEndpoint: "https://bob.example.com/didcomm",
			},
		},
	}
	r.documents[BobDID] = bobDoc

	// Register Bob's keys
	r.keys[testKeys.BobX25519.KID] = testKeys.BobX25519.PublicJWK
	r.keys[testKeys.BobP256.KID] = testKeys.BobP256.PublicJWK
	r.keys[testKeys.BobP384.KID] = testKeys.BobP384.PublicJWK
	r.keys[testKeys.BobEdSign.KID] = testKeys.BobEdSign.PublicJWK

	return r, nil
}

// NewMockResolverWithWellKnownKeys creates a resolver using the DIDComm spec test vector keys.
func NewMockResolverWithWellKnownKeys() (*MockResolver, error) {
	wellKnownKeys, err := LoadWellKnownKeys()
	if err != nil {
		return nil, err
	}

	r := &MockResolver{
		documents: make(map[string]*MockDIDDocument),
		keys:      make(map[string]jwk.Key),
	}

	// Alice's document with well-known keys
	aliceDoc := &MockDIDDocument{
		ID: AliceDID,
		KeyAgreement: []MockVerificationMethod{
			{
				ID:           "did:example:alice#key-x25519-1",
				Type:         "X25519KeyAgreementKey2020",
				Controller:   AliceDID,
				PublicKeyJWK: mustPublicKey(wellKnownKeys.AliceKeyAgreementX25519),
			},
			{
				ID:           "did:example:alice#key-p256-1",
				Type:         "JsonWebKey2020",
				Controller:   AliceDID,
				PublicKeyJWK: mustPublicKey(wellKnownKeys.AliceKeyAgreementP256),
			},
		},
		Service: []MockService{
			{
				ID:              AliceDID + "#didcomm-1",
				Type:            "DIDCommMessaging",
				ServiceEndpoint: "https://alice.example.com/didcomm",
			},
		},
	}
	r.documents[AliceDID] = aliceDoc
	r.keys["did:example:alice#key-x25519-1"] = mustPublicKey(wellKnownKeys.AliceKeyAgreementX25519)
	r.keys["did:example:alice#key-p256-1"] = mustPublicKey(wellKnownKeys.AliceKeyAgreementP256)

	// Bob's document with well-known keys
	bobDoc := &MockDIDDocument{
		ID: BobDID,
		KeyAgreement: []MockVerificationMethod{
			{
				ID:           "did:example:bob#key-x25519-1",
				Type:         "X25519KeyAgreementKey2020",
				Controller:   BobDID,
				PublicKeyJWK: mustPublicKey(wellKnownKeys.BobKeyAgreementX25519),
			},
			{
				ID:           "did:example:bob#key-p256-1",
				Type:         "JsonWebKey2020",
				Controller:   BobDID,
				PublicKeyJWK: mustPublicKey(wellKnownKeys.BobKeyAgreementP256),
			},
		},
		Service: []MockService{
			{
				ID:              BobDID + "#didcomm-1",
				Type:            "DIDCommMessaging",
				ServiceEndpoint: "https://bob.example.com/didcomm",
			},
		},
	}
	r.documents[BobDID] = bobDoc
	r.keys["did:example:bob#key-x25519-1"] = mustPublicKey(wellKnownKeys.BobKeyAgreementX25519)
	r.keys["did:example:bob#key-p256-1"] = mustPublicKey(wellKnownKeys.BobKeyAgreementP256)

	return r, nil
}

func mustPublicKey(k jwk.Key) jwk.Key {
	pub, err := k.PublicKey()
	if err != nil {
		// If it's already a public key, return as-is
		return k
	}
	return pub
}

// Resolve resolves a DID to its DID Document.
func (r *MockResolver) Resolve(ctx context.Context, did string) (*MockDIDDocument, error) {
	doc, ok := r.documents[did]
	if !ok {
		return nil, fmt.Errorf("DID not found: %s", did)
	}
	return doc, nil
}

// ResolveKey resolves a key ID (DID URL) to a JWK.
func (r *MockResolver) ResolveKey(ctx context.Context, keyID string) (jwk.Key, error) {
	key, ok := r.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return key, nil
}

// GetKeyAgreementKeys returns all key agreement keys for a DID.
func (r *MockResolver) GetKeyAgreementKeys(ctx context.Context, did string) ([]jwk.Key, error) {
	doc, err := r.Resolve(ctx, did)
	if err != nil {
		return nil, err
	}

	var keys []jwk.Key
	for _, vm := range doc.KeyAgreement {
		keys = append(keys, vm.PublicKeyJWK)
	}
	return keys, nil
}

// GetAuthenticationKeys returns all authentication keys for a DID.
func (r *MockResolver) GetAuthenticationKeys(ctx context.Context, did string) ([]jwk.Key, error) {
	doc, err := r.Resolve(ctx, did)
	if err != nil {
		return nil, err
	}

	var keys []jwk.Key
	for _, vm := range doc.Authentication {
		keys = append(keys, vm.PublicKeyJWK)
	}
	return keys, nil
}

// GetServiceEndpoint returns the DIDComm messaging service endpoint for a DID.
func (r *MockResolver) GetServiceEndpoint(ctx context.Context, did string) (string, error) {
	doc, err := r.Resolve(ctx, did)
	if err != nil {
		return "", err
	}

	for _, svc := range doc.Service {
		if svc.Type == "DIDCommMessaging" {
			return svc.ServiceEndpoint, nil
		}
	}
	return "", fmt.Errorf("no DIDCommMessaging service found for %s", did)
}

// AddDocument adds a DID Document to the resolver.
func (r *MockResolver) AddDocument(doc *MockDIDDocument) {
	r.documents[doc.ID] = doc

	// Also register all verification method keys
	for _, vm := range doc.KeyAgreement {
		r.keys[vm.ID] = vm.PublicKeyJWK
	}
	for _, vm := range doc.Authentication {
		r.keys[vm.ID] = vm.PublicKeyJWK
	}
	for _, vm := range doc.AssertionMethod {
		r.keys[vm.ID] = vm.PublicKeyJWK
	}
	for _, vm := range doc.VerificationMethod {
		r.keys[vm.ID] = vm.PublicKeyJWK
	}
}

// AddKey adds a key to the resolver by key ID.
func (r *MockResolver) AddKey(keyID string, key jwk.Key) {
	r.keys[keyID] = key
}

// ExtractDIDFromKeyID extracts the DID from a key ID (DID URL).
func ExtractDIDFromKeyID(keyID string) string {
	// Key ID format: did:method:specific#fragment
	if idx := strings.Index(keyID, "#"); idx != -1 {
		return keyID[:idx]
	}
	return keyID
}

// MockKeyStore provides private key storage for tests.
type MockKeyStore struct {
	keys map[string]jwk.Key
}

// NewMockKeyStore creates a new mock key store.
func NewMockKeyStore() *MockKeyStore {
	return &MockKeyStore{
		keys: make(map[string]jwk.Key),
	}
}

// AddPrivateKey adds a private key to the store.
func (ks *MockKeyStore) AddPrivateKey(keyID string, key jwk.Key) {
	ks.keys[keyID] = key
}

// GetPrivateKey retrieves a private key by ID.
func (ks *MockKeyStore) GetPrivateKey(keyID string) (jwk.Key, error) {
	key, ok := ks.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("private key not found: %s", keyID)
	}
	return key, nil
}

// ListKeyIDs returns all key IDs in the store.
func (ks *MockKeyStore) ListKeyIDs() []string {
	var ids []string
	for id := range ks.keys {
		ids = append(ids, id)
	}
	return ids
}

// NewMockKeyStoreFromTestKeys creates a key store populated with test keys.
func NewMockKeyStoreFromTestKeys(keys *TestKeys, forDID string) *MockKeyStore {
	ks := NewMockKeyStore()

	switch forDID {
	case AliceDID:
		ks.AddPrivateKey(keys.AliceEdSign.KID, keys.AliceEdSign.PrivateJWK)
		ks.AddPrivateKey(keys.AliceX25519.KID, keys.AliceX25519.PrivateJWK)
		ks.AddPrivateKey(keys.AliceP256.KID, keys.AliceP256.PrivateJWK)
		ks.AddPrivateKey(keys.AliceP384.KID, keys.AliceP384.PrivateJWK)
	case BobDID:
		ks.AddPrivateKey(keys.BobEdSign.KID, keys.BobEdSign.PrivateJWK)
		ks.AddPrivateKey(keys.BobX25519.KID, keys.BobX25519.PrivateJWK)
		ks.AddPrivateKey(keys.BobP256.KID, keys.BobP256.PrivateJWK)
		ks.AddPrivateKey(keys.BobP384.KID, keys.BobP384.PrivateJWK)
	}

	return ks
}

// NewMockKeyStoreFromWellKnownKeys creates a key store from the DIDComm spec keys.
func NewMockKeyStoreFromWellKnownKeys(forDID string) (*MockKeyStore, error) {
	wellKnownKeys, err := LoadWellKnownKeys()
	if err != nil {
		return nil, err
	}

	ks := NewMockKeyStore()

	switch forDID {
	case AliceDID:
		ks.AddPrivateKey("did:example:alice#key-x25519-1", wellKnownKeys.AliceKeyAgreementX25519)
		ks.AddPrivateKey("did:example:alice#key-p256-1", wellKnownKeys.AliceKeyAgreementP256)
	case BobDID:
		ks.AddPrivateKey("did:example:bob#key-x25519-1", wellKnownKeys.BobKeyAgreementX25519)
		ks.AddPrivateKey("did:example:bob#key-p256-1", wellKnownKeys.BobKeyAgreementP256)
	}

	return ks, nil
}
