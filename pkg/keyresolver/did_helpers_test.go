package keyresolver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// Test DID constants to avoid duplication
const (
	testDIDWeb     = "did:web:example.com"
	testDIDContext = "https://www.w3.org/ns/did/v1"
	// Test vector X25519 public key (base64url-encoded)
	testX25519JWKx = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
)

// makeTestDIDDoc creates a basic DID document structure for testing
func makeTestDIDDoc(id string, vms []any) map[string]any {
	return map[string]any{
		"@context":           []string{testDIDContext},
		"id":                 id,
		"verificationMethod": vms,
	}
}

// makeTestDIDDocWithKA creates a DID document with keyAgreement section
func makeTestDIDDocWithKA(id string, vms []any, kas []any) map[string]any {
	doc := makeTestDIDDoc(id, vms)
	doc["keyAgreement"] = kas
	return doc
}

// makeTestX25519JWK creates a test X25519 JWK
func makeTestX25519JWK() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "X25519", "x": testX25519JWKx}
}

// makeTestVM creates a verification method for testing
func makeTestVM(id, vmType, controller string, keyData map[string]any) map[string]any {
	vm := map[string]any{
		"id":         id,
		"type":       vmType,
		"controller": controller,
	}
	for k, v := range keyData {
		vm[k] = v
	}
	return vm
}

func TestExtractEd25519FromMetadata_JWK(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	vm := makeTestVM(testDIDWeb+"#key-1", "JsonWebKey2020", testDIDWeb, map[string]any{
		"publicKeyJwk": Ed25519ToJWK(pubKey),
	})
	metadata := makeTestDIDDoc(testDIDWeb, []any{vm})

	extracted, err := ExtractEd25519FromMetadata(metadata, testDIDWeb+"#key-1")
	if err != nil {
		t.Fatalf("failed to extract key: %v", err)
	}

	if !pubKey.Equal(extracted) {
		t.Fatal("extracted key doesn't match original")
	}
}

func TestExtractEd25519FromMetadata_Multibase(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create multikey: 0xed (237) + 0x01 (prefix) + public key bytes
	multicodec := []byte{0xed, 0x01}
	multikeyBytes := append(multicodec, pubKey...)
	multikey := encodeMultibase(multikeyBytes)

	vm := makeTestVM(testDIDWeb+"#key-1", "Ed25519VerificationKey2020", testDIDWeb, map[string]any{
		"publicKeyMultibase": multikey,
	})
	metadata := makeTestDIDDoc(testDIDWeb, []any{vm})

	extracted, err := ExtractEd25519FromMetadata(metadata, testDIDWeb+"#key-1")
	if err != nil {
		t.Fatalf("failed to extract key: %v", err)
	}

	if !pubKey.Equal(extracted) {
		t.Fatal("extracted key doesn't match original")
	}
}

// encodeMultibase encodes bytes as base58-btc with 'z' prefix
func encodeMultibase(data []byte) string {
	// Simple base58-btc encoding for testing
	// In production, use github.com/multiformats/go-multibase
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := ""

	// Handle leading zeros
	for _, b := range data {
		if b != 0 {
			break
		}
		result += "1"
	}

	// Convert to base58
	x := make([]byte, len(data))
	copy(x, data)

	for len(x) > 0 {
		var carry int
		var newX []byte
		for _, b := range x {
			carry = carry*256 + int(b)
			if len(newX) > 0 || carry >= 58 {
				newX = append(newX, byte(carry/58))
			}
			carry = carry % 58
		}
		result = string(alphabet[carry]) + result
		x = newX
	}

	return "z" + result
}

func TestExtractEd25519FromMetadata_FragmentMatch(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Test when verification method ID is just a fragment
	vm := makeTestVM("#key-1", "JsonWebKey2020", testDIDWeb, map[string]any{
		"publicKeyJwk": Ed25519ToJWK(pubKey),
	})
	metadata := makeTestDIDDoc(testDIDWeb, []any{vm})

	extracted, err := ExtractEd25519FromMetadata(metadata, testDIDWeb+"#key-1")
	if err != nil {
		t.Fatalf("failed to extract key: %v", err)
	}

	if !pubKey.Equal(extracted) {
		t.Fatal("extracted key doesn't match original")
	}
}

func TestExtractEd25519FromMetadata_NotFound(t *testing.T) {
	vm := makeTestVM(testDIDWeb+"#other-key", "JsonWebKey2020", testDIDWeb, nil)
	metadata := makeTestDIDDoc(testDIDWeb, []any{vm})

	_, err := ExtractEd25519FromMetadata(metadata, testDIDWeb+"#key-1")
	if err == nil {
		t.Fatal("expected error when key not found")
	}
}

func TestExtractEd25519FromMetadata_InvalidFormat(t *testing.T) {
	_, err := ExtractEd25519FromMetadata("not a map", testDIDWeb+"#key-1")
	if err == nil {
		t.Fatal("expected error for invalid metadata format")
	}
}

func TestExtractEd25519FromMetadata_NoVerificationMethods(t *testing.T) {
	metadata := map[string]any{
		"@context": []string{testDIDContext},
		"id":       testDIDWeb,
	}

	_, err := ExtractEd25519FromMetadata(metadata, testDIDWeb+"#key-1")
	if err == nil {
		t.Fatal("expected error when no verification methods")
	}
}

func TestExtractEd25519FromMetadata_OpenIDFederation(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// OpenID Federation entity configuration format
	metadata := map[string]any{
		"iss": "https://op.example.com",
		"metadata": map[string]any{
			"openid_provider": map[string]any{
				"issuer": "https://op.example.com",
				"jwks": map[string]any{
					"keys": []any{
						map[string]any{
							"kid": "key-1",
							"kty": "OKP",
							"crv": "Ed25519",
							"x":   base64.RawURLEncoding.EncodeToString(pubKey),
						},
					},
				},
			},
		},
	}

	extracted, err := ExtractEd25519FromMetadata(metadata, "key-1")
	if err != nil {
		t.Fatalf("failed to extract key from OIDF entity config: %v", err)
	}

	if !pubKey.Equal(extracted) {
		t.Fatal("extracted key doesn't match original")
	}
}

func TestExtractDIDFromVerificationMethod(t *testing.T) {
	tests := []struct {
		vm       string
		expected string
	}{
		{"did:web:example.com#key-1", "did:web:example.com"},
		{"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
		{"did:web:example.com", "did:web:example.com"},
		{"#key-1", "#key-1"}, // Fragment-only returns as-is since no DID part
	}

	for _, tt := range tests {
		t.Run(tt.vm, func(t *testing.T) {
			got := ExtractDIDFromVerificationMethod(tt.vm)
			if got != tt.expected {
				t.Errorf("ExtractDIDFromVerificationMethod(%q) = %q, want %q", tt.vm, got, tt.expected)
			}
		})
	}
}

func TestExtractFragmentFromVerificationMethod(t *testing.T) {
	tests := []struct {
		vm       string
		expected string
	}{
		{"did:web:example.com#key-1", "key-1"},
		{"did:web:example.com#", ""},
		{"did:web:example.com", ""},
		{"#key-1", "key-1"},
	}

	for _, tt := range tests {
		t.Run(tt.vm, func(t *testing.T) {
			got := ExtractFragmentFromVerificationMethod(tt.vm)
			if got != tt.expected {
				t.Errorf("ExtractFragmentFromVerificationMethod(%q) = %q, want %q", tt.vm, got, tt.expected)
			}
		})
	}
}

func TestDecodeMultikeyEd25519_Valid(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create valid multikey
	multicodec := []byte{0xed, 0x01}
	multikeyBytes := append(multicodec, pubKey...)
	multikey := encodeMultibase(multikeyBytes)

	decoded, err := decodeMultikeyEd25519(multikey)
	if err != nil {
		t.Fatalf("failed to decode multikey: %v", err)
	}

	if !pubKey.Equal(decoded) {
		t.Fatal("decoded key doesn't match original")
	}
}

func TestDecodeMultikeyEd25519_Empty(t *testing.T) {
	_, err := decodeMultikeyEd25519("")
	if err == nil {
		t.Fatal("expected error for empty multikey")
	}
}

func TestDecodeMultikeyEd25519_WrongMulticodec(t *testing.T) {
	// Create multikey with wrong multicodec (P-256 instead of Ed25519)
	multicodec := []byte{0x80, 0x24} // P-256 multicodec
	multikeyBytes := append(multicodec, make([]byte, 33)...)
	multikey := encodeMultibase(multikeyBytes)

	_, err := decodeMultikeyEd25519(multikey)
	if err == nil {
		t.Fatal("expected error for wrong multicodec")
	}
}

func TestDecodeMultikeyEd25519_TooShort(t *testing.T) {
	multikey := encodeMultibase([]byte{0xed, 0x01})
	_, err := decodeMultikeyEd25519(multikey)
	if err == nil {
		t.Fatal("expected error for too short multikey")
	}
}

// Tests for X25519 key agreement extraction

func TestExtractX25519FromMetadata_JWK(t *testing.T) {
	ka := makeTestVM(testDIDWeb+"#key-x25519-1", "X25519KeyAgreementKey2020", testDIDWeb, map[string]any{
		"publicKeyJwk": makeTestX25519JWK(),
	})
	metadata := makeTestDIDDocWithKA(testDIDWeb, nil, []any{ka})

	key, err := ExtractX25519FromMetadata(metadata, testDIDWeb)
	if err != nil {
		t.Fatalf("failed to extract X25519 key: %v", err)
	}
	if key == nil {
		t.Fatal("extracted key is nil")
	}
}

func TestExtractX25519FromMetadata_Multibase(t *testing.T) {
	x25519Pub := make([]byte, 32)
	for i := range x25519Pub {
		x25519Pub[i] = byte(i + 1)
	}
	multicodec := []byte{0xec, 0x01}
	multikeyBytes := append(multicodec, x25519Pub...)
	multikey := encodeMultibase(multikeyBytes)

	ka := makeTestVM(testDIDWeb+"#key-x25519-1", "X25519KeyAgreementKey2020", testDIDWeb, map[string]any{
		"publicKeyMultibase": multikey,
	})
	metadata := makeTestDIDDocWithKA(testDIDWeb, nil, []any{ka})

	key, err := ExtractX25519FromMetadata(metadata, testDIDWeb)
	if err != nil {
		t.Fatalf("failed to extract X25519 key: %v", err)
	}
	if key == nil {
		t.Fatal("extracted key is nil")
	}
}

func TestExtractX25519FromMetadata_ReferenceResolution(t *testing.T) {
	vm := makeTestVM(testDIDWeb+"#key-x25519-1", "X25519KeyAgreementKey2020", testDIDWeb, map[string]any{
		"publicKeyJwk": makeTestX25519JWK(),
	})
	metadata := makeTestDIDDocWithKA(testDIDWeb, []any{vm}, []any{testDIDWeb + "#key-x25519-1"})

	key, err := ExtractX25519FromMetadata(metadata, testDIDWeb)
	if err != nil {
		t.Fatalf("failed to extract X25519 key via reference: %v", err)
	}
	if key == nil {
		t.Fatal("extracted key is nil")
	}
}

func TestExtractX25519FromMetadata_FragmentReference(t *testing.T) {
	vm := makeTestVM(testDIDWeb+"#key-x25519-1", "X25519KeyAgreementKey2020", testDIDWeb, map[string]any{
		"publicKeyJwk": makeTestX25519JWK(),
	})
	metadata := makeTestDIDDocWithKA(testDIDWeb, []any{vm}, []any{"#key-x25519-1"})

	key, err := ExtractX25519FromMetadata(metadata, testDIDWeb)
	if err != nil {
		t.Fatalf("failed to extract X25519 key via fragment reference: %v", err)
	}
	if key == nil {
		t.Fatal("extracted key is nil")
	}
}

// Tests for service resolution

func TestExtractServiceFromMetadata_String(t *testing.T) {
	metadata := map[string]any{
		"@context": []string{testDIDContext},
		"id":       testDIDWeb,
		"service": []any{
			map[string]any{
				"id":              testDIDWeb + "#didcomm-1",
				"type":            "DIDCommMessaging",
				"serviceEndpoint": "https://example.com/didcomm",
			},
		},
	}

	svc, err := ExtractServiceFromMetadata(metadata, testDIDWeb)
	if err != nil {
		t.Fatalf("failed to extract service: %v", err)
	}
	if svc.ServiceEndpoint != "https://example.com/didcomm" {
		t.Errorf("wrong endpoint: got %q, want %q", svc.ServiceEndpoint, "https://example.com/didcomm")
	}
}

func TestExtractServiceFromMetadata_Array(t *testing.T) {
	metadata := map[string]any{
		"@context": []string{testDIDContext},
		"id":       testDIDWeb,
		"service": []any{
			map[string]any{
				"id":   testDIDWeb + "#didcomm-1",
				"type": "DIDCommMessaging",
				"serviceEndpoint": []any{
					"https://example.com/didcomm",
					"https://backup.example.com/didcomm",
				},
			},
		},
	}

	svc, err := ExtractServiceFromMetadata(metadata, "did:web:example.com")
	if err != nil {
		t.Fatalf("failed to extract service: %v", err)
	}
	if svc.ServiceEndpoint != "https://example.com/didcomm" {
		t.Errorf("wrong endpoint: got %q, want %q", svc.ServiceEndpoint, "https://example.com/didcomm")
	}
}

func TestExtractServiceFromMetadata_Object(t *testing.T) {
	// Test serviceEndpoint as object with uri field
	metadata := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"service": []any{
			map[string]any{
				"id":   "did:web:example.com#didcomm-1",
				"type": "DIDCommMessaging",
				"serviceEndpoint": map[string]any{
					"uri":         "https://example.com/didcomm",
					"routingKeys": []any{"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
					"accept":      []any{"didcomm/v2"},
				},
			},
		},
	}

	svc, err := ExtractServiceFromMetadata(metadata, "did:web:example.com")
	if err != nil {
		t.Fatalf("failed to extract service: %v", err)
	}
	if svc.ServiceEndpoint != "https://example.com/didcomm" {
		t.Errorf("wrong endpoint: got %q, want %q", svc.ServiceEndpoint, "https://example.com/didcomm")
	}
	if len(svc.RoutingKeys) != 1 || svc.RoutingKeys[0] != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Errorf("wrong routing keys: %v", svc.RoutingKeys)
	}
	if len(svc.Accept) != 1 || svc.Accept[0] != "didcomm/v2" {
		t.Errorf("wrong accept: %v", svc.Accept)
	}
}

func TestExtractServiceFromMetadata_NotFound(t *testing.T) {
	metadata := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"service": []any{
			map[string]any{
				"id":              "did:web:example.com#linked-domain",
				"type":            "LinkedDomains",
				"serviceEndpoint": "https://example.com",
			},
		},
	}

	_, err := ExtractServiceFromMetadata(metadata, testDIDWeb)
	if err == nil {
		t.Fatal("expected error when DIDCommMessaging service not found")
	}
}

// Tests for resolveKeyAgreementRefs

func TestResolveKeyAgreementRefs_EmbeddedMethod(t *testing.T) {
	ka := makeTestVM(testDIDWeb+"#key-x25519-1", "X25519KeyAgreementKey2020", testDIDWeb, nil)
	doc := makeTestDIDDocWithKA(testDIDWeb, []any{}, []any{ka})

	kas, ok := doc["keyAgreement"].([]any)
	if !ok {
		t.Fatal("keyAgreement not found")
	}

	result, err := resolveKeyAgreementRefs(kas, doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
}

func TestResolveKeyAgreementRefs_FullIDReference(t *testing.T) {
	vm := makeTestVM(testDIDWeb+"#key-x25519-1", "X25519KeyAgreementKey2020", testDIDWeb, nil)
	doc := makeTestDIDDocWithKA(testDIDWeb, []any{vm}, []any{testDIDWeb + "#key-x25519-1"})

	kas := doc["keyAgreement"].([]any)
	result, err := resolveKeyAgreementRefs(kas, doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
}

func TestResolveKeyAgreementRefs_FragmentReference(t *testing.T) {
	vm := makeTestVM(testDIDWeb+"#key-x25519-1", "X25519KeyAgreementKey2020", testDIDWeb, nil)
	doc := makeTestDIDDocWithKA(testDIDWeb, []any{vm}, []any{"#key-x25519-1"})

	kas := doc["keyAgreement"].([]any)
	result, err := resolveKeyAgreementRefs(kas, doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
}

func TestResolveKeyAgreementRefs_FragmentOnlyVM(t *testing.T) {
	// Test when verification method ID is fragment-only but reference is full
	vm := makeTestVM("#key-x25519-1", "X25519KeyAgreementKey2020", testDIDWeb, nil)
	doc := makeTestDIDDocWithKA(testDIDWeb, []any{vm}, []any{testDIDWeb + "#key-x25519-1"})

	kas := doc["keyAgreement"].([]any)
	result, err := resolveKeyAgreementRefs(kas, doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
}
