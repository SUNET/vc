//go:build vc20

package keyresolver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestExtractEd25519FromMetadata_JWK(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	metadata := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":           "did:web:example.com#key-1",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": Ed25519ToJWK(pubKey),
			},
		},
	}

	extracted, err := ExtractEd25519FromMetadata(metadata, "did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to extract key: %v", err)
	}

	if !pubKey.Equal(extracted) {
		t.Fatal("extracted key doesn't match original")
	}
}

func TestExtractEd25519FromMetadata_Multibase(t *testing.T) {
	// Test with a known Ed25519 multikey
	// z6Mk... format: multibase(z) + multicodec(0xed01) + 32 bytes
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create multikey: 0xed (237) + 0x01 (prefix) + public key bytes
	multicodec := []byte{0xed, 0x01}
	multikeyBytes := append(multicodec, pubKey...)

	// Encode as base58-btc with 'z' prefix
	multikey := encodeMultibase(multikeyBytes)

	metadata := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":                 "did:web:example.com#key-1",
				"type":               "Ed25519VerificationKey2020",
				"controller":         "did:web:example.com",
				"publicKeyMultibase": multikey,
			},
		},
	}

	extracted, err := ExtractEd25519FromMetadata(metadata, "did:web:example.com#key-1")
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
	metadata := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":           "#key-1",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": Ed25519ToJWK(pubKey),
			},
		},
	}

	extracted, err := ExtractEd25519FromMetadata(metadata, "did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to extract key: %v", err)
	}

	if !pubKey.Equal(extracted) {
		t.Fatal("extracted key doesn't match original")
	}
}

func TestExtractEd25519FromMetadata_NotFound(t *testing.T) {
	metadata := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":   "did:web:example.com#other-key",
				"type": "JsonWebKey2020",
			},
		},
	}

	_, err := ExtractEd25519FromMetadata(metadata, "did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error when key not found")
	}
}

func TestExtractEd25519FromMetadata_InvalidFormat(t *testing.T) {
	_, err := ExtractEd25519FromMetadata("not a map", "did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error for invalid metadata format")
	}
}

func TestExtractEd25519FromMetadata_NoVerificationMethods(t *testing.T) {
	metadata := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
	}

	_, err := ExtractEd25519FromMetadata(metadata, "did:web:example.com#key-1")
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
	// Create multikey that's too short
	multikey := encodeMultibase([]byte{0xed, 0x01})

	_, err := decodeMultikeyEd25519(multikey)
	if err == nil {
		t.Fatal("expected error for too short multikey")
	}
}
