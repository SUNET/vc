package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestToken_Parse_WithRealCredential(t *testing.T) {
	// Create a real SD-JWT credential for testing
	client := New()

	// Generate keys
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "base64url...",
		"y":   "base64url...",
		"kid": "holder-key-1",
	}

	vctm := &VCTM{
		VCT:  "https://example.com/credentials/test",
		Name: "Test Credential",
	}

	documentData := []byte(`{
		"given_name": "John",
		"family_name": "Doe",
		"birthdate": "1990-01-01"
	}`)

	// Build credential
	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(privateKey, "issuer-key-1")
	token, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		vctmRaw,
		documentData,
		holderJWK,
		&CredentialOptions{Integrity: integrity},
	)
	if err != nil {
		t.Fatalf("Failed to build credential: %v", err)
	}

	// Now parse it using Token.Parse()
	parsed, err := Token(token).Parse()
	if err != nil {
		t.Fatalf("Token.Parse() error = %v", err)
	}

	// Verify parsed structure
	if parsed == nil {
		t.Fatal("Token.Parse() returned nil ParsedCredential")
	}

	// Check claims
	if parsed.Claims == nil {
		t.Fatal("Claims is nil")
	}

	// Verify issuer
	if iss, ok := parsed.Claims["iss"].(string); !ok || iss != "https://issuer.example.com" {
		t.Errorf("Expected iss = https://issuer.example.com, got %v", parsed.Claims["iss"])
	}

	// Verify VCT (derived from VCTM)
	if vct, ok := parsed.Claims["vct"].(string); !ok || vct != "https://example.com/credentials/test" {
		t.Errorf("Expected vct = https://example.com/credentials/test, got %v", parsed.Claims["vct"])
	}

	// Verify disclosed claims are present
	if _, ok := parsed.Claims["given_name"]; !ok {
		t.Error("Expected given_name to be disclosed in claims")
	}
	if _, ok := parsed.Claims["family_name"]; !ok {
		t.Error("Expected family_name to be disclosed in claims")
	}
	if _, ok := parsed.Claims["birthdate"]; !ok {
		t.Error("Expected birthdate to be disclosed in claims")
	}

	// Verify disclosures array (may be 0 if all claims are in the JWT body)
	t.Logf("Number of selective disclosures: %d", len(parsed.Disclosures))

	// Verify header
	if parsed.Header == nil {
		t.Fatal("Header is nil")
	}

	if alg, ok := parsed.Header["alg"].(string); !ok || alg != "ES256" {
		t.Errorf("Expected alg = ES256, got %v", parsed.Header["alg"])
	}

	// Verify internal claims are removed
	if _, ok := parsed.Claims["_sd"]; ok {
		t.Error("Expected _sd to be removed from final claims")
	}
	if _, ok := parsed.Claims["_sd_alg"]; ok {
		t.Error("Expected _sd_alg to be removed from final claims")
	}

	// Verify signature is present
	if parsed.Signature == "" {
		t.Error("Expected signature to be present")
	}

	t.Logf("Successfully parsed credential with %d disclosures", len(parsed.Disclosures))
	t.Logf("Claims: %v", parsed.Claims)
}

func TestToken_Parse(t *testing.T) {
	tests := []struct {
		name              string
		token             string
		wantErr           bool
		expectedClaims    map[string]string // simplified for testing
		expectedDiscCount int
	}{
		{ // #nosec G101
			name: "valid SD-JWT with disclosures",
			// Valid SD-JWT with two properly-encoded disclosures and matching _sd hashes
			token:             "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCJ9.eyJfc2QiOiBbInpzMlZlaktUdWJRNHdlVHVBcUVmLUlmV1hGaHRTMXA0aFlIdE1VU183YmMiLCAiMEZYYjh2azRDSXJVN3EyaFpsUFhLdnlRaUs5N00ycUw4V3NieTEyMFl2VSJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20iLCAidmN0IjogInVybjpleGFtcGxlOnBpZCJ9.c2lnbmF0dXJl~WyJzYWx0MSIsICJnaXZlbl9uYW1lIiwgIkpvaG4iXQ~WyJzYWx0MiIsICJmYW1pbHlfbmFtZSIsICJEb2UiXQ~",
			wantErr:           false,
			expectedDiscCount: 2,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "invalid base64 header",
			token:   "invalid~~~",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Token(tt.token).Parse()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Token.Parse() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Token.Parse() unexpected error = %v", err)
				return
			}

			if parsed == nil {
				t.Error("Token.Parse() returned nil ParsedCredential")
				return
			}

			if len(parsed.Disclosures) != tt.expectedDiscCount {
				t.Errorf("Token.Parse() got %d disclosures, want %d", len(parsed.Disclosures), tt.expectedDiscCount)
			}

			if parsed.Claims == nil {
				t.Error("Token.Parse() Claims is nil")
			}

			if parsed.Header == nil {
				t.Error("Token.Parse() Header is nil")
			}
		})
	}
}

func TestParseSelectiveDisclosure(t *testing.T) {
	tests := []struct {
		name        string
		disclosures []string
		want        []Discloser
		wantErr     bool
		errContains string
	}{
		{
			name: "valid single disclosure - string value",
			// ["salt123", "given_name", "John"]
			disclosures: []string{"WyJzYWx0MTIzIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ"},
			want: []Discloser{
				{
					Salt:      "salt123",
					ClaimName: "given_name",
					Value:     "John",
					IsArray:   false,
				},
			},
			wantErr: false,
		},
		{
			name: "valid multiple disclosures",
			// ["salt1", "given_name", "John"], ["salt2", "family_name", "Doe"], ["salt3", "birthdate", "1990-01-01"]
			disclosures: []string{
				"WyJzYWx0MSIsImdpdmVuX25hbWUiLCJKb2huIl0",
				"WyJzYWx0MiIsImZhbWlseV9uYW1lIiwiRG9lIl0",
				"WyJzYWx0MyIsImJpcnRoZGF0ZSIsIjE5OTAtMDEtMDEiXQ",
			},
			want: []Discloser{
				{Salt: "salt1", ClaimName: "given_name", Value: "John", IsArray: false},
				{Salt: "salt2", ClaimName: "family_name", Value: "Doe", IsArray: false},
				{Salt: "salt3", ClaimName: "birthdate", Value: "1990-01-01", IsArray: false},
			},
			wantErr: false,
		},
		{
			name: "valid disclosure with number value",
			// ["salt456", "age", 30]
			disclosures: []string{"WyJzYWx0NDU2IiwiYWdlIiwzMF0"},
			want: []Discloser{
				{Salt: "salt456", ClaimName: "age", Value: float64(30), IsArray: false},
			},
			wantErr: false,
		},
		{
			name: "valid disclosure with boolean value",
			// ["salt789", "is_verified", true]
			disclosures: []string{"WyJzYWx0Nzg5IiwiaXNfdmVyaWZpZWQiLHRydWVd"},
			want: []Discloser{
				{Salt: "salt789", ClaimName: "is_verified", Value: true, IsArray: false},
			},
			wantErr: false,
		},
		{
			name: "valid disclosure with null value",
			// ["saltabc", "middle_name", null]
			disclosures: []string{"WyJzYWx0YWJjIiwibWlkZGxlX25hbWUiLG51bGxd"},
			want: []Discloser{
				{Salt: "saltabc", ClaimName: "middle_name", Value: nil, IsArray: false},
			},
			wantErr: false,
		},
		{
			name: "valid disclosure with object value",
			// ["saltxyz", "address", {"street": "123 Main St", "city": "Anytown"}]
			disclosures: []string{"WyJzYWx0eHl6IiwiYWRkcmVzcyIseyJzdHJlZXQiOiIxMjMgTWFpbiBTdCIsImNpdHkiOiJBbnl0b3duIn1d"},
			want: []Discloser{
				{
					Salt:      "saltxyz",
					ClaimName: "address",
					Value: map[string]any{
						"street": "123 Main St",
						"city":   "Anytown",
					},
					IsArray: false,
				},
			},
			wantErr: false,
		},
		{
			name: "valid disclosure with array value",
			// ["saltarr", "hobbies", ["reading", "coding", "hiking"]]
			disclosures: []string{"WyJzYWx0YXJyIiwiaG9iYmllcyIsWyJyZWFkaW5nIiwiY29kaW5nIiwiaGlraW5nIl1d"},
			want: []Discloser{
				{
					Salt:      "saltarr",
					ClaimName: "hobbies",
					Value:     []any{"reading", "coding", "hiking"},
					IsArray:   false,
				},
			},
			wantErr: false,
		},
		{
			name: "valid disclosure with empty array value",
			// ["saltempty", "items", []]
			disclosures: []string{"WyJzYWx0ZW1wdHkiLCJpdGVtcyIsW11d"},
			want: []Discloser{
				{Salt: "saltempty", ClaimName: "items", Value: []any{}, IsArray: false},
			},
			wantErr: false,
		},
		{
			name: "valid disclosure with mixed type array",
			// ["saltmixed", "data", [1, "text", true, null]]
			disclosures: []string{"WyJzYWx0bWl4ZWQiLCJkYXRhIixbMSwidGV4dCIsdHJ1ZSxudWxsXV0"},
			want: []Discloser{
				{
					Salt:      "saltmixed",
					ClaimName: "data",
					Value:     []any{float64(1), "text", true, nil},
					IsArray:   false,
				},
			},
			wantErr: false,
		},
		{
			name: "valid disclosure with nested array value",
			// ["saltnested", "matrix", [[1, 2], [3, 4]]]
			disclosures: []string{"WyJzYWx0bmVzdGVkIiwibWF0cml4IixbWzEsMl0sWzMsNF1dXQ"},
			want: []Discloser{
				{
					Salt:      "saltnested",
					ClaimName: "matrix",
					Value: []any{
						[]any{float64(1), float64(2)},
						[]any{float64(3), float64(4)},
					},
					IsArray: false,
				},
			},
			wantErr: false,
		},
		{
			name: "valid array element disclosure (2 elements)",
			// ["saltelem", "value123"]
			disclosures: []string{"WyJzYWx0ZWxlbSIsInZhbHVlMTIzIl0"},
			want: []Discloser{
				{Salt: "saltelem", ClaimName: "", Value: "value123", IsArray: true},
			},
			wantErr: false,
		},
		{
			name:        "empty disclosure array",
			disclosures: []string{},
			want:        []Discloser{},
			wantErr:     false,
		},
		{
			name:        "nil disclosure array",
			disclosures: nil,
			want:        nil,
			wantErr:     true,
			errContains: "selective disclosure array is nil",
		},
		{
			name:        "disclosure with empty string",
			disclosures: []string{""},
			want:        nil,
			wantErr:     true,
			errContains: "disclosure at index 0 is empty",
		},
		{
			name:        "invalid base64 encoding",
			disclosures: []string{"not-valid-base64!!!"},
			want:        nil,
			wantErr:     true,
			errContains: "failed to decode disclosure at index 0",
		},
		{
			name:        "valid base64 but not JSON",
			disclosures: []string{"bm90IGpzb24"}, // "not json" in base64
			want:        nil,
			wantErr:     true,
			errContains: "failed to unmarshal disclosure at index 0",
		},
		{
			name: "disclosure array too short (only 1 element)",
			// ["salt"] - missing claim_name and value
			disclosures: []string{"WyJzYWx0Il0"},
			want:        nil,
			wantErr:     true,
			errContains: "has invalid format: expected at least 2 elements, got 1",
		},
		{
			name: "disclosure with non-string claim name in object property",
			// [123, 456, "value"] - salt is number instead of string
			disclosures: []string{"WzEyMyw0NTYsInZhbHVlIl0"},
			want:        nil,
			wantErr:     true,
			errContains: "has invalid salt: expected string",
		},
		{
			name: "disclosure with non-string claim name (3 elements)",
			// ["salt", 456, "value"] - claim name is number, not string
			disclosures: []string{"WyJzYWx0Iiw0NTYsInZhbHVlIl0"},
			want:        nil,
			wantErr:     true,
			errContains: "has invalid claim name: expected string",
		},
		{
			name: "mixed valid and invalid disclosures",
			disclosures: []string{
				"WyJzYWx0MSIsImdpdmVuX25hbWUiLCJKb2huIl0", // valid
				"invalid-base64!!!",                       // invalid
			},
			want:        nil,
			wantErr:     true,
			errContains: "failed to decode disclosure at index 1",
		},
		{
			name: "disclosure with extra elements (should still work as object property)",
			// ["salt", "name", "John", "extra", "data"] - more than 3 elements
			disclosures: []string{"WyJzYWx0IiwibmFtZSIsIkpvaG4iLCJleHRyYSIsImRhdGEiXQ"},
			want: []Discloser{
				{Salt: "salt", ClaimName: "name", Value: "John", IsArray: false},
			},
			wantErr: false,
		},
		{
			name: "disclosure with empty string claim name",
			// ["salt", "", "value"]
			disclosures: []string{"WyJzYWx0IiwiIiwidmFsdWUiXQ"},
			want: []Discloser{
				{Salt: "salt", ClaimName: "", Value: "value", IsArray: false},
			},
			wantErr: false,
		},
		{
			name: "disclosure with special characters in claim name",
			// ["salt", "user.email@domain", "test@example.com"]
			disclosures: []string{"WyJzYWx0IiwidXNlci5lbWFpbEBkb21haW4iLCJ0ZXN0QGV4YW1wbGUuY29tIl0"},
			want: []Discloser{
				{Salt: "salt", ClaimName: "user.email@domain", Value: "test@example.com", IsArray: false},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSelectiveDisclosure(tt.disclosures)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSelectiveDisclosure() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errContains != "" {
					if !strings.Contains(err.Error(), tt.errContains) {
						t.Errorf("ParseSelectiveDisclosure() error = %v, want error containing %v", err, tt.errContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSelectiveDisclosure() unexpected error = %v", err)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ParseSelectiveDisclosure() got %d disclosers, want %d", len(got), len(tt.want))
				return
			}

			for i, wantDiscloser := range tt.want {
				gotDiscloser := got[i]

				if gotDiscloser.Salt != wantDiscloser.Salt {
					t.Errorf("ParseSelectiveDisclosure() discloser[%d].Salt = %v, want %v", i, gotDiscloser.Salt, wantDiscloser.Salt)
				}

				if gotDiscloser.ClaimName != wantDiscloser.ClaimName {
					t.Errorf("ParseSelectiveDisclosure() discloser[%d].ClaimName = %v, want %v", i, gotDiscloser.ClaimName, wantDiscloser.ClaimName)
				}

				if gotDiscloser.IsArray != wantDiscloser.IsArray {
					t.Errorf("ParseSelectiveDisclosure() discloser[%d].IsArray = %v, want %v", i, gotDiscloser.IsArray, wantDiscloser.IsArray)
				}

				// Deep comparison for Value field
				if !deepEqual(gotDiscloser.Value, wantDiscloser.Value) {
					t.Errorf("ParseSelectiveDisclosure() discloser[%d].Value = %v (%T), want %v (%T)",
						i, gotDiscloser.Value, gotDiscloser.Value, wantDiscloser.Value, wantDiscloser.Value)
				}
			}
		})
	}
}

// Helper function for deep equality comparison
func deepEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Handle maps
	aMap, aIsMap := a.(map[string]any)
	bMap, bIsMap := b.(map[string]any)
	if aIsMap && bIsMap {
		if len(aMap) != len(bMap) {
			return false
		}
		for k, v := range aMap {
			if !deepEqual(v, bMap[k]) {
				return false
			}
		}
		return true
	}

	// Handle slices
	aSlice, aIsSlice := a.([]any)
	bSlice, bIsSlice := b.([]any)
	if aIsSlice && bIsSlice {
		if len(aSlice) != len(bSlice) {
			return false
		}
		for i := range aSlice {
			if !deepEqual(aSlice[i], bSlice[i]) {
				return false
			}
		}
		return true
	}

	// For primitive types, use direct comparison
	return a == b
}

func TestToken_Split(t *testing.T) {
	tests := []struct {
		name                  string
		token                 string
		wantErr               bool
		expectedDisclosures   int
		expectedKeyBindingLen int
	}{
		{
			name:                  "token with disclosures and key binding",
			token:                 "header.payload.signature~disc1~disc2~kb.header.payload.signature",
			wantErr:               false,
			expectedDisclosures:   2,
			expectedKeyBindingLen: 4,
		},
		{
			name:                  "token with disclosures no key binding",
			token:                 "header.payload.signature~disc1~",
			wantErr:               false,
			expectedDisclosures:   1,
			expectedKeyBindingLen: 0,
		},
		{
			name:                "empty token",
			token:               "",
			wantErr:             true,
			expectedDisclosures: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, body, sig, disclosures, keyBinding, err := Token(tt.token).Split()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Token.Split() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Token.Split() unexpected error = %v", err)
				return
			}

			if header == "" || body == "" || sig == "" {
				t.Error("Token.Split() header, body, or signature is empty")
			}

			if len(disclosures) != tt.expectedDisclosures {
				t.Errorf("Token.Split() got %d disclosures, want %d", len(disclosures), tt.expectedDisclosures)
			}

			if len(keyBinding) != tt.expectedKeyBindingLen {
				t.Errorf("Token.Split() got %d key binding parts, want %d", len(keyBinding), tt.expectedKeyBindingLen)
			}
		})
	}
}

// makeDisclosure creates a base64url-encoded disclosure and its hash for testing.
func makeDisclosure(t *testing.T, parts ...any) (string, string) {
	t.Helper()
	raw, err := json.Marshal(parts)
	if err != nil {
		t.Fatalf("failed to marshal disclosure: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(encoded))
	hashB64 := base64.RawURLEncoding.EncodeToString(hash[:])
	return encoded, hashB64
}

func TestResolveDisclosuresRecursive_Nested(t *testing.T) {
	// Simulate place_of_birth with nested _sd
	discLocality, hashLocality := makeDisclosure(t, "salt1", "locality", "Stockholm")
	discRegion, hashRegion := makeDisclosure(t, "salt2", "region", "Stockholm")
	discPOB, hashPOB := makeDisclosure(t, "salt3", "place_of_birth", map[string]any{
		"_sd": []any{hashLocality, hashRegion},
	})

	claims := map[string]any{
		"iss":     "https://issuer.example.com",
		"_sd":     []any{hashPOB},
		"_sd_alg": "sha-256",
	}

	disclosures := []string{discLocality, discRegion, discPOB}

	err := resolveDisclosuresRecursive(claims, disclosures)
	if err != nil {
		t.Fatalf("resolveDisclosuresRecursive() error = %v", err)
	}

	// _sd removed at top level
	if _, ok := claims["_sd"]; ok {
		t.Error("Expected _sd to be removed from top level")
	}
	if _, ok := claims["_sd_alg"]; ok {
		t.Error("Expected _sd_alg to be removed from top level")
	}

	// place_of_birth resolved
	pob, ok := claims["place_of_birth"].(map[string]any)
	if !ok {
		t.Fatalf("Expected place_of_birth to be a map, got %T: %v", claims["place_of_birth"], claims["place_of_birth"])
	}

	if pob["locality"] != "Stockholm" {
		t.Errorf("Expected place_of_birth.locality = Stockholm, got %v", pob["locality"])
	}
	if pob["region"] != "Stockholm" {
		t.Errorf("Expected place_of_birth.region = Stockholm, got %v", pob["region"])
	}
	if _, ok := pob["_sd"]; ok {
		t.Error("Expected _sd to be removed from place_of_birth")
	}
}

func TestResolveDisclosuresRecursive_NestedAddress(t *testing.T) {
	// Address already present in JWT body but with _sd for sub-fields
	discStreet, hashStreet := makeDisclosure(t, "s1", "street_address", "Tulegatan")
	discPostal, hashPostal := makeDisclosure(t, "s2", "postal_code", "11353")
	discCountry, hashCountry := makeDisclosure(t, "s3", "country", "SE")

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"address": map[string]any{
			"_sd": []any{hashStreet, hashPostal, hashCountry},
		},
	}

	disclosures := []string{discStreet, discPostal, discCountry}

	err := resolveDisclosuresRecursive(claims, disclosures)
	if err != nil {
		t.Fatalf("resolveDisclosuresRecursive() error = %v", err)
	}

	addr, ok := claims["address"].(map[string]any)
	if !ok {
		t.Fatalf("Expected address to be a map, got %T", claims["address"])
	}
	if addr["street_address"] != "Tulegatan" {
		t.Errorf("Expected address.street_address = Tulegatan, got %v", addr["street_address"])
	}
	if addr["postal_code"] != "11353" {
		t.Errorf("Expected address.postal_code = 11353, got %v", addr["postal_code"])
	}
	if addr["country"] != "SE" {
		t.Errorf("Expected address.country = SE, got %v", addr["country"])
	}
	if _, ok := addr["_sd"]; ok {
		t.Error("Expected _sd to be removed from address")
	}
}

func TestResolveDisclosuresRecursive_ArrayElements(t *testing.T) {
	// Array element disclosures use {"...": hash} markers
	discElem1, hashElem1 := makeDisclosure(t, "s1", "SE")
	discElem2, hashElem2 := makeDisclosure(t, "s2", "EU")

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"nationalities": []any{
			map[string]any{"...": hashElem1},
			map[string]any{"...": hashElem2},
		},
	}

	disclosures := []string{discElem1, discElem2}

	err := resolveDisclosuresRecursive(claims, disclosures)
	if err != nil {
		t.Fatalf("resolveDisclosuresRecursive() error = %v", err)
	}

	nats, ok := claims["nationalities"].([]any)
	if !ok {
		t.Fatalf("Expected nationalities to be a slice, got %T", claims["nationalities"])
	}
	if len(nats) != 2 {
		t.Fatalf("Expected 2 elements, got %d", len(nats))
	}
	if nats[0] != "SE" {
		t.Errorf("Expected nationalities[0] = SE, got %v", nats[0])
	}
	if nats[1] != "EU" {
		t.Errorf("Expected nationalities[1] = EU, got %v", nats[1])
	}
}

func TestResolveDisclosuresRecursive_ArrayDisclosedViaParentSD(t *testing.T) {
	// This tests the real-world scenario where:
	// - "nationalities" is itself selectively disclosed at the top level (_sd)
	// - Its VALUE is an array containing element disclosure markers: [{"...": hash}]
	// - The element disclosures are also in the token
	// The resolution must:
	// 1. Resolve "nationalities" from top-level _sd
	// 2. Then resolve the array element markers inside its value

	// Create element disclosures first
	discElem1, hashElem1 := makeDisclosure(t, "elem_salt_1", "SE")
	discElem2, hashElem2 := makeDisclosure(t, "elem_salt_2", "FI")

	// Create the nationalities disclosure whose value contains element markers
	discNats, hashNats := makeDisclosure(t, "nats_salt", "nationalities", []any{
		map[string]any{"...": hashElem1},
		map[string]any{"...": hashElem2},
	})

	claims := map[string]any{
		"iss":     "https://issuer.example.com",
		"_sd":     []any{hashNats},
		"_sd_alg": "sha-256",
	}

	disclosures := []string{discNats, discElem1, discElem2}

	err := resolveDisclosuresRecursive(claims, disclosures)
	if err != nil {
		t.Fatalf("resolveDisclosuresRecursive() error = %v", err)
	}

	// nationalities should be resolved with element values
	nats, ok := claims["nationalities"].([]any)
	if !ok {
		t.Fatalf("Expected nationalities to be []any, got %T: %v", claims["nationalities"], claims["nationalities"])
	}
	if len(nats) != 2 {
		t.Fatalf("Expected 2 elements, got %d: %v", len(nats), nats)
	}
	if nats[0] != "SE" {
		t.Errorf("Expected nationalities[0] = SE, got %v", nats[0])
	}
	if nats[1] != "FI" {
		t.Errorf("Expected nationalities[1] = FI, got %v", nats[1])
	}
}

func TestResolveDisclosuresRecursive_DecoyHashes(t *testing.T) {
	// Decoy hashes are random hashes in _sd that don't correspond to any disclosure.
	// They exist to hide the number of actual selective disclosures.
	// These should be silently ignored.
	discName, hashName := makeDisclosure(t, "salt1", "given_name", "Helen")

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"_sd": []any{
			hashName,
			"decoy_hash_aaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"decoy_hash_bbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"decoy_hash_ccccccccccccccccccccccccccc",
		},
		"_sd_alg": "sha-256",
	}

	disclosures := []string{discName}

	err := resolveDisclosuresRecursive(claims, disclosures)
	if err != nil {
		t.Fatalf("resolveDisclosuresRecursive() error = %v", err)
	}

	// Only the real disclosure should be resolved
	if claims["given_name"] != "Helen" {
		t.Errorf("Expected given_name = Helen, got %v", claims["given_name"])
	}

	// No extra claims should appear from decoys
	for key := range claims {
		if key == "iss" || key == "given_name" {
			continue
		}
		t.Errorf("Unexpected claim %q in result (possible decoy leak)", key)
	}
}

func TestResolveDisclosuresRecursive_AttackerInjectedDisclosure(t *testing.T) {
	// Security test: An attacker appends their own disclosure to the SD-JWT token.
	// The injected disclosure's hash is NOT in the signed _sd array.
	// It MUST NOT appear in the resolved claims.
	discName, hashName := makeDisclosure(t, "legit_salt", "given_name", "Helen")

	// Attacker-crafted disclosure trying to inject "is_admin: true"
	attackerDisc, _ := makeDisclosure(t, "evil_salt", "is_admin", true)
	// Attacker also tries to inject an email override
	attackerDisc2, _ := makeDisclosure(t, "evil_salt2", "email", "attacker@evil.com")

	// The signed credential only has hashName in its _sd array
	claims := map[string]any{
		"iss":     "https://issuer.example.com",
		"_sd":     []any{hashName},
		"_sd_alg": "sha-256",
	}

	// Attacker appends their disclosures to the token
	disclosures := []string{discName, attackerDisc, attackerDisc2}

	err := resolveDisclosuresRecursive(claims, disclosures)
	if err != nil {
		t.Fatalf("resolveDisclosuresRecursive() error = %v", err)
	}

	// Legitimate disclosure should be resolved
	if claims["given_name"] != "Helen" {
		t.Errorf("Expected given_name = Helen, got %v", claims["given_name"])
	}

	// Attacker's injected claims MUST NOT appear
	if _, ok := claims["is_admin"]; ok {
		t.Error("SECURITY: attacker-injected 'is_admin' claim was resolved - disclosure hash not in signed _sd array")
	}
	if _, ok := claims["email"]; ok {
		t.Error("SECURITY: attacker-injected 'email' claim was resolved - disclosure hash not in signed _sd array")
	}
}

func TestResolveDisclosuresRecursive_AttackerInjectedNestedDisclosure(t *testing.T) {
	// Security test: Attacker injects a disclosure targeting a nested _sd array.
	// The nested _sd only contains the legitimate hash, not the attacker's.
	discStreet, hashStreet := makeDisclosure(t, "legit", "street_address", "Tulegatan")
	attackerDisc, _ := makeDisclosure(t, "evil", "admin_note", "pwned")

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"address": map[string]any{
			"_sd": []any{hashStreet}, // Only legitimate hash in signed payload
		},
	}

	// Attacker appends their disclosure
	disclosures := []string{discStreet, attackerDisc}

	err := resolveDisclosuresRecursive(claims, disclosures)
	if err != nil {
		t.Fatalf("resolveDisclosuresRecursive() error = %v", err)
	}

	addr, ok := claims["address"].(map[string]any)
	if !ok {
		t.Fatalf("Expected address to be a map, got %T", claims["address"])
	}

	// Legitimate claim present
	if addr["street_address"] != "Tulegatan" {
		t.Errorf("Expected address.street_address = Tulegatan, got %v", addr["street_address"])
	}

	// Attacker's claim MUST NOT appear
	if _, ok := addr["admin_note"]; ok {
		t.Error("SECURITY: attacker-injected 'admin_note' in nested object was resolved")
	}
}

func TestResolveDisclosuresRecursive_AttackerInjectedArrayElement(t *testing.T) {
	// Security test: Attacker tries to inject an extra array element disclosure.
	// Only markers in the signed array with valid hashes should be resolved.
	discElem1, hashElem1 := makeDisclosure(t, "legit_salt", "SE")
	attackerElem, attackerHash := makeDisclosure(t, "evil_salt", "ATTACKER_COUNTRY")

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"nationalities": []any{
			map[string]any{"...": hashElem1},
			// Note: no marker for attackerHash - the signed array doesn't include it
		},
	}

	// Attacker appends their disclosure
	disclosures := []string{discElem1, attackerElem}
	_ = attackerHash // not used in claims - that's the point

	err := resolveDisclosuresRecursive(claims, disclosures)
	if err != nil {
		t.Fatalf("resolveDisclosuresRecursive() error = %v", err)
	}

	nats, ok := claims["nationalities"].([]any)
	if !ok {
		t.Fatalf("Expected nationalities to be a slice, got %T", claims["nationalities"])
	}

	// Only 1 legitimate element
	if len(nats) != 1 {
		t.Errorf("Expected 1 element, got %d: %v", len(nats), nats)
	}
	if nats[0] != "SE" {
		t.Errorf("Expected nationalities[0] = SE, got %v", nats[0])
	}

	// Attacker's value MUST NOT appear anywhere
	for i, v := range nats {
		if v == "ATTACKER_COUNTRY" {
			t.Errorf("SECURITY: attacker-injected array element at index %d", i)
		}
	}
}

func TestTokenParse_AttackerAppendsUnsignedDisclosure(t *testing.T) {
	// End-to-end security test simulating the real attack:
	//
	// SD-JWT structure: <signed_jwt>~<disclosure1>~<disclosure2>~<kb-jwt>
	//
	// The disclosures after ~ are NOT signed. They are just base64url strings.
	// An attacker who intercepts the token can trivially append:
	//   ~<attacker_base64_disclosure>~
	// before the trailing key-binding JWT (or at the end if no KB).
	//
	// The ONLY protection is that the signed JWT body contains _sd hashes.
	// Only disclosures whose sha256 hash appears in the signed _sd array
	// should be accepted.

	client := New()

	// Generate issuer key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test_x",
		"y":   "test_y",
		"kid": "holder-1",
	}

	vctm := &VCTM{
		VCT:  "urn:example:pid:1",
		Name: "PID Credential",
	}

	documentData := []byte(`{
		"given_name": "Helen",
		"family_name": "Mirren"
	}`)

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(privateKey, "issuer-key-1")
	token, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		vctmRaw,
		documentData,
		holderJWK,
		&CredentialOptions{Integrity: integrity},
	)
	if err != nil {
		t.Fatalf("Failed to build credential: %v", err)
	}

	// Verify the legitimate token first
	parsed, err := Token(token).Parse()
	if err != nil {
		t.Fatalf("Token.Parse() failed on legitimate token: %v", err)
	}
	if parsed.Claims["given_name"] != "Helen" {
		t.Fatalf("Expected given_name=Helen in legitimate parse, got %v", parsed.Claims["given_name"])
	}

	// --- ATTACK: Append unsigned disclosure to the token ---
	// Craft a malicious disclosure: ["evil_salt", "is_admin", true]
	evilDisclosure, _ := json.Marshal([]any{"evil_salt_value", "is_admin", true})
	evilDiscB64 := base64.RawURLEncoding.EncodeToString(evilDisclosure)

	// Also try to override an existing claim
	overrideDisclosure, _ := json.Marshal([]any{"override_salt", "given_name", "ATTACKER"})
	overrideDiscB64 := base64.RawURLEncoding.EncodeToString(overrideDisclosure)

	// Append attacker disclosures to token.
	// Token format: <jwt>~<disc1>~...~<discN>~  (trailing ~ means no key binding)
	// We insert before the final empty segment
	attackerToken := strings.TrimSuffix(token, "~") + "~" + evilDiscB64 + "~" + overrideDiscB64 + "~"

	// Parse the tampered token
	parsedAttacked, err := Token(attackerToken).Parse()
	if err != nil {
		t.Fatalf("Token.Parse() error on attacked token: %v", err)
	}

	// SECURITY: Attacker's injected claim MUST NOT appear
	if _, ok := parsedAttacked.Claims["is_admin"]; ok {
		t.Error("SECURITY FAILURE: attacker-injected 'is_admin' claim was accepted from unsigned disclosure")
	}

	// SECURITY: Attacker cannot override legitimate claims
	if parsedAttacked.Claims["given_name"] == "ATTACKER" {
		t.Error("SECURITY FAILURE: attacker overrode 'given_name' via unsigned disclosure")
	}

	// Legitimate claims should still be present and correct
	if parsedAttacked.Claims["given_name"] != "Helen" {
		t.Errorf("Expected given_name=Helen after attack, got %v", parsedAttacked.Claims["given_name"])
	}
	if parsedAttacked.Claims["family_name"] != "Mirren" {
		t.Errorf("Expected family_name=Mirren after attack, got %v", parsedAttacked.Claims["family_name"])
	}

	t.Logf("Security check passed: %d disclosures in attacked token, none injected into claims",
		len(parsedAttacked.Disclosures))
}

func TestTokenParse_NationalitiesWithElementDisclosures(t *testing.T) {
	// Simulates the real-world scenario:
	// - JWT body has _sd containing hash of nationalities disclosure
	// - nationalities disclosure value = [{"...": elem_hash}]
	// - element disclosure = ["salt", "SE"]
	// - Both disclosures are in the token after ~
	// Token.Parse() must resolve both levels.

	// Step 1: Create element disclosure
	elemParts := []any{"elem_salt_1", "SE"}
	elemJSON, _ := json.Marshal(elemParts)
	elemB64 := base64.RawURLEncoding.EncodeToString(elemJSON)
	elemHash := sha256.Sum256([]byte(elemB64))
	elemHashB64 := base64.RawURLEncoding.EncodeToString(elemHash[:])

	// Step 2: Create nationalities disclosure with array marker
	natsParts := []any{"nats_salt", "nationalities", []any{
		map[string]any{"...": elemHashB64},
	}}
	natsJSON, _ := json.Marshal(natsParts)
	natsB64 := base64.RawURLEncoding.EncodeToString(natsJSON)
	natsHash := sha256.Sum256([]byte(natsB64))
	natsHashB64 := base64.RawURLEncoding.EncodeToString(natsHash[:])

	// Step 3: Create JWT body with _sd containing nationalities hash
	jwtBody := map[string]any{
		"iss":     "https://issuer.example.com",
		"vct":     "urn:eudi:pid:1",
		"_sd":     []any{natsHashB64},
		"_sd_alg": "sha-256",
	}
	bodyJSON, _ := json.Marshal(jwtBody)
	bodyB64 := base64.RawURLEncoding.EncodeToString(bodyJSON)

	// Step 4: Create a minimal JWT header
	header := map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Step 5: Assemble the token: header.body.sig~nats_disc~elem_disc~
	token := headerB64 + "." + bodyB64 + ".fake_sig~" + natsB64 + "~" + elemB64 + "~"

	// Step 6: Parse
	parsed, err := Token(token).Parse()
	if err != nil {
		t.Fatalf("Token.Parse() error = %v", err)
	}

	// Verify nationalities is resolved to ["SE"]
	nats, ok := parsed.Claims["nationalities"].([]any)
	if !ok {
		t.Fatalf("Expected nationalities to be []any, got %T: %v",
			parsed.Claims["nationalities"], parsed.Claims["nationalities"])
	}
	if len(nats) != 1 {
		t.Fatalf("Expected 1 element in nationalities, got %d: %v", len(nats), nats)
	}
	if nats[0] != "SE" {
		t.Errorf("Expected nationalities[0] = SE, got %v (type %T)", nats[0], nats[0])
	}

	// Verify no unresolved markers remain
	for _, elem := range nats {
		if m, ok := elem.(map[string]any); ok {
			if _, hasMarker := m["..."]; hasMarker {
				t.Error("Unresolved array element marker found in nationalities")
			}
		}
	}

	t.Logf("nationalities resolved: %v", nats)
}
