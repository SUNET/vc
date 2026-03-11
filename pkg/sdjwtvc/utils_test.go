package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	vctURL, integrity := serveVCTM(t, vctm)
	signer := newTestSigner(privateKey, "issuer-key-1")
	token, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		vctURL,
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

	// Verify VCT (now the URL from the test server)
	if vct, ok := parsed.Claims["vct"].(string); !ok || vct != vctURL {
		t.Errorf("Expected vct = %s, got %v", vctURL, parsed.Claims["vct"])
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
		{
			name: "valid SD-JWT with disclosures",
			// This is a sample token - in real usage, this would be a valid SD-JWT
			token:             "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJfc2QiOlsiaGFzaDEiLCJoYXNoMiJdLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwidmN0IjoidXJuOmV4YW1wbGU6cGlkIn0.c2lnbmF0dXJl~disclosure1~disclosure2~",
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
