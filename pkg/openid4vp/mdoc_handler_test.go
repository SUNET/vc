package openid4vp

import (
	"encoding/base64"
	"testing"

	"vc/pkg/mdoc"

	"github.com/fxamacker/cbor/v2"
)

func TestNewMDocHandler(t *testing.T) {
	h, err := NewMDocHandler()
	if err != nil {
		t.Fatalf("NewMDocHandler() error = %v", err)
	}
	if h == nil {
		t.Fatal("NewMDocHandler() returned nil")
	}
	if h.verifier == nil {
		t.Error("verifier should not be nil")
	}
}

func TestNewMDocHandler_WithTrustList(t *testing.T) {
	trustList := mdoc.NewIACATrustList()

	h, err := NewMDocHandler(WithMDocTrustList(trustList))
	if err != nil {
		t.Fatalf("NewMDocHandler() error = %v", err)
	}
	if h.trustList != trustList {
		t.Error("trust list was not set correctly")
	}
}

func TestIsMDocFormat(t *testing.T) {
	tests := []struct {
		name    string
		vpToken string
		want    bool
	}{
		{
			name:    "JWT token (has dots)",
			vpToken: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			want:    false,
		},
		{
			name:    "Empty string",
			vpToken: "",
			want:    false,
		},
		{
			name:    "Invalid base64",
			vpToken: "!!!invalid!!!",
			want:    false,
		},
		{
			name:    "CBOR map (0xa0)",
			vpToken: base64.RawURLEncoding.EncodeToString([]byte{0xa0}),
			want:    true,
		},
		{
			name:    "CBOR array (0x80)",
			vpToken: base64.RawURLEncoding.EncodeToString([]byte{0x80}),
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsMDocFormat(tt.vpToken)
			if got != tt.want {
				t.Errorf("IsMDocFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractMDocClaims_InvalidToken(t *testing.T) {
	tests := []struct {
		name    string
		vpToken string
	}{
		{
			name:    "Empty token",
			vpToken: "",
		},
		{
			name:    "Invalid base64",
			vpToken: "!!!invalid!!!",
		},
		{
			name:    "Invalid CBOR",
			vpToken: base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xff}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractMDocClaims(tt.vpToken)
			if err == nil {
				t.Error("ExtractMDocClaims() should fail")
			}
		})
	}
}

func TestExtractMDocClaims_ValidToken(t *testing.T) {
	// Create a minimal DeviceResponse with test data
	deviceResponse := mdoc.DeviceResponse{
		Version: "1.0",
		Status:  0,
		Documents: []mdoc.Document{
			{
				DocType: mdoc.DocType,
				IssuerSigned: mdoc.IssuerSigned{
					NameSpaces: map[string][]mdoc.IssuerSignedItem{
						mdoc.Namespace: {
							{ElementIdentifier: "family_name", ElementValue: "Doe"},
							{ElementIdentifier: "given_name", ElementValue: "John"},
							{ElementIdentifier: "birth_date", ElementValue: "1990-01-15"},
						},
					},
				},
			},
		},
	}

	// Encode to CBOR
	data, err := cbor.Marshal(deviceResponse)
	if err != nil {
		t.Fatalf("Failed to encode DeviceResponse: %v", err)
	}

	vpToken := base64.RawURLEncoding.EncodeToString(data)

	claims, err := ExtractMDocClaims(vpToken)
	if err != nil {
		t.Fatalf("ExtractMDocClaims() error = %v", err)
	}

	// Check unqualified claims (from primary namespace)
	if claims["family_name"] != "Doe" {
		t.Errorf("family_name = %v, want Doe", claims["family_name"])
	}
	if claims["given_name"] != "John" {
		t.Errorf("given_name = %v, want John", claims["given_name"])
	}
	if claims["birth_date"] != "1990-01-15" {
		t.Errorf("birth_date = %v, want 1990-01-15", claims["birth_date"])
	}

	// Check qualified claims
	qualifiedKey := mdoc.Namespace + ".family_name"
	if claims[qualifiedKey] != "Doe" {
		t.Errorf("%s = %v, want Doe", qualifiedKey, claims[qualifiedKey])
	}
}

func TestMDocDocumentClaims_GetClaims(t *testing.T) {
	dc := &MDocDocumentClaims{
		DocType: mdoc.DocType,
		Namespaces: map[string]map[string]any{
			mdoc.Namespace: {
				"family_name": "Doe",
				"given_name":  "John",
			},
			"custom.namespace": {
				"custom_field": "custom_value",
			},
		},
	}

	claims := dc.GetClaims()

	// Unqualified claims from primary namespace
	if claims["family_name"] != "Doe" {
		t.Errorf("family_name = %v, want Doe", claims["family_name"])
	}

	// Qualified claims
	if claims[mdoc.Namespace+".family_name"] != "Doe" {
		t.Error("qualified family_name not found")
	}
	if claims["custom.namespace.custom_field"] != "custom_value" {
		t.Error("qualified custom_field not found")
	}
}

func TestMapMDocToOIDC(t *testing.T) {
	mdocClaims := map[string]any{
		"family_name":  "Doe",
		"given_name":   "John",
		"birth_date":   "1990-01-15",
		"sex":          1, // male
		"age_over_18":  true,
		"custom_claim": "custom_value",
	}

	oidcClaims := MapMDocToOIDC(mdocClaims)

	// Check standard mappings
	if oidcClaims["family_name"] != "Doe" {
		t.Errorf("family_name not mapped correctly")
	}
	if oidcClaims["birthdate"] != "1990-01-15" {
		t.Errorf("birth_date should be mapped to birthdate")
	}
	if oidcClaims["gender"] != 1 {
		t.Errorf("sex should be mapped to gender")
	}
	if oidcClaims["age_over_18"] != true {
		t.Errorf("age_over_18 should be passed through")
	}

	// Custom claims should pass through unchanged
	if oidcClaims["custom_claim"] != "custom_value" {
		t.Errorf("custom_claim should pass through unchanged")
	}
}

func TestMDocHandler_VerifyAndExtract_InvalidToken(t *testing.T) {
	h, _ := NewMDocHandler()

	tests := []struct {
		name    string
		vpToken string
	}{
		{
			name:    "Empty token",
			vpToken: "",
		},
		{
			name:    "Invalid base64",
			vpToken: "!!!invalid!!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.VerifyAndExtract(t.Context(), tt.vpToken)
			if err == nil {
				t.Error("VerifyAndExtract() should fail")
			}
		})
	}
}

func TestMDocVerificationResult_Documents(t *testing.T) {
	result := &MDocVerificationResult{
		Valid:     true,
		Documents: make(map[string]*MDocDocumentClaims),
	}

	result.Documents[mdoc.DocType] = &MDocDocumentClaims{
		DocType: mdoc.DocType,
		Namespaces: map[string]map[string]any{
			mdoc.Namespace: {
				"family_name": "Doe",
			},
		},
	}

	if !result.Valid {
		t.Error("result should be valid")
	}

	if len(result.Documents) != 1 {
		t.Errorf("expected 1 document, got %d", len(result.Documents))
	}

	doc, ok := result.Documents[mdoc.DocType]
	if !ok {
		t.Fatal("document not found")
	}

	claims := doc.GetClaims()
	if claims["family_name"] != "Doe" {
		t.Error("family_name not found in claims")
	}
}

func TestExtractMDocClaims_EmptyDocuments(t *testing.T) {
	// Create a DeviceResponse with no documents
	deviceResponse := mdoc.DeviceResponse{
		Version:   "1.0",
		Status:    0,
		Documents: []mdoc.Document{},
	}

	data, err := cbor.Marshal(deviceResponse)
	if err != nil {
		t.Fatalf("Failed to encode DeviceResponse: %v", err)
	}

	vpToken := base64.RawURLEncoding.EncodeToString(data)

	_, err = ExtractMDocClaims(vpToken)
	if err == nil {
		t.Error("ExtractMDocClaims() should fail for empty documents")
	}
}

func TestExtractMDocClaims_StandardBase64(t *testing.T) {
	// Test with standard base64 encoding (not URL-safe)
	deviceResponse := mdoc.DeviceResponse{
		Version: "1.0",
		Status:  0,
		Documents: []mdoc.Document{
			{
				DocType: mdoc.DocType,
				IssuerSigned: mdoc.IssuerSigned{
					NameSpaces: map[string][]mdoc.IssuerSignedItem{
						mdoc.Namespace: {
							{ElementIdentifier: "family_name", ElementValue: "Test"},
						},
					},
				},
			},
		},
	}

	data, err := cbor.Marshal(deviceResponse)
	if err != nil {
		t.Fatalf("Failed to encode DeviceResponse: %v", err)
	}

	// Use standard base64 (not URL-safe)
	vpToken := base64.StdEncoding.EncodeToString(data)

	claims, err := ExtractMDocClaims(vpToken)
	if err != nil {
		t.Fatalf("ExtractMDocClaims() with standard base64 error = %v", err)
	}

	if claims["family_name"] != "Test" {
		t.Errorf("family_name = %v, want Test", claims["family_name"])
	}
}
