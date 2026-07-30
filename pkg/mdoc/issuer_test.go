package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// issuedElementValues extracts the disclosed element identifiers and values
// for a namespace from an issued document, unwrapping the Tag 24
// byte-string encoding used for each IssuerSignedItem.
func issuedElementValues(t *testing.T, doc *DocumentMdoc, namespace string) map[string]any {
	t.Helper()

	values := make(map[string]any)
	for _, anyItem := range doc.IssuerSigned.NameSpaces[namespace] {
		var item IssuerSignedItem
		switch v := anyItem.(type) {
		case cbor.Tag:
			content, ok := v.Content.([]byte)
			if !ok {
				t.Fatalf("Tag content is not []byte")
			}
			if err := cbor.Unmarshal(content, &item); err != nil {
				t.Fatalf("failed to unmarshal item from Tag: %v", err)
			}
		case IssuerSignedItem:
			item = v
		case *IssuerSignedItem:
			item = *v
		default:
			t.Fatalf("unexpected item type %T in NameSpaces", anyItem)
		}
		values[item.ElementIdentifier] = item.ElementValue
	}
	return values
}

func createTestIssuerConfig(t *testing.T) IssuerConfig {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test DS Certificate"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return IssuerConfig{
		SignerKey:        priv,
		CertificateChain: []*x509.Certificate{cert},
		DefaultValidity:  365 * 24 * time.Hour,
		DigestAlgorithm:  DigestAlgorithmSHA256,
	}
}

// testMDLSchema returns an MDDL schema shaped like an ISO 18013-5 mDL,
// including a mandatory driving_privileges array-of-records claim.
func testMDLSchema() *MDDLSchema {
	return &MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
		Claims: map[string]NamespaceClaims{
			"org.iso.18013.5.1": {
				"family_name":            {Mandatory: true, ValueType: "tstr"},
				"given_name":             {Mandatory: true, ValueType: "tstr"},
				"birth_date":             {Mandatory: true, ValueType: "full-date"},
				"issue_date":             {Mandatory: true, ValueType: "full-date"},
				"expiry_date":            {Mandatory: true, ValueType: "full-date"},
				"issuing_country":        {Mandatory: true, ValueType: "tstr"},
				"issuing_authority":      {Mandatory: true, ValueType: "tstr"},
				"document_number":        {Mandatory: true, ValueType: "tstr"},
				"portrait":               {Mandatory: true, ValueType: "bstr"},
				"driving_privileges":     {Mandatory: true, ValueType: "array"},
				"nationalities":          {ValueType: "array"},
				"height":                 {ValueType: "uint"},
				"age_over_18":            {ValueType: "bool"},
				"age_over_21":            {ValueType: "bool"},
				"age_over_65":            {ValueType: "bool"},
				"un_distinguishing_sign": {ValueType: "tstr"},
				"portrait_capture_date":  {ValueType: "tdate"},
				"pseudonym_seed":         {ValueType: "bstr"},
			},
		},
	}
}

// testMDLDocumentData returns raw JSON document data satisfying every
// mandatory claim in testMDLSchema, plus a few optional ones.
func testMDLDocumentData(t *testing.T) []byte {
	t.Helper()
	data := map[string]any{
		"family_name":       "Andersson",
		"given_name":        "Erik",
		"birth_date":        "1990-03-15",
		"issue_date":        "2024-01-01",
		"expiry_date":       "2034-01-01",
		"issuing_country":   "SE",
		"issuing_authority": "Transportstyrelsen",
		"document_number":   "SE1234567",
		"portrait":          base64.StdEncoding.EncodeToString([]byte{0xFF, 0xD8, 0xFF}),
		"driving_privileges": []map[string]any{
			{"vehicle_category_code": "B"},
		},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal test document data: %v", err)
	}
	return raw
}

// testPIDSchema returns an MDDL schema for a completely different doctype
// with none of mDL's fields, to demonstrate that Issue() has no
// doctype-specific branching: the same code path issues both.
func testPIDSchema() *MDDLSchema {
	return &MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "eu.europa.ec.eudi.pid.1",
		Claims: map[string]NamespaceClaims{
			"eu.europa.ec.eudi.pid.1": {
				"family_name":       {Mandatory: true, ValueType: "tstr"},
				"given_name":        {Mandatory: true, ValueType: "tstr"},
				"birth_date":        {Mandatory: true, ValueType: "full-date"},
				"issuing_country":   {Mandatory: true, ValueType: "tstr"},
				"issuing_authority": {Mandatory: true, ValueType: "tstr"},
				"nationalities":     {ValueType: "array"},
			},
		},
	}
}

func testPIDDocumentData(t *testing.T) []byte {
	t.Helper()
	data := map[string]any{
		"family_name":       "Andersson",
		"given_name":        "Erik",
		"birth_date":        "1990-03-15",
		"issuing_country":   "SE",
		"issuing_authority": "Skatteverket",
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal test document data: %v", err)
	}
	return raw
}

func TestNewIssuer(t *testing.T) {
	config := createTestIssuerConfig(t)

	issuer, err := NewIssuer(config)
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}

	if issuer == nil {
		t.Fatal("NewIssuer() returned nil")
	}
}

func TestNewIssuer_MissingSignerKey(t *testing.T) {
	config := IssuerConfig{
		CertificateChain: []*x509.Certificate{{}},
	}

	_, err := NewIssuer(config)
	if err == nil {
		t.Error("NewIssuer() should fail without signer key")
	}
}

func TestNewIssuer_MissingCertificate(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	config := IssuerConfig{
		SignerKey: priv,
	}

	_, err := NewIssuer(config)
	if err == nil {
		t.Error("NewIssuer() should fail without certificate")
	}
}

func TestNewIssuer_DefaultValidity(t *testing.T) {
	config := createTestIssuerConfig(t)
	config.DefaultValidity = 0 // Should use default

	issuer, err := NewIssuer(config)
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}

	if issuer.defaultValidity != 365*24*time.Hour {
		t.Errorf("defaultValidity = %v, want %v", issuer.defaultValidity, 365*24*time.Hour)
	}
}

func TestIssuer_Issue(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, err := NewIssuer(config)
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}

	deviceKey, err := GenerateDeviceKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateDeviceKeyPair() error = %v", err)
	}

	req := &IssuanceRequest{
		DocumentData:    testMDLDocumentData(t),
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          testMDLSchema(),
	}

	issued, err := issuer.Issue(req)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if issued == nil {
		t.Fatal("Issue() returned nil")
	}
	if issued.DocumentMdoc.Documents == nil {
		t.Error("Documents is nil")
	}
	if issued.SignedMSO == nil {
		t.Error("SignedMSO is nil")
	}
	if issued.ValidFrom.IsZero() {
		t.Error("ValidFrom is zero")
	}
	if issued.ValidUntil.IsZero() {
		t.Error("ValidUntil is zero")
	}

	// testMDLDocumentData() doesn't set age_over_18, so it must not appear -
	// addElements only adds a claim when the document data actually supplies
	// it, never a hardcoded/forced value.
	if len(issued.DocumentMdoc.Documents) != 1 {
		t.Fatalf("Documents = %d, want 1", len(issued.DocumentMdoc.Documents))
	}
	values := issuedElementValues(t, &issued.DocumentMdoc.Documents[0], Namespace)
	if _, ok := values["age_over_18"]; ok {
		t.Error("age_over_18 should not be disclosed when not present in document data")
	}
}

func TestIssuer_Issue_NilRequest(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	_, err := issuer.Issue(nil)
	if err == nil {
		t.Error("Issue(nil) should fail, not panic")
	}
}

func TestIssuer_Issue_AgeOverReflectsActualValue(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	data := map[string]any{
		"family_name":       "Andersson",
		"given_name":        "Erik",
		"birth_date":        "1990-03-15",
		"issue_date":        "2024-01-01",
		"expiry_date":       "2034-01-01",
		"issuing_country":   "SE",
		"issuing_authority": "Transportstyrelsen",
		"document_number":   "SE1234567",
		"portrait":          base64.StdEncoding.EncodeToString([]byte{0xFF, 0xD8, 0xFF}),
		"driving_privileges": []map[string]any{
			{"vehicle_category_code": "B"},
		},
		"age_over_18": false,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal test document data: %v", err)
	}

	deviceKey, err := GenerateDeviceKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateDeviceKeyPair() error = %v", err)
	}

	req := &IssuanceRequest{
		DocumentData:    raw,
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          testMDLSchema(),
	}

	issued, err := issuer.Issue(req)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	values := issuedElementValues(t, &issued.DocumentMdoc.Documents[0], Namespace)
	v, ok := values["age_over_18"]
	if !ok {
		t.Fatal("age_over_18 should be disclosed when present in document data")
	}
	if v != false {
		t.Errorf("age_over_18 = %v, want false (matching the supplied document data, not forced true)", v)
	}
}

func TestIssuer_Issue_MissingDeviceKey(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	req := &IssuanceRequest{
		DocumentData:    testMDLDocumentData(t),
		DevicePublicKey: nil,
		Schema:          testMDLSchema(),
	}

	_, err := issuer.Issue(req)
	if err == nil {
		t.Error("Issue() should fail without device key")
	}
}

func TestIssuer_Issue_MissingDocumentData(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	req := &IssuanceRequest{
		DocumentData:    nil,
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          testMDLSchema(),
	}

	_, err := issuer.Issue(req)
	if err == nil {
		t.Error("Issue() should fail without document data")
	}
}

func TestIssuer_Issue_MissingSchema(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	req := &IssuanceRequest{
		DocumentData:    testMDLDocumentData(t),
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          nil,
	}

	_, err := issuer.Issue(req)
	if err == nil {
		t.Error("Issue() should fail without a schema")
	}
}

func TestIssuer_Issue_MissingMandatoryClaim(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	doc, _ := json.Marshal(map[string]any{
		"given_name": "Erik", // "family_name" and other mandatory claims omitted
	})
	req := &IssuanceRequest{
		DocumentData:    doc,
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          testMDLSchema(),
	}

	_, err := issuer.Issue(req)
	if err == nil {
		t.Fatal("Issue() should fail when a mandatory claim is missing")
	}
}

func TestIssuer_Issue_PIDAndMDLSameCodePath(t *testing.T) {
	// PID and mDL share nothing but the generic addElements() pass over
	// whatever the schema declares — this exercises both doctypes through
	// Issue() to demonstrate there is no per-doctype branching left.
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	for _, tc := range []struct {
		name string
		doc  []byte
		schm *MDDLSchema
	}{
		{"mDL", testMDLDocumentData(t), testMDLSchema()},
		{"PID", testPIDDocumentData(t), testPIDSchema()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
			issued, err := issuer.Issue(&IssuanceRequest{
				DocumentData:    tc.doc,
				DevicePublicKey: &deviceKey.PublicKey,
				Schema:          tc.schm,
			})
			if err != nil {
				t.Fatalf("Issue() error = %v", err)
			}
			if len(issued.DocumentMdoc.Documents) != 1 {
				t.Fatalf("Documents = %d, want 1", len(issued.DocumentMdoc.Documents))
			}
			if issued.DocumentMdoc.Documents[0].DocType != tc.schm.DocType {
				t.Errorf("DocType = %q, want %q", issued.DocumentMdoc.Documents[0].DocType, tc.schm.DocType)
			}
		})
	}
}

func TestIssuer_IssueBatch(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	deviceKey1, _ := GenerateDeviceKeyPair(elliptic.P256())
	deviceKey2, _ := GenerateDeviceKeyPair(elliptic.P256())

	batch := BatchIssuanceRequest{
		Requests: []IssuanceRequest{
			{DocumentData: testMDLDocumentData(t), DevicePublicKey: &deviceKey1.PublicKey, Schema: testMDLSchema()},
			{DocumentData: testMDLDocumentData(t), DevicePublicKey: &deviceKey2.PublicKey, Schema: testMDLSchema()},
		},
	}

	result := issuer.IssueBatch(batch)

	if len(result.Issued) != 2 {
		t.Errorf("Issued count = %d, want 2", len(result.Issued))
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors = %v, want none", result.Errors)
	}
}

func TestIssuer_IssueBatch_PartialFailure(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())

	batch := BatchIssuanceRequest{
		Requests: []IssuanceRequest{
			{DocumentData: testMDLDocumentData(t), DevicePublicKey: &deviceKey.PublicKey, Schema: testMDLSchema()},
			{DocumentData: testMDLDocumentData(t), DevicePublicKey: nil, Schema: testMDLSchema()}, // Will fail
		},
	}

	result := issuer.IssueBatch(batch)

	if len(result.Issued) != 1 {
		t.Errorf("Issued count = %d, want 1", len(result.Issued))
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors count = %d, want 1", len(result.Errors))
	}
}

func TestGenerateDeviceKeyPair(t *testing.T) {
	priv, err := GenerateDeviceKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateDeviceKeyPair() error = %v", err)
	}

	if priv == nil {
		t.Error("PrivateKey is nil")
	}
	if priv.PublicKey.Curve != elliptic.P256() {
		t.Error("Expected P-256 curve")
	}
}

func TestParseDeviceKey(t *testing.T) {
	priv, err := GenerateDeviceKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateDeviceKeyPair() error = %v", err)
	}

	// Convert to COSE key bytes
	coseKey, err := NewCOSEKeyFromECDSA(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewCOSEKeyFromECDSA() error = %v", err)
	}

	keyBytes, err := coseKey.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}

	// Parse back
	parsedKey, err := ParseDeviceKey(keyBytes, "cose")
	if err != nil {
		t.Fatalf("ParseDeviceKey() error = %v", err)
	}

	parsedECDSA, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("ParseDeviceKey() did not return ECDSA key")
	}

	if priv.PublicKey.X.Cmp(parsedECDSA.X) != 0 || priv.PublicKey.Y.Cmp(parsedECDSA.Y) != 0 {
		t.Error("Parsed key doesn't match original")
	}
}

func TestNewCOSEKeyFromECDSAPublic(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	coseKey, err := NewCOSEKeyFromECDSAPublic(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewCOSEKeyFromECDSAPublic() error = %v", err)
	}

	if coseKey.Kty != KeyTypeEC2 {
		t.Errorf("Kty = %d, want %d", coseKey.Kty, KeyTypeEC2)
	}
	if coseKey.Crv != CurveP256 {
		t.Errorf("Crv = %d, want %d", coseKey.Crv, CurveP256)
	}
}

func TestNewCOSEKeyFromEd25519Public(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	coseKey, err := NewCOSEKeyFromEd25519Public(pub)
	if err != nil {
		t.Fatalf("NewCOSEKeyFromEd25519Public() error = %v", err)
	}

	if coseKey.Kty != KeyTypeOKP {
		t.Errorf("Kty = %d, want %d", coseKey.Kty, KeyTypeOKP)
	}
	if coseKey.Crv != CurveEd25519 {
		t.Errorf("Crv = %d, want %d", coseKey.Crv, CurveEd25519)
	}
}

func TestIssuer_OptionalElements(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	var data map[string]any
	if err := json.Unmarshal(testMDLDocumentData(t), &data); err != nil {
		t.Fatalf("unmarshal test document data: %v", err)
	}
	data["nationalities"] = []string{"SE"}
	data["height"] = 180
	data["age_over_18"] = true
	doc, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal test document data: %v", err)
	}

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	req := &IssuanceRequest{
		DocumentData:    doc,
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          testMDLSchema(),
	}

	issued, err := issuer.Issue(req)
	if err != nil {
		t.Fatalf("Issue() with optional elements error = %v", err)
	}

	if issued == nil {
		t.Fatal("Issue() returned nil")
	}
}

func TestIssuer_DrivingPrivileges(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	var data map[string]any
	if err := json.Unmarshal(testMDLDocumentData(t), &data); err != nil {
		t.Fatalf("unmarshal test document data: %v", err)
	}
	// driving_privileges is a mandatory "array" claim — it passes through
	// to CBOR unchanged, including nested structured records like "codes".
	data["driving_privileges"] = []map[string]any{
		{
			"vehicle_category_code": "B",
			"issue_date":            "2020-01-01",
			"expiry_date":           "2030-01-01",
		},
		{
			"vehicle_category_code": "A",
			"issue_date":            "2021-01-01",
			"expiry_date":           "2031-01-01",
			"codes": []map[string]any{
				{"code": "78", "sign": "=", "value": "automatic"},
			},
		},
	}
	doc, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal test document data: %v", err)
	}

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	req := &IssuanceRequest{
		DocumentData:    doc,
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          testMDLSchema(),
	}

	issued, err := issuer.Issue(req)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if issued == nil {
		t.Fatal("Issue() returned nil")
	}
}

func TestConvertElementValue(t *testing.T) {
	tests := []struct {
		name      string
		valueType string
		raw       any
		wantErr   bool
		check     func(t *testing.T, got any)
	}{
		{"full-date", "full-date", "2024-01-01", false, func(t *testing.T, got any) {
			if got != FullDate("2024-01-01") {
				t.Errorf("got %#v, want FullDate", got)
			}
		}},
		{"full-date wrong type", "full-date", 123.0, true, nil},
		{"tdate", "tdate", "2024-01-01T00:00:00Z", false, func(t *testing.T, got any) {
			if got != TDate("2024-01-01T00:00:00Z") {
				t.Errorf("got %#v, want TDate", got)
			}
		}},
		{"bstr base64 string", "bstr", base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), false, func(t *testing.T, got any) {
			b, ok := got.([]byte)
			if !ok || string(b) != string([]byte{1, 2, 3}) {
				t.Errorf("got %#v, want []byte{1,2,3}", got)
			}
		}},
		{"bstr invalid base64", "bstr", "not-base64!!", true, nil},
		{"uint", "uint", 42.0, false, func(t *testing.T, got any) {
			if got != uint64(42) {
				t.Errorf("got %#v, want uint64(42)", got)
			}
		}},
		{"int", "int", -5.0, false, func(t *testing.T, got any) {
			if got != int64(-5) {
				t.Errorf("got %#v, want int64(-5)", got)
			}
		}},
		{"passthrough tstr", "tstr", "hello", false, func(t *testing.T, got any) {
			if got != "hello" {
				t.Errorf("got %#v, want %q", got, "hello")
			}
		}},
		{"passthrough array", "array", []any{"a", "b"}, false, func(t *testing.T, got any) {
			arr, ok := got.([]any)
			if !ok || len(arr) != 2 {
				t.Errorf("got %#v, want a 2-element slice", got)
			}
		}},
		{"int rejects fractional value", "int", 5.5, true, nil},
		{"uint rejects fractional value", "uint", 5.5, true, nil},
		{"uint rejects negative value", "uint", -1.0, true, nil},
		{"int rejects out-of-range value", "int", math.MaxFloat64, true, nil},
		{"uint rejects out-of-range value", "uint", math.MaxFloat64, true, nil},
		{"int accepts large exact integer", "int", 9007199254740992.0, false, func(t *testing.T, got any) {
			if got != int64(9007199254740992) {
				t.Errorf("got %#v, want int64(9007199254740992)", got)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertElementValue(ClaimMetadata{ValueType: tt.valueType}, tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// TestConvertElementValue_NestedArraySchema verifies that an "array"
// value_type with a declared Elements schema (e.g. mDL's driving_privileges,
// which nests full-date issue_date/expiry_date fields and a further nested
// "codes" array) recursively converts each item's fields instead of passing
// the raw JSON values through unchanged.
func TestConvertElementValue_NestedArraySchema(t *testing.T) {
	meta := ClaimMetadata{
		ValueType: "array",
		Elements: map[string]ClaimMetadata{
			"vehicle_category_code": {Mandatory: true, ValueType: "tstr"},
			"issue_date":            {ValueType: "full-date"},
			"expiry_date":           {ValueType: "full-date"},
			"codes": {
				ValueType: "array",
				Elements: map[string]ClaimMetadata{
					"code":  {Mandatory: true, ValueType: "tstr"},
					"sign":  {ValueType: "tstr"},
					"value": {ValueType: "tstr"},
				},
			},
		},
	}

	raw := []any{
		map[string]any{
			"vehicle_category_code": "B",
			"issue_date":            "2024-01-01",
			"expiry_date":           "2034-01-01",
			"codes": []any{
				map[string]any{"code": "78"},
			},
		},
	}

	got, err := convertElementValue(meta, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	arr, ok := got.([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("got %#v, want a 1-element slice", got)
	}
	item, ok := arr[0].(map[string]any)
	if !ok {
		t.Fatalf("array item is %T, want map[string]any", arr[0])
	}
	if item["vehicle_category_code"] != "B" {
		t.Errorf("vehicle_category_code = %#v, want %q (tstr passthrough)", item["vehicle_category_code"], "B")
	}
	if item["issue_date"] != FullDate("2024-01-01") {
		t.Errorf("issue_date = %#v, want FullDate(\"2024-01-01\")", item["issue_date"])
	}
	if item["expiry_date"] != FullDate("2034-01-01") {
		t.Errorf("expiry_date = %#v, want FullDate(\"2034-01-01\")", item["expiry_date"])
	}

	codes, ok := item["codes"].([]any)
	if !ok || len(codes) != 1 {
		t.Fatalf("codes = %#v, want a 1-element slice", item["codes"])
	}
	code, ok := codes[0].(map[string]any)
	if !ok || code["code"] != "78" {
		t.Fatalf("codes[0] = %#v, want map with code=\"78\"", codes[0])
	}
}

func TestIssuer_InjectPseudonymSeed(t *testing.T) {
	config := createTestIssuerConfig(t)
	config.PseudonymSeed = true
	issuer, _ := NewIssuer(config)

	schema := testMDLSchema() // declares "pseudonym_seed" as an optional bstr claim
	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	req := &IssuanceRequest{
		DocumentData:    testMDLDocumentData(t),
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          schema,
	}

	issued, err := issuer.Issue(req)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if issued == nil {
		t.Fatal("Issue() returned nil")
	}

	// A schema that does NOT declare pseudonym_seed must not error even
	// though the issuer has the feature enabled — it's driven by the
	// schema, not by namespace/doctype.
	noSeedSchema := testPIDSchema()
	deviceKey2, _ := GenerateDeviceKeyPair(elliptic.P256())
	if _, err := issuer.Issue(&IssuanceRequest{
		DocumentData:    testPIDDocumentData(t),
		DevicePublicKey: &deviceKey2.PublicKey,
		Schema:          noSeedSchema,
	}); err != nil {
		t.Fatalf("Issue() without pseudonym_seed claim should succeed, got error = %v", err)
	}
}

func TestPublicKeyToCOSEKey_AllCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
		crv   int64
	}{
		{"P-256", elliptic.P256(), CurveP256},
		{"P-384", elliptic.P384(), CurveP384},
		{"P-521", elliptic.P521(), CurveP521},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, _ := ecdsa.GenerateKey(tc.curve, rand.Reader)
			coseKey, err := NewCOSEKeyFromECDSAPublic(&priv.PublicKey)
			if err != nil {
				t.Fatalf("NewCOSEKeyFromECDSAPublic() error = %v", err)
			}
			if coseKey.Crv != tc.crv {
				t.Errorf("Crv = %d, want %d", coseKey.Crv, tc.crv)
			}
		})
	}
}

func TestGenerateDeviceKeyPairEd25519(t *testing.T) {
	pub, priv, err := GenerateDeviceKeyPairEd25519()
	if err != nil {
		t.Fatalf("GenerateDeviceKeyPairEd25519() error = %v", err)
	}

	if pub == nil {
		t.Error("PublicKey is nil")
	}
	if priv == nil {
		t.Error("PrivateKey is nil")
	}

	// Verify key length
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("PublicKey length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestIssuer_GetInfo(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, err := NewIssuer(config)
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}

	info := issuer.GetInfo()

	if info.KeyAlgorithm != "ECDSA" {
		t.Errorf("KeyAlgorithm = %s, want ECDSA", info.KeyAlgorithm)
	}
	if info.CertChainLength != 1 {
		t.Errorf("CertChainLength = %d, want 1", info.CertChainLength)
	}
	if info.NotBefore.IsZero() {
		t.Error("NotBefore is zero")
	}
	if info.NotAfter.IsZero() {
		t.Error("NotAfter is zero")
	}
}

func TestIssuer_RevokeDocument(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	// RevokeDocument should return an error as it's not implemented
	err := issuer.RevokeDocument("SE1234567")
	if err == nil {
		t.Error("RevokeDocument() should return an error (not implemented)")
	}
}

func TestParseDeviceKey_X509(t *testing.T) {
	// Skip until x509 format is implemented in ParseDeviceKey
	t.Skip("ParseDeviceKey x509 format not yet implemented")

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Encode to DER
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}

	// Parse back as X.509
	parsedKey, err := ParseDeviceKey(pubDER, "x509")
	if err != nil {
		t.Fatalf("ParseDeviceKey(x509) error = %v", err)
	}

	parsedECDSA, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("ParseDeviceKey() did not return ECDSA key")
	}

	if priv.PublicKey.X.Cmp(parsedECDSA.X) != 0 || priv.PublicKey.Y.Cmp(parsedECDSA.Y) != 0 {
		t.Error("Parsed key doesn't match original")
	}
}

func TestParseDeviceKey_InvalidFormat(t *testing.T) {
	_, err := ParseDeviceKey([]byte("invalid"), "unknown")
	if err == nil {
		t.Error("ParseDeviceKey() should fail with unknown format")
	}
}

func TestConvertNameSpaces(t *testing.T) {
	// Create test TaggedCBOR data
	data1 := []byte{0x01, 0x02, 0x03}
	data2 := []byte{0x04, 0x05, 0x06}
	data3 := []byte{0x07, 0x08, 0x09}

	ins := IssuerNameSpaces{
		Namespace: {
			TaggedCBOR{Data: data1},
			TaggedCBOR{Data: data2},
		},
		"org.example.custom": {
			TaggedCBOR{Data: data3},
		},
	}

	result := convertNameSpaces(ins)

	// Verify the result structure
	if len(result) != 2 {
		t.Fatalf("convertNameSpaces() returned %d namespaces, want 2", len(result))
	}

	// Check main namespace
	mainNS, ok := result[Namespace]
	if !ok {
		t.Fatalf("convertNameSpaces() missing namespace %s", Namespace)
	}
	if len(mainNS) != 2 {
		t.Errorf("namespace %s has %d items, want 2", Namespace, len(mainNS))
	}
	if string(mainNS[0]) != string(data1) {
		t.Errorf("namespace[0] = %v, want %v", mainNS[0], data1)
	}
	if string(mainNS[1]) != string(data2) {
		t.Errorf("namespace[1] = %v, want %v", mainNS[1], data2)
	}

	// Check custom namespace
	customNS, ok := result["org.example.custom"]
	if !ok {
		t.Fatal("convertNameSpaces() missing namespace org.example.custom")
	}
	if len(customNS) != 1 {
		t.Errorf("custom namespace has %d items, want 1", len(customNS))
	}
	if string(customNS[0]) != string(data3) {
		t.Errorf("custom namespace[0] = %v, want %v", customNS[0], data3)
	}
}

func TestConvertNameSpaces_Empty(t *testing.T) {
	ins := IssuerNameSpaces{}

	result := convertNameSpaces(ins)

	if len(result) != 0 {
		t.Errorf("convertNameSpaces(empty) returned %d namespaces, want 0", len(result))
	}
}

func TestConvertNameSpaces_EmptyItems(t *testing.T) {
	ins := IssuerNameSpaces{
		Namespace: {}, // Empty slice
	}

	result := convertNameSpaces(ins)

	if len(result) != 1 {
		t.Fatalf("convertNameSpaces() returned %d namespaces, want 1", len(result))
	}

	mainNS := result[Namespace]
	if len(mainNS) != 0 {
		t.Errorf("namespace has %d items, want 0", len(mainNS))
	}
}
