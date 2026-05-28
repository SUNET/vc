package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// boolPtr returns a pointer to a bool value.
//
//go:fix inline
func boolPtr(b bool) *bool {
	return new(b)
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

func createTestMDoc() *MDoc {
	return &MDoc{
		FamilyName:           "Andersson",
		GivenName:            "Erik",
		BirthDate:            "1990-03-15",
		IssueDate:            "2024-01-01",
		ExpiryDate:           "2034-01-01",
		IssuingCountry:       "SE",
		IssuingAuthority:     "Transportstyrelsen",
		DocumentNumber:       "SE1234567",
		Portrait:             []byte{0xFF, 0xD8, 0xFF}, // JPEG header
		DrivingPrivileges:    []DrivingPrivilege{{VehicleCategoryCode: "B"}},
		UNDistinguishingSign: "S",
	}
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

	mdoc := createTestMDoc()
	deviceKey, err := GenerateDeviceKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateDeviceKeyPair() error = %v", err)
	}

	req := &IssuanceRequest{
		MDoc:            mdoc,
		DevicePublicKey: &deviceKey.PublicKey,
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
}

func TestIssuer_Issue_MissingDeviceKey(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	mdoc := createTestMDoc()
	req := &IssuanceRequest{
		MDoc:            mdoc,
		DevicePublicKey: nil,
	}

	_, err := issuer.Issue(req)
	if err == nil {
		t.Error("Issue() should fail without device key")
	}
}

func TestIssuer_Issue_MissingMDoc(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	req := &IssuanceRequest{
		MDoc:            nil,
		DevicePublicKey: &deviceKey.PublicKey,
	}

	_, err := issuer.Issue(req)
	if err == nil {
		t.Error("Issue() should fail without MDoc")
	}
}

func TestIssuer_IssueBatch(t *testing.T) {
	config := createTestIssuerConfig(t)
	issuer, _ := NewIssuer(config)

	deviceKey1, _ := GenerateDeviceKeyPair(elliptic.P256())
	deviceKey2, _ := GenerateDeviceKeyPair(elliptic.P256())

	batch := BatchIssuanceRequest{
		Requests: []IssuanceRequest{
			{MDoc: createTestMDoc(), DevicePublicKey: &deviceKey1.PublicKey},
			{MDoc: createTestMDoc(), DevicePublicKey: &deviceKey2.PublicKey},
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
			{MDoc: createTestMDoc(), DevicePublicKey: &deviceKey.PublicKey},
			{MDoc: createTestMDoc(), DevicePublicKey: nil}, // Will fail
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

	mdoc := createTestMDoc()
	// Add optional elements with proper pointer types
	nationality := "SE"
	residentCity := "Stockholm"
	residentState := "Stockholms län"
	mdoc.Nationality = &nationality
	mdoc.ResidentCity = &residentCity
	mdoc.ResidentState = &residentState
	mdoc.AgeOver = &AgeOver{Over18: new(true), Over21: new(true)}

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	req := &IssuanceRequest{
		MDoc:            mdoc,
		DevicePublicKey: &deviceKey.PublicKey,
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

	mdoc := createTestMDoc()

	// Define string pointers for optional fields
	bIssue := "2020-01-01"
	bExpiry := "2030-01-01"
	aIssue := "2021-01-01"
	aExpiry := "2031-01-01"
	sign := "="
	value := "automatic"

	mdoc.DrivingPrivileges = []DrivingPrivilege{
		{
			VehicleCategoryCode: "B",
			IssueDate:           &bIssue,
			ExpiryDate:          &bExpiry,
		},
		{
			VehicleCategoryCode: "A",
			IssueDate:           &aIssue,
			ExpiryDate:          &aExpiry,
			Codes: []DrivingPrivilegeCode{
				{Code: "78", Sign: &sign, Value: &value},
			},
		},
	}

	deviceKey, _ := GenerateDeviceKeyPair(elliptic.P256())
	req := &IssuanceRequest{
		MDoc:            mdoc,
		DevicePublicKey: &deviceKey.PublicKey,
	}

	issued, err := issuer.Issue(req)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if issued == nil {
		t.Fatal("Issue() returned nil")
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
