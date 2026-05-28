package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	//"github.com/fxamacker/cbor/v2"
	"math/big"
	"testing"
	"time"
)

func createTestSignerAndCert(t *testing.T) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test DS"},
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

	return priv, []*x509.Certificate{cert}
}

func createTestDeviceKey(t *testing.T) *COSEKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	coseKey, err := NewCOSEKeyFromECDSA(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewCOSEKeyFromECDSA() error = %v", err)
	}

	return coseKey
}

func TestNewMSOBuilder(t *testing.T) {
	builder := NewMSOBuilder(DocType)

	if builder == nil {
		t.Fatal("NewMSOBuilder() returned nil")
	}
	if builder.docType != DocType {
		t.Errorf("docType = %s, want %s", builder.docType, DocType)
	}
	if builder.digestAlgorithm != DigestAlgorithmSHA256 {
		t.Errorf("digestAlgorithm = %s, want %s", builder.digestAlgorithm, DigestAlgorithmSHA256)
	}
}

func TestMSOBuilder_WithDigestAlgorithm(t *testing.T) {
	builder := NewMSOBuilder(DocType).
		WithDigestAlgorithm(DigestAlgorithmSHA384)

	if builder.digestAlgorithm != DigestAlgorithmSHA384 {
		t.Errorf("digestAlgorithm = %s, want %s", builder.digestAlgorithm, DigestAlgorithmSHA384)
	}
}

func TestMSOBuilder_WithValidity(t *testing.T) {
	now := time.Now()
	later := now.Add(365 * 24 * time.Hour)

	builder := NewMSOBuilder(DocType).
		WithValidity(now, later)

	if !builder.validFrom.Equal(now) {
		t.Errorf("validFrom = %v, want %v", builder.validFrom, now)
	}
	if !builder.validUntil.Equal(later) {
		t.Errorf("validUntil = %v, want %v", builder.validUntil, later)
	}
}

func TestMSOBuilder_WithDeviceKey(t *testing.T) {
	deviceKey := createTestDeviceKey(t)

	builder := NewMSOBuilder(DocType).
		WithDeviceKey(deviceKey)

	if builder.deviceKey != deviceKey {
		t.Error("deviceKey not set correctly")
	}
}

func TestMSOBuilder_AddDataElement(t *testing.T) {
	builder := NewMSOBuilder(DocType)

	if err := builder.AddDataElement(Namespace, "family_name", "Doe"); err != nil {
		t.Fatalf("AddDataElement() error = %v", err)
	}

	if len(builder.namespaces[Namespace]) != 1 {
		t.Errorf("expected 1 item, got %d", len(builder.namespaces[Namespace]))
	}

	item := builder.namespaces[Namespace][0]
	if item.ElementID != "family_name" {
		t.Errorf("ElementID = %s, want family_name", item.ElementID)
	}
	if item.ElementValue != "Doe" {
		t.Errorf("ElementValue = %v, want Doe", item.ElementValue)
	}
	if len(item.Random) != 32 {
		t.Errorf("Random length = %d, want 32", len(item.Random))
	}
}

func TestMSOBuilder_AddDataElementWithRandom(t *testing.T) {
	builder := NewMSOBuilder(DocType)

	customRandom := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if err := builder.AddDataElementWithRandom(Namespace, "given_name", "John", customRandom); err != nil {
		t.Fatalf("AddDataElementWithRandom() error = %v", err)
	}

	item := builder.namespaces[Namespace][0]
	if string(item.Random) != string(customRandom) {
		t.Error("Custom random not applied")
	}
}

func TestMSOBuilder_Build(t *testing.T) {
	priv, certChain := createTestSignerAndCert(t)
	deviceKey := createTestDeviceKey(t)

	now := time.Now()
	builder := NewMSOBuilder(DocType).
		WithDigestAlgorithm(DigestAlgorithmSHA256).
		WithValidity(now, now.Add(365*24*time.Hour)).
		WithDeviceKey(deviceKey).
		WithSigner(priv, certChain)

	// Add some data elements
	builder.AddDataElement(Namespace, "family_name", "Doe")       // #nosec G104
	builder.AddDataElement(Namespace, "given_name", "John")       // #nosec G104
	builder.AddDataElement(Namespace, "birth_date", "1990-01-15") // #nosec G104

	signedMSO, issuerNameSpaces, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if signedMSO == nil {
		t.Fatal("Build() returned nil signedMSO")
	}
	if issuerNameSpaces == nil {
		t.Fatal("Build() returned nil issuerNameSpaces")
	}

	// Verify namespace has items
	if len(issuerNameSpaces[Namespace]) != 3 {
		t.Errorf("expected 3 items in namespace, got %d", len(issuerNameSpaces[Namespace]))
	}
}

func TestMSOBuilder_Build_MissingSignerKey(t *testing.T) {
	deviceKey := createTestDeviceKey(t)

	builder := NewMSOBuilder(DocType).
		WithValidity(time.Now(), time.Now().Add(time.Hour)).
		WithDeviceKey(deviceKey)

	_, _, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without signer key")
	}
}

func TestMSOBuilder_Build_MissingDeviceKey(t *testing.T) {
	priv, certChain := createTestSignerAndCert(t)

	builder := NewMSOBuilder(DocType).
		WithValidity(time.Now(), time.Now().Add(time.Hour)).
		WithSigner(priv, certChain)

	_, _, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without device key")
	}
}

func TestMSOBuilder_Build_MissingValidity(t *testing.T) {
	priv, certChain := createTestSignerAndCert(t)
	deviceKey := createTestDeviceKey(t)

	builder := NewMSOBuilder(DocType).
		WithDeviceKey(deviceKey).
		WithSigner(priv, certChain)

	_, _, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without validity period")
	}
}

func TestVerifyMSO(t *testing.T) {
	priv, certChain := createTestSignerAndCert(t)
	deviceKey := createTestDeviceKey(t)

	now := time.Now()
	builder := NewMSOBuilder(DocType).
		WithValidity(now, now.Add(365*24*time.Hour)).
		WithDeviceKey(deviceKey).
		WithSigner(priv, certChain)

	builder.AddDataElement(Namespace, "family_name", "Doe") // #nosec G104

	signedMSO, _, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	mso, err := VerifyMSO(signedMSO, certChain[0])
	if err != nil {
		t.Fatalf("VerifyMSO() error = %v", err)
	}

	if mso == nil {
		t.Fatal("VerifyMSO() returned nil MSO")
	}
	if mso.Version != "1.0" {
		t.Errorf("Version = %s, want 1.0", mso.Version)
	}
	if mso.DocType != DocType {
		t.Errorf("DocType = %s, want %s", mso.DocType, DocType)
	}
}

func TestValidateMSOValidity(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name       string
		validFrom  time.Time
		validUntil time.Time
		wantError  bool
	}{
		{
			name:       "valid",
			validFrom:  now.Add(-time.Hour),
			validUntil: now.Add(time.Hour),
			wantError:  false,
		},
		{
			name:       "not yet valid",
			validFrom:  now.Add(time.Hour),
			validUntil: now.Add(2 * time.Hour),
			wantError:  true,
		},
		{
			name:       "expired",
			validFrom:  now.Add(-2 * time.Hour),
			validUntil: now.Add(-time.Hour),
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mso := &MobileSecurityObject{
				ValidityInfo: ValidityInfo{
					ValidFrom:  tt.validFrom,
					ValidUntil: tt.validUntil,
				},
			}

			err := ValidateMSOValidity(mso)
			if tt.wantError && err == nil {
				t.Error("ValidateMSOValidity() should return error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("ValidateMSOValidity() error = %v", err)
			}
		})
	}
}

func TestGetDigestIDs(t *testing.T) {
	mso := &MobileSecurityObject{
		ValueDigests: map[string]map[uint][]byte{
			Namespace: {
				0: []byte{1, 2, 3},
				2: []byte{4, 5, 6},
				1: []byte{7, 8, 9},
			},
		},
	}

	ids := GetDigestIDs(mso, Namespace)

	if len(ids) != 3 {
		t.Fatalf("GetDigestIDs() returned %d ids, want 3", len(ids))
	}

	// Should be sorted
	if ids[0] != 0 || ids[1] != 1 || ids[2] != 2 {
		t.Errorf("GetDigestIDs() not sorted: got %v", ids)
	}
}

func TestGetDigestIDs_UnknownNamespace(t *testing.T) {
	mso := &MobileSecurityObject{
		ValueDigests: map[string]map[uint][]byte{},
	}

	ids := GetDigestIDs(mso, "unknown.namespace")

	if ids != nil {
		t.Errorf("GetDigestIDs() should return nil for unknown namespace, got %v", ids)
	}
}

func TestGetMSOInfo(t *testing.T) {
	mso := &MobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: string(DigestAlgorithmSHA256),
		DocType:         DocType,
		ValidityInfo: ValidityInfo{
			Signed:     time.Now(),
			ValidFrom:  time.Now(),
			ValidUntil: time.Now().Add(time.Hour),
		},
		ValueDigests: map[string]map[uint][]byte{
			Namespace: {
				0: []byte{1},
				1: []byte{2},
			},
		},
	}

	info := GetMSOInfo(mso)

	if info.Version != "1.0" {
		t.Errorf("Version = %s, want 1.0", info.Version)
	}
	if info.DocType != DocType {
		t.Errorf("DocType = %s, want %s", info.DocType, DocType)
	}
	if info.DigestCount != 2 {
		t.Errorf("DigestCount = %d, want 2", info.DigestCount)
	}
	if len(info.Namespaces) != 1 {
		t.Errorf("Namespaces length = %d, want 1", len(info.Namespaces))
	}
}

func TestDigestAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		alg  DigestAlgorithm
	}{
		{"SHA-256", DigestAlgorithmSHA256},
		{"SHA-384", DigestAlgorithmSHA384},
		{"SHA-512", DigestAlgorithmSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, certChain := createTestSignerAndCert(t)
			deviceKey := createTestDeviceKey(t)

			now := time.Now()
			builder := NewMSOBuilder(DocType).
				WithDigestAlgorithm(tt.alg).
				WithValidity(now, now.Add(time.Hour)).
				WithDeviceKey(deviceKey).
				WithSigner(priv, certChain)

			builder.AddDataElement(Namespace, "test", "value") // #nosec G104

			_, _, err := builder.Build()
			if err != nil {
				t.Errorf("Build() with %s error = %v", tt.alg, err)
			}
		})
	}
}

func TestVerifyDigest(t *testing.T) {
	signerKey, signerCert := createTestSignerAndCert(t)
	deviceKey := createTestDeviceKey(t)

	now := time.Now()
	builder := NewMSOBuilder(DocType).
		WithDigestAlgorithm(DigestAlgorithmSHA256).
		WithValidity(now, now.AddDate(1, 0, 0)).
		WithDeviceKey(deviceKey).
		WithSigner(signerKey, signerCert)

	// Add some data elements
	builder.AddDataElement(Namespace, "family_name", "Andersson") // #nosec G104
	builder.AddDataElement(Namespace, "given_name", "Erik")       // #nosec G104
	builder.AddDataElement(Namespace, "birth_date", "1990-03-15") // #nosec G104

	signedMSO, issuerNameSpaces, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// First verify the MSO to get the MobileSecurityObject
	mso, err := VerifyMSO(signedMSO, signerCert[0])
	if err != nil {
		t.Fatalf("VerifyMSO() error = %v", err)
	}

	// Verify the issuer namespaces has items
	if len(issuerNameSpaces[Namespace]) != 3 {
		t.Errorf("Expected 3 items in namespace, got %d", len(issuerNameSpaces[Namespace]))
	}

	// Verify the MSO has the correct number of digest entries
	if len(mso.ValueDigests[Namespace]) != 3 {
		t.Errorf("Expected 3 digests in MSO, got %d", len(mso.ValueDigests[Namespace]))
	}

	// Decode TaggedCBOR to IssuerSignedItem and verify digest
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	issuerSignedNS := issuerNameSpaces
	for _, taggedItem := range issuerSignedNS[Namespace] {
        var item IssuerSignedItem
        encodedBytes, _ := taggedItem.Content.([]byte)
        if err := encoder.Unmarshal(encodedBytes, &item); err != nil {
            t.Fatalf("Unmarshal error = %v", err)
        }
        err := VerifyDigest(mso, Namespace, taggedItem) 
        if err != nil {
            t.Errorf("VerifyDigest() for %s error = %v", item.ElementIdentifier, err)
        }
    }
}

func TestVerifyDigest_InvalidItem(t *testing.T) {
	signerKey, signerCert := createTestSignerAndCert(t)
	deviceKey := createTestDeviceKey(t)

	now := time.Now()
	builder := NewMSOBuilder(DocType).
		WithDigestAlgorithm(DigestAlgorithmSHA256).
		WithValidity(now, now.AddDate(1, 0, 0)).
		WithDeviceKey(deviceKey).
		WithSigner(signerKey, signerCert)

	builder.AddDataElement(Namespace, "family_name", "Andersson") // #nosec G104

	signedMSO, _, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	mso, err := VerifyMSO(signedMSO, signerCert[0])
	if err != nil {
		t.Fatalf("VerifyMSO() error = %v", err)
	}

	// Create a fake item that was not in the MSO
	fakeItem := &IssuerSignedItem{
		DigestID:          999,
		Random:            []byte("random"),
		ElementIdentifier: "fake_element",
		ElementValue:      "fake_value",
	}

	err = VerifyDigest(mso, Namespace, fakeItem)
	if err == nil {
		t.Error("VerifyDigest() should fail for invalid item")
	}
}
