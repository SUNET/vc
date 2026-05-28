package mdoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/fxamacker/cbor/v2"
	"math/big"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/trust"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// deviceAuthMockTrustEvaluator is a mock TrustEvaluator for testing device auth
type deviceAuthMockTrustEvaluator struct {
	trusted  bool
	iacaCert *x509.Certificate
}

func (m *deviceAuthMockTrustEvaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trustapi.TrustDecision, error) {
	return &trustapi.TrustDecision{
		Trusted:        m.trusted,
		Reason:         "test decision",
		TrustFramework: "test-mock",
	}, nil
}

func (m *deviceAuthMockTrustEvaluator) SupportsKeyType(kt trust.KeyType) bool {
	return kt == trust.KeyTypeX5C
}

// createTestTrustEvaluatorFromIACA creates a mock TrustEvaluator that trusts credentials from the given IACA
func createTestTrustEvaluatorFromIACA(iacaCert *x509.Certificate) trust.TrustEvaluator {
	return &deviceAuthMockTrustEvaluator{trusted: true, iacaCert: iacaCert}
}

// createTestIACACert creates a test IACA root certificate for device auth tests
func createTestIACACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	iacaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate IACA key: %v", err)
	}

	iacaTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Test IACA"},
			CommonName:   "Test IACA Root",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	iacaCertDER, err := x509.CreateCertificate(rand.Reader, iacaTemplate, iacaTemplate, &iacaKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatalf("failed to create IACA certificate: %v", err)
	}

	iacaCert, err := x509.ParseCertificate(iacaCertDER)
	if err != nil {
		t.Fatalf("failed to parse IACA certificate: %v", err)
	}

	return iacaCert, iacaKey
}

// createTestDSCert creates a test Document Signer certificate signed by IACA
func createTestDSCert(t *testing.T, dsKey *ecdsa.PrivateKey, iacaCert *x509.Certificate, iacaKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	dsTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Test Issuer"},
			CommonName:   "Test Document Signer",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	dsCertDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, iacaCert, &dsKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatalf("failed to create DS certificate: %v", err)
	}

	dsCert, err := x509.ParseCertificate(dsCertDER)
	if err != nil {
		t.Fatalf("failed to parse DS certificate: %v", err)
	}

	return dsCert
}

// getEffectiveLength returns the length of the data regardless of its 
// container (raw bytes, any slice, or CBOR tag).
func getEffectiveLength(v any) int {
    if v == nil {
        return 0
    }

    switch val := v.(type) {
    case []byte:
        return len(val)
    case []any:
        return len(val)
    case cbor.Tag:
        // If it's a tag, we check the length of its content
        if content, ok := val.Content.([]byte); ok {
            return len(content)
        }
        if content, ok := val.Content.([]any); ok {
            return len(content)
        }
    }
    return 0
}

func TestNewDeviceAuthBuilder(t *testing.T) {
	builder := NewDeviceAuthBuilder(DocType)

	if builder == nil {
		t.Fatal("NewDeviceAuthBuilder() returned nil")
	}

	if builder.docType != DocType {
		t.Errorf("docType = %s, want %s", builder.docType, DocType)
	}
}

func TestDeviceAuthBuilder_WithSessionTranscript(t *testing.T) {
	builder := NewDeviceAuthBuilder(DocType)
	transcript := []byte("test session transcript")

	result := builder.WithSessionTranscript(transcript)

	if result != builder {
		t.Error("WithSessionTranscript() should return builder for chaining")
	}
	if string(builder.sessionTranscript) != string(transcript) {
		t.Error("sessionTranscript not set correctly")
	}
}

func TestDeviceAuthBuilder_WithDeviceKey(t *testing.T) {
	builder := NewDeviceAuthBuilder(DocType)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	result := builder.WithDeviceKey(key)

	if result != builder {
		t.Error("WithDeviceKey() should return builder for chaining")
	}
	if builder.deviceKey == nil {
		t.Error("deviceKey not set")
	}
	if builder.useMAC {
		t.Error("useMAC should be false for signature-based auth")
	}
}

func TestDeviceAuthBuilder_WithSessionKey(t *testing.T) {
	builder := NewDeviceAuthBuilder(DocType)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	result := builder.WithSessionKey(sessionKey)

	if result != builder {
		t.Error("WithSessionKey() should return builder for chaining")
	}
	if len(builder.sessionKey) != 32 {
		t.Error("sessionKey not set correctly")
	}
	if !builder.useMAC {
		t.Error("useMAC should be true for MAC-based auth")
	}
}

func TestDeviceAuthBuilder_AddDeviceNameSpace(t *testing.T) {
	builder := NewDeviceAuthBuilder(DocType)
	elements := map[string]any{
		"custom_element": "custom_value",
	}

	result := builder.AddDeviceNameSpace(Namespace, elements)

	if result != builder {
		t.Error("AddDeviceNameSpace() should return builder for chaining")
	}
	if builder.deviceNameSpaces[Namespace] == nil {
		t.Error("deviceNameSpaces not set")
	}
	if builder.deviceNameSpaces[Namespace]["custom_element"] != "custom_value" {
		t.Error("element not set correctly")
	}
}

func TestDeviceAuthBuilder_Build_Signature(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	transcript := []byte("test session transcript")

	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithDeviceKey(deviceKey)

	deviceSigned, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if deviceSigned == nil {
		t.Fatal("Build() returned nil")
	}

	// Fix for: invalid argument: deviceSigned.DeviceAuth.DeviceSignature (any) for len
	if deviceSigned.DeviceAuth.DeviceSignature == nil {
		t.Error("DeviceSignature should not be nil")
	} else {
		if getEffectiveLength(deviceSigned.DeviceAuth.DeviceSignature) == 0 {
			t.Error("DeviceSignature should contain data")
		}
	}
	// Ensure DeviceMac is empty/nil
	if deviceSigned.DeviceAuth.DeviceMac != nil {
		t.Error("DeviceMac should be nil for signature-based auth")
	}
    if getEffectiveLength(deviceSigned.NameSpaces) == 0 {
        t.Error("NameSpaces should be set and contain data")
    }
}

func TestDeviceAuthBuilder_Build_MAC(t *testing.T) {
    sessionKey := make([]byte, 32)
    rand.Read(sessionKey)

    transcript := []byte("test session transcript")

    builder := NewDeviceAuthBuilder(DocType).
        WithSessionTranscript(transcript).
        WithSessionKey(sessionKey)

    deviceSigned, err := builder.Build()
    if err != nil {
        t.Fatalf("Build() error = %v", err)
    }

    if deviceSigned == nil {
        t.Fatal("Build() returned nil")
    }

    // 1. DeviceMac is []byte: Use standard len()
    if len(deviceSigned.DeviceAuth.DeviceMac) == 0 {
        t.Error("DeviceMac should be set for MAC-based auth")
    }

    // 2. DeviceSignature is any: Check for nil
    // A nil interface means the field was not populated.
    if deviceSigned.DeviceAuth.DeviceSignature != nil {
        t.Errorf("DeviceSignature should be nil for MAC-based auth, got %T", deviceSigned.DeviceAuth.DeviceSignature)
    }
}

func TestDeviceAuthBuilder_Build_MissingTranscript(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	builder := NewDeviceAuthBuilder(DocType).
		WithDeviceKey(deviceKey)

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without session transcript")
	}
}

func TestDeviceAuthBuilder_Build_MissingKey(t *testing.T) {
	transcript := []byte("test session transcript")

	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript)

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without device key or session key")
	}
}

func TestDeviceAuthBuilder_Build_WithNameSpaces(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	transcript := []byte("test session transcript")

	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithDeviceKey(deviceKey).
		AddDeviceNameSpace(Namespace, map[string]any{
			"device_signed_element": "value",
		})

	deviceSigned, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if getEffectiveLength(deviceSigned.NameSpaces) == 0 {
		t.Error("NameSpaces should be set and contain data")
	}
}

func TestNewDeviceAuthVerifier(t *testing.T) {
	transcript := []byte("test session transcript")

	verifier := NewDeviceAuthVerifier(transcript, DocType)

	if verifier == nil {
		t.Fatal("NewDeviceAuthVerifier() returned nil")
	}
}

func TestDeviceAuthVerifier_VerifySignature(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	transcript := []byte("test session transcript")

	// Build device auth
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithDeviceKey(deviceKey)

	deviceSigned, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Verify
	verifier := NewDeviceAuthVerifier(transcript, DocType)
	err = verifier.VerifySignature(deviceSigned, &deviceKey.PublicKey)
	if err != nil {
		t.Errorf("VerifySignature() error = %v", err)
	}
}

func TestDeviceAuthVerifier_VerifySignature_WrongKey(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	transcript := []byte("test session transcript")

	// Build device auth
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithDeviceKey(deviceKey)

	deviceSigned, _ := builder.Build()

	// Verify with wrong key
	verifier := NewDeviceAuthVerifier(transcript, DocType)
	err := verifier.VerifySignature(deviceSigned, &wrongKey.PublicKey)
	if err == nil {
		t.Error("VerifySignature() should fail with wrong key")
	}
}

func TestDeviceAuthVerifier_VerifyMAC(t *testing.T) {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	transcript := []byte("test session transcript")

	// Build device auth with MAC
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithSessionKey(sessionKey)

	deviceSigned, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Verify
	verifier := NewDeviceAuthVerifier(transcript, DocType)
	err = verifier.VerifyMAC(deviceSigned, sessionKey)
	if err != nil {
		t.Errorf("VerifyMAC() error = %v", err)
	}
}

func TestDeviceAuthVerifier_VerifyMAC_WrongKey(t *testing.T) {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	transcript := []byte("test session transcript")

	// Build device auth with MAC
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithSessionKey(sessionKey)

	deviceSigned, _ := builder.Build()

	// Verify with wrong key
	verifier := NewDeviceAuthVerifier(transcript, DocType)
	err := verifier.VerifyMAC(deviceSigned, wrongKey)
	if err == nil {
		t.Error("VerifyMAC() should fail with wrong key")
	}
}

func TestDeviceAuthVerifier_VerifySignature_NoSignature(t *testing.T) {
	transcript := []byte("test session transcript")

	deviceSigned := &DeviceSignedMdoc{
		NameSpaces: []byte{},
		DeviceAuth: DeviceAuthMdoc{},
	}

	verifier := NewDeviceAuthVerifier(transcript, DocType)
	err := verifier.VerifySignature(deviceSigned, nil)
	if err == nil {
		t.Error("VerifySignature() should fail with no signature")
	}
}

func TestDeviceAuthVerifier_VerifyMAC_NoMAC(t *testing.T) {
	transcript := []byte("test session transcript")

	deviceSigned := &DeviceSignedMdoc{
		NameSpaces: []byte{},
		DeviceAuth: DeviceAuthMdoc{},
	}

	verifier := NewDeviceAuthVerifier(transcript, DocType)
	err := verifier.VerifyMAC(deviceSigned, []byte("key"))
	if err == nil {
		t.Error("VerifyMAC() should fail with no MAC")
	}
}

func TestExtractDeviceKeyFromMSO(t *testing.T) {
	// Create a device key
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create COSE key
	coseKey, err := NewCOSEKeyFromECDSA(&deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create COSE key: %v", err)
	}

	keyBytes, err := coseKey.Bytes()
	if err != nil {
		t.Fatalf("failed to encode COSE key: %v", err)
	}

	// Create MSO with device key
	mso := &MobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		DocType:         DocType,
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey: keyBytes,
		},
	}

	// Extract the key
	extractedKey, err := ExtractDeviceKeyFromMSO(mso)
	if err != nil {
		t.Fatalf("ExtractDeviceKeyFromMSO() error = %v", err)
	}

	// Verify it's an ECDSA key
	ecKey, ok := extractedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("ExtractDeviceKeyFromMSO() did not return ECDSA key")
	}

	// Verify the key matches
	if ecKey.X.Cmp(deviceKey.PublicKey.X) != 0 || ecKey.Y.Cmp(deviceKey.PublicKey.Y) != 0 {
		t.Error("ExtractDeviceKeyFromMSO() returned different key")
	}
}

func TestExtractDeviceKeyFromMSO_NilMSO(t *testing.T) {
	_, err := ExtractDeviceKeyFromMSO(nil)
	if err == nil {
		t.Error("ExtractDeviceKeyFromMSO() should fail with nil MSO")
	}
}

func TestExtractDeviceKeyFromMSO_NoDeviceKey(t *testing.T) {
	mso := &MobileSecurityObject{
		Version: "1.0",
	}

	_, err := ExtractDeviceKeyFromMSO(mso)
	if err == nil {
		t.Error("ExtractDeviceKeyFromMSO() should fail with no device key")
	}
}

func TestDeriveDeviceAuthenticationKey(t *testing.T) {
	// Create session encryption
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	readerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	transcript := []byte("test transcript")

	sessionEncryption, err := NewSessionEncryptionDevice(deviceKey, &readerKey.PublicKey, transcript)
	if err != nil {
		t.Fatalf("failed to create session encryption: %v", err)
	}

	// Derive device auth key
	authKey, err := DeriveDeviceAuthenticationKey(sessionEncryption)
	if err != nil {
		t.Fatalf("DeriveDeviceAuthenticationKey() error = %v", err)
	}

	if len(authKey) != 32 {
		t.Errorf("DeriveDeviceAuthenticationKey() key length = %d, want 32", len(authKey))
	}

	// Derive again - should be deterministic
	authKey2, _ := DeriveDeviceAuthenticationKey(sessionEncryption)
	if string(authKey) != string(authKey2) {
		t.Error("DeriveDeviceAuthenticationKey() should be deterministic")
	}
}

func TestDeriveDeviceAuthenticationKey_NilSession(t *testing.T) {
	_, err := DeriveDeviceAuthenticationKey(nil)
	if err == nil {
		t.Error("DeriveDeviceAuthenticationKey() should fail with nil session")
	}
}

func TestDeviceAuthBuilder_RoundTrip(t *testing.T) {
	// This test verifies the complete flow of building and verifying device auth
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	readerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Build session transcript
	transcript, err := BuildSessionTranscript(
		[]byte("device engagement"),
		[]byte("reader key"),
		nil,
	)
	if err != nil {
		t.Fatalf("BuildSessionTranscript() error = %v", err)
	}

	// Build device auth
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithDeviceKey(deviceKey).
		AddDeviceNameSpace(Namespace, map[string]any{
			"device_time": "2024-01-15T10:00:00Z",
		})

	deviceSigned, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Verify device auth
	verifier := NewDeviceAuthVerifier(transcript, DocType)
	err = verifier.VerifySignature(deviceSigned, &deviceKey.PublicKey)
	if err != nil {
		t.Errorf("VerifySignature() error = %v", err)
	}

	// Verify with wrong transcript should fail
	wrongTranscript, _ := BuildSessionTranscript(
		[]byte("different engagement"),
		[]byte("reader key"),
		nil,
	)
	wrongVerifier := NewDeviceAuthVerifier(wrongTranscript, DocType)
	err = wrongVerifier.VerifySignature(deviceSigned, &deviceKey.PublicKey)
	if err == nil {
		t.Error("VerifySignature() should fail with wrong transcript")
	}

	_ = readerKey // Silence unused warning
}

func TestVerifier_VerifyDeviceAuth_Signature(t *testing.T) {
	// Create keys
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate device key: %v", err)
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}

	// Create IACA certificate
	iacaCert, iacaKey := createTestIACACert(t)

	// Create Document Signer certificate signed by IACA
	dsCert := createTestDSCert(t, issuerKey, iacaCert, iacaKey)

	// Build session transcript
	transcript, err := BuildSessionTranscript(
		[]byte("device engagement"),
		[]byte("reader key"),
		nil,
	)
	if err != nil {
		t.Fatalf("BuildSessionTranscript() error = %v", err)
	}

	// Create device COSE key for MSO
	deviceCOSEKey, err := NewCOSEKeyFromECDSA(&deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create device COSE key: %v", err)
	}
	deviceKeyBytes, _ := deviceCOSEKey.Bytes()

	// Create MSO
	mso := &MobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		DocType:         DocType,
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey: deviceKeyBytes,
		},
		ValidityInfo: ValidityInfo{
			Signed:         time.Now(),
			ValidFrom:      time.Now().Add(-time.Hour),
			ValidUntil:     time.Now().Add(365 * 24 * time.Hour),
			ExpectedUpdate: nil,
		},
	}

	// Build device auth with signature
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithDeviceKey(deviceKey)

	deviceSigned, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Create Document
	doc := &DocumentMdoc{
		DocType:      DocType,
		DeviceSigned: *deviceSigned,
	}

	// Create verifier with trust list
	trustEvaluator := createTestTrustEvaluatorFromIACA(iacaCert)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	// Verify device auth
	err = verifier.VerifyDeviceAuth(doc, mso, transcript)
	if err != nil {
		t.Errorf("VerifyDeviceAuth() error = %v", err)
	}

	_ = dsCert // Used in full flow
}

func TestVerifier_VerifyDeviceAuth_NoDeviceAuth(t *testing.T) {
	// Create verifier
	iacaCert, _ := createTestIACACert(t)
	trustEvaluator := createTestTrustEvaluatorFromIACA(iacaCert)

	verifier, _ := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})

	// Create document without device auth
	doc := &DocumentMdoc{
		DocType: DocType,
		DeviceSigned: DeviceSignedMdoc{
			DeviceAuth: DeviceAuthMdoc{}, // Empty - no signature or MAC
		},
	}

	// Create minimal MSO
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := NewCOSEKeyFromECDSA(&deviceKey.PublicKey)
	deviceKeyBytes, _ := deviceCOSEKey.Bytes()

	mso := &MobileSecurityObject{
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey: deviceKeyBytes,
		},
	}

	transcript := []byte("transcript")

	// Should succeed (no device auth may be acceptable in some contexts)
	err := verifier.VerifyDeviceAuth(doc, mso, transcript)
	if err != nil {
		t.Errorf("VerifyDeviceAuth() with no device auth should not error = %v", err)
	}
}

func TestVerifier_VerifyDeviceAuth_WrongKey(t *testing.T) {
	// Create keys
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Build session transcript
	transcript, _ := BuildSessionTranscript(
		[]byte("device engagement"),
		[]byte("reader key"),
		nil,
	)

	// Create MSO with WRONG key (not the one used to sign)
	wrongCOSEKey, _ := NewCOSEKeyFromECDSA(&wrongKey.PublicKey)
	wrongKeyBytes, _ := wrongCOSEKey.Bytes()

	mso := &MobileSecurityObject{
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey: wrongKeyBytes,
		},
	}

	// Build device auth with original key
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithDeviceKey(deviceKey)

	deviceSigned, _ := builder.Build()

	// Create Document
	doc := &DocumentMdoc{
		DocType:      DocType,
		DeviceSigned: *deviceSigned,
	}

	// Create verifier
	iacaCert, _ := createTestIACACert(t)
	trustEvaluator := createTestTrustEvaluatorFromIACA(iacaCert)

	verifier, _ := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})

	// Should fail - device signed with different key than MSO declares
	err := verifier.VerifyDeviceAuth(doc, mso, transcript)
	if err == nil {
		t.Error("VerifyDeviceAuth() should fail when signature key doesn't match MSO device key")
	}
}

func TestVerifier_VerifyDeviceAuth_MACRequiresSessionKey(t *testing.T) {
	// Create keys
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	// Build session transcript
	transcript, _ := BuildSessionTranscript(
		[]byte("device engagement"),
		[]byte("reader key"),
		nil,
	)

	// Build device auth with MAC
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithSessionKey(sessionKey)

	deviceSigned, _ := builder.Build()

	// Create MSO
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := NewCOSEKeyFromECDSA(&deviceKey.PublicKey)
	deviceKeyBytes, _ := deviceCOSEKey.Bytes()

	mso := &MobileSecurityObject{
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey: deviceKeyBytes,
		},
	}

	// Create Document
	doc := &DocumentMdoc{
		DocType:      DocType,
		DeviceSigned: *deviceSigned,
	}

	// Create verifier
	iacaCert, _ := createTestIACACert(t)
	trustEvaluator := createTestTrustEvaluatorFromIACA(iacaCert)

	verifier, _ := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})

	// Should fail - MAC verification needs session key
	err := verifier.VerifyDeviceAuth(doc, mso, transcript)
	if err == nil {
		t.Error("VerifyDeviceAuth() with MAC should require session key")
	}
	if err.Error() != "MAC verification requires session key - use VerifyDeviceAuthWithSessionKey" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestVerifier_VerifyDeviceAuthWithSessionKey(t *testing.T) {
	// Create session key
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	// Build session transcript
	transcript, _ := BuildSessionTranscript(
		[]byte("device engagement"),
		[]byte("reader key"),
		nil,
	)

	// Build device auth with MAC
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithSessionKey(sessionKey)

	deviceSigned, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Create Document
	doc := &DocumentMdoc{
		DocType:      DocType,
		DeviceSigned: *deviceSigned,
	}

	// Create verifier
	iacaCert, _ := createTestIACACert(t)
	trustEvaluator := createTestTrustEvaluatorFromIACA(iacaCert)

	verifier, _ := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})

	// Verify with session key
	err = verifier.VerifyDeviceAuthWithSessionKey(doc, transcript, sessionKey)
	if err != nil {
		t.Errorf("VerifyDeviceAuthWithSessionKey() error = %v", err)
	}
}

func TestVerifier_VerifyDeviceAuthWithSessionKey_WrongKey(t *testing.T) {
	// Create session keys
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	// Build session transcript
	transcript, _ := BuildSessionTranscript(
		[]byte("device engagement"),
		[]byte("reader key"),
		nil,
	)

	// Build device auth with MAC
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithSessionKey(sessionKey)

	deviceSigned, _ := builder.Build()

	// Create Document
	doc := &DocumentMdoc{
		DocType:      DocType,
		DeviceSigned: *deviceSigned,
	}

	// Create verifier
	iacaCert, _ := createTestIACACert(t)
	trustEvaluator := createTestTrustEvaluatorFromIACA(iacaCert)

	verifier, _ := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})

	// Verify with wrong key - should fail
	err := verifier.VerifyDeviceAuthWithSessionKey(doc, transcript, wrongKey)
	if err == nil {
		t.Error("VerifyDeviceAuthWithSessionKey() should fail with wrong key")
	}
}

func TestVerifier_VerifyDeviceAuthWithSessionKey_NoMAC(t *testing.T) {
	// Create document with no MAC
	doc := &DocumentMdoc{
		DocType: DocType,
		DeviceSigned: DeviceSignedMdoc{
			DeviceAuth: DeviceAuthMdoc{}, // Empty - no MAC
		},
	}

	// Create verifier
	iacaCert, _ := createTestIACACert(t)
	trustEvaluator := createTestTrustEvaluatorFromIACA(iacaCert)

	verifier, _ := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})

	// Should fail - no MAC present
	err := verifier.VerifyDeviceAuthWithSessionKey(doc, []byte("transcript"), []byte("key"))
	if err == nil {
		t.Error("VerifyDeviceAuthWithSessionKey() should fail when no MAC present")
	}
}

func TestVerifier_VerifyDeviceAuth_InvalidDeviceKey(t *testing.T) {
	// Create device key for signing
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Build session transcript
	transcript, _ := BuildSessionTranscript(
		[]byte("device engagement"),
		[]byte("reader key"),
		nil,
	)

	// Create MSO with invalid device key bytes
	mso := &MobileSecurityObject{
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey: []byte{0x01, 0x02, 0x03}, // Invalid CBOR
		},
	}

	// Build device auth
	builder := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(transcript).
		WithDeviceKey(deviceKey)

	deviceSigned, _ := builder.Build()

	// Create Document
	doc := &DocumentMdoc{
		DocType:      DocType,
		DeviceSigned: *deviceSigned,
	}

	// Create verifier
	iacaCert, _ := createTestIACACert(t)
	trustEvaluator := createTestTrustEvaluatorFromIACA(iacaCert)

	verifier, _ := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})

	// Should fail - invalid device key in MSO
	err := verifier.VerifyDeviceAuth(doc, mso, transcript)
	
	if err == nil {
		t.Error("VerifyDeviceAuth() should fail with invalid device key")
	}
}
