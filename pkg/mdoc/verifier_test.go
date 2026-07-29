package mdoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/trust"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// mockTrustEvaluator is a test implementation of TrustEvaluator that always trusts certificates.
type mockTrustEvaluator struct {
	trusted bool
	reason  string
}

func (m *mockTrustEvaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trustapi.TrustDecision, error) {
	return &trustapi.TrustDecision{
		Trusted:        m.trusted,
		Reason:         m.reason,
		TrustFramework: "test-mock",
	}, nil
}

func (m *mockTrustEvaluator) SupportsKeyType(kt trust.KeyType) bool {
	return kt == trust.KeyTypeX5C
}

// createTestTrustEvaluator creates a mock TrustEvaluator for testing.
func createTestTrustEvaluator(trusted bool) trust.TrustEvaluator {
	return &mockTrustEvaluator{trusted: trusted, reason: "test decision"}
}

// recordingTrustEvaluator is a test TrustEvaluator that records the last
// EvaluationRequest it received, so tests can assert on how the caller
// (e.g. Verifier) populated fields like SubjectID.
type recordingTrustEvaluator struct {
	trusted bool
	lastReq *trust.EvaluationRequest
}

func (m *recordingTrustEvaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trustapi.TrustDecision, error) {
	m.lastReq = req
	return &trustapi.TrustDecision{
		Trusted:        m.trusted,
		Reason:         "test decision",
		TrustFramework: "test-mock",
	}, nil
}

func (m *recordingTrustEvaluator) SupportsKeyType(kt trust.KeyType) bool {
	return kt == trust.KeyTypeX5C
}

// createTestTrustListWithDS is like createTestTrustList but allows the caller
// to customize the DS certificate template (e.g. to add SANs) before it is
// signed.
func createTestTrustListWithDS(t *testing.T, mutateDS func(*x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()

	// Generate IACA key pair
	iacaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate IACA key: %v", err)
	}

	// Create IACA certificate
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

	// Generate DS key pair
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate DS key: %v", err)
	}

	// Create DS certificate
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

	if mutateDS != nil {
		mutateDS(dsTemplate)
	}

	dsCertDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, iacaCert, &dsKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatalf("failed to create DS certificate: %v", err)
	}

	dsCert, err := x509.ParseCertificate(dsCertDER)
	if err != nil {
		t.Fatalf("failed to parse DS certificate: %v", err)
	}

	return dsCert, dsKey, []*x509.Certificate{dsCert, iacaCert}
}

func createTestTrustList(t *testing.T) (trust.TrustEvaluator, *x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()

	trustEvaluator := createTestTrustEvaluator(true)
	dsCert, dsKey, certChain := createTestTrustListWithDS(t, nil)

	return trustEvaluator, dsCert, dsKey, certChain
}

func createTestDeviceResponse(t *testing.T, dsKey *ecdsa.PrivateKey, certChain []*x509.Certificate) *DeviceResponseMdoc {
	t.Helper()

	// Create issuer
	issuer, err := NewIssuer(IssuerConfig{
		SignerKey:        dsKey,
		CertificateChain: certChain,
		DefaultValidity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create issuer: %v", err)
	}

	// Create test mDL
	mdoc := &MDoc{
		FamilyName:           "Smith",
		GivenName:            "John",
		BirthDate:            "1990-03-15",
		IssueDate:            "2024-01-15",
		ExpiryDate:           "2034-01-15",
		IssuingCountry:       "SE",
		IssuingAuthority:     "Transportstyrelsen",
		DocumentNumber:       "DL123456789",
		Portrait:             []byte{0xFF, 0xD8, 0xFF, 0xE0},
		UNDistinguishingSign: "SE",
		DrivingPrivileges: []DrivingPrivilege{
			{VehicleCategoryCode: "B"},
		},
		AgeOver: &AgeOver{
			Over18: new(true),
			Over21: new(true),
			Over65: new(false),
		},
	}

	// Generate device key
	deviceKey, err := GenerateDeviceKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate device key: %v", err)
	}

	// Issue the mDL
	issued, err := issuer.Issue(&IssuanceRequest{
		MDoc:            mdoc,
		DevicePublicKey: &deviceKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("failed to issue mDL: %v", err)
	}
	// Build device response using the Document from issued
	return issued.DocumentMdoc
}

func TestNewVerifier(t *testing.T) {
	trustEvaluator := createTestTrustEvaluator(true)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator: trustEvaluator,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if verifier == nil {
		t.Fatal("NewVerifier() returned nil")
	}
}

func TestNewVerifierMissingTrustEvaluator(t *testing.T) {
	_, err := NewVerifier(VerifierConfig{})

	if err == nil {
		t.Fatal("NewVerifier() expected error for missing TrustEvaluator")
	}
}

func TestVerifier_VerifyDeviceResponse(t *testing.T) {
	trustEvaluator, dsCert, dsKey, certChain := createTestTrustList(t)
	_ = dsCert

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)

	result := verifier.VerifyDeviceResponse(response)

	if !result.Valid {
		t.Errorf("VerifyDeviceResponse() Valid = false, errors: %v", result.Errors)
		for _, doc := range result.Documents {
			t.Errorf("Document %s errors: %v", doc.DocType, doc.Errors)
		}
	}

	if len(result.Documents) != 1 {
		t.Errorf("VerifyDeviceResponse() Documents = %d, want 1", len(result.Documents))
	}
}

func TestVerifier_VerifyDocument(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)

	if len(response.Documents) == 0 {
		t.Fatal("expected at least one document in test response")
	}

	doc := &response.Documents[0]

	result := verifier.VerifyDocument(doc)

	if !result.Valid {
		t.Errorf("VerifyDocument() Valid = false, errors: %v", result.Errors)
	}

	if result.MSO == nil {
		t.Error("VerifyDocument() MSO is nil")
	}

	if result.IssuerCertificate == nil {
		t.Error("VerifyDocument() IssuerCertificate is nil")
	}

	if len(result.VerifiedElements) == 0 {
		t.Error("VerifyDocument() VerifiedElements is empty")
	}

	if _, ok := result.VerifiedElements[Namespace]; !ok {
		t.Errorf("VerifyDocument() missing namespace %s", Namespace)
	}
}

func TestVerifier_VerifyDocument_InvalidVersion(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)
	response.Version = "2.0"

	result := verifier.VerifyDeviceResponse(response)

	if result.Valid {
		t.Error("VerifyDeviceResponse() should fail for unsupported version")
	}
}

func TestVerifier_VerifyDocument_InvalidStatus(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)
	response.Status = 10

	result := verifier.VerifyDeviceResponse(response)

	if result.Valid {
		t.Error("VerifyDeviceResponse() should fail for non-zero status")
	}
}

func TestVerifier_VerifyDocument_DocumentErrors(t *testing.T) {
	trustEvaluator, _, _, _ := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	// 1. Manually build a response representing a protocol failure
	// According to the spec, an error response contains DocumentErrors and drops Documents
	response := &DeviceResponseMdoc{
		Version:   "1.0",
		Documents: nil, // Clear documents to simulate an unpresentable state
		DocumentErrors: []DocumentError{
			{
				DocType: 1, // 1 = Data Not Available / Generation Failure
			},
		},
		Status: 0, // Session status is fine, but the document itself failed
	}

	// 2. Execute verification
	result := verifier.VerifyDeviceResponse(response)

	// 3. Assertions
	if result.Valid {
		t.Error("VerifyDeviceResponse() should fail when DocumentErrors are present")
	}

	// Ensure our exact error message is surfaced in the result block
	if len(result.Errors) == 0 {
		t.Error("Expected error messages to be appended to result.Errors, but found none")
	}
}

func TestVerifier_UntrustedIssuer(t *testing.T) {
	// Create a TrustEvaluator that does NOT trust the issuer
	untrustedEvaluator := createTestTrustEvaluator(false)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      untrustedEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	// Create a response with an issuer that the evaluator doesn't trust
	_, _, dsKey, certChain := createTestTrustList(t)
	response := createTestDeviceResponse(t, dsKey, certChain)

	result := verifier.VerifyDeviceResponse(response)

	if result.Valid {
		t.Error("VerifyDeviceResponse() should fail for untrusted issuer")
	}
}

func TestVerificationResult_ExtractElements(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)
	result := verifier.VerifyDeviceResponse(response)

	elements := result.ExtractElements()

	if len(elements) == 0 {
		t.Error("ExtractElements() returned empty map")
	}

	if _, ok := elements[Namespace]; !ok {
		t.Errorf("ExtractElements() missing namespace %s", Namespace)
	}

	if _, ok := elements[Namespace]["family_name"]; !ok {
		t.Error("ExtractElements() missing family_name")
	}
}

func TestVerificationResult_GetElement(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)
	result := verifier.VerifyDeviceResponse(response)

	familyName, found := result.GetElement(Namespace, "family_name")
	if !found {
		t.Error("GetElement() family_name not found")
	}
	if familyName != "Smith" {
		t.Errorf("GetElement() family_name = %v, want Smith", familyName)
	}

	_, found = result.GetElement(Namespace, "nonexistent")
	if found {
		t.Error("GetElement() should return false for nonexistent element")
	}
}

func TestVerificationResult_GetMDocElements(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)
	result := verifier.VerifyDeviceResponse(response)

	elements := result.GetMDocElements()

	if len(elements) == 0 {
		t.Error("GetMDocElements() returned empty map")
	}

	if elements["family_name"] != "Smith" {
		t.Errorf("GetMDocElements() family_name = %v, want Smith", elements["family_name"])
	}

	if elements["given_name"] != "John" {
		t.Errorf("GetMDocElements() given_name = %v, want John", elements["given_name"])
	}
}

func TestVerificationResult_VerifyAgeOver(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)
	result := verifier.VerifyDeviceResponse(response)

	// Test age_over_18 (should be true)
	over18, found := result.VerifyAgeOver(18)
	if !found {
		t.Error("VerifyAgeOver(18) not found")
	}
	if !over18 {
		t.Error("VerifyAgeOver(18) should be true")
	}

	// Test age_over_21 (should be true)
	over21, found := result.VerifyAgeOver(21)
	if !found {
		t.Error("VerifyAgeOver(21) not found")
	}
	if !over21 {
		t.Error("VerifyAgeOver(21) should be true")
	}

	// Test age_over_65 (should be false)
	over65, found := result.VerifyAgeOver(65)
	if !found {
		t.Error("VerifyAgeOver(65) not found")
	}
	if over65 {
		t.Error("VerifyAgeOver(65) should be false")
	}

	// Test nonexistent age attestation
	_, found = result.VerifyAgeOver(99)
	if found {
		t.Error("VerifyAgeOver(99) should return false for missing attestation")
	}
}

func TestNewRequestBuilder(t *testing.T) {
	builder := NewRequestBuilder(DocType)

	if builder == nil {
		t.Fatal("NewRequestBuilder() returned nil")
	}

	if builder.docType != DocType {
		t.Errorf("NewRequestBuilder() docType = %s, want %s", builder.docType, DocType)
	}
}

func TestRequestBuilder_AddElement(t *testing.T) {
	builder := NewRequestBuilder(DocType)

	builder.AddElement(Namespace, "family_name", false)
	builder.AddElement(Namespace, "given_name", true)

	req := builder.Build()

	if req.DocType != DocType {
		t.Errorf("Build() DocType = %s, want %s", req.DocType, DocType)
	}

	if len(req.NameSpaces) != 1 {
		t.Errorf("Build() NameSpaces count = %d, want 1", len(req.NameSpaces))
	}

	if len(req.NameSpaces[Namespace]) != 2 {
		t.Errorf("Build() elements count = %d, want 2", len(req.NameSpaces[Namespace]))
	}

	if req.NameSpaces[Namespace]["family_name"] != false {
		t.Error("Build() family_name intentToRetain should be false")
	}

	if req.NameSpaces[Namespace]["given_name"] != true {
		t.Error("Build() given_name intentToRetain should be true")
	}
}

func TestRequestBuilder_AddMandatoryElements(t *testing.T) {
	builder := NewRequestBuilder(DocType)

	builder.AddMandatoryElements(false)

	req := builder.Build()

	mandatoryElements := []string{
		"family_name",
		"given_name",
		"birth_date",
		"issue_date",
		"expiry_date",
		"issuing_country",
		"issuing_authority",
		"document_number",
		"portrait",
		"driving_privileges",
		"un_distinguishing_sign",
	}

	for _, elem := range mandatoryElements {
		if _, ok := req.NameSpaces[Namespace][elem]; !ok {
			t.Errorf("Build() missing mandatory element: %s", elem)
		}
	}
}

func TestRequestBuilder_AddAgeVerification(t *testing.T) {
	builder := NewRequestBuilder(DocType)

	builder.AddAgeVerification(18, 21)

	req := builder.Build()

	if _, ok := req.NameSpaces[Namespace]["age_over_18"]; !ok {
		t.Error("Build() missing age_over_18")
	}

	if _, ok := req.NameSpaces[Namespace]["age_over_21"]; !ok {
		t.Error("Build() missing age_over_21")
	}
}

func TestRequestBuilder_WithRequestInfo(t *testing.T) {
	builder := NewRequestBuilder(DocType)

	builder.AddElement(Namespace, "family_name", false).
		WithRequestInfo("purpose", "age verification")

	req := builder.Build()

	if req.RequestInfo == nil {
		t.Fatal("Build() RequestInfo is nil")
	}

	if req.RequestInfo["purpose"] != "age verification" {
		t.Errorf("Build() RequestInfo[purpose] = %v, want 'age verification'", req.RequestInfo["purpose"])
	}
}

func TestRequestBuilder_BuildEncoded(t *testing.T) {
	builder := NewRequestBuilder(DocType)

	builder.AddElement(Namespace, "family_name", false)

	encoded, err := builder.BuildEncoded()
	if err != nil {
		t.Fatalf("BuildEncoded() error = %v", err)
	}

	if len(encoded) == 0 {
		t.Error("BuildEncoded() returned empty bytes")
	}

	// Verify we can decode it
	encoder, _ := NewCBOREncoder()
	var decoded ItemsRequest
	if err := encoder.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if decoded.DocType != DocType {
		t.Errorf("decoded DocType = %s, want %s", decoded.DocType, DocType)
	}
}

func TestRequestBuilder_BuildDeviceRequest(t *testing.T) {
	builder := NewRequestBuilder(DocType)

	builder.AddElement(Namespace, "family_name", false)

	req, err := builder.BuildDeviceRequest()
	if err != nil {
		t.Fatalf("BuildDeviceRequest() error = %v", err)
	}

	if req.Version != "1.0" {
		t.Errorf("BuildDeviceRequest() Version = %s, want 1.0", req.Version)
	}

	if len(req.DocRequests) != 1 {
		t.Errorf("BuildDeviceRequest() DocRequests count = %d, want 1", len(req.DocRequests))
	}

	if len(req.DocRequests[0].ItemsRequest) == 0 {
		t.Error("BuildDeviceRequest() ItemsRequest is empty")
	}
}

func TestVerifier_VerifyIssuerSigned(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)

	if len(response.Documents) == 0 {
		t.Fatal("expected at least one document in response")
	}

	doc := &response.Documents[0]

	mso, elements, err := verifier.VerifyIssuerSigned(&doc.IssuerSigned, doc.DocType)
	if err != nil {
		t.Fatalf("VerifyIssuerSigned() error = %v", err)
	}

	if mso == nil {
		t.Error("VerifyIssuerSigned() MSO is nil")
	}

	if len(elements) == 0 {
		t.Error("VerifyIssuerSigned() elements is empty")
	}

	if val, ok := elements[Namespace]["family_name"]; !ok || val != "Smith" {
		t.Errorf("VerifyIssuerSigned() family_name = %v, want Smith", val)
	}
}

func TestVerifier_WithCustomClock(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)

	futureClock := func() time.Time {
		return time.Now().Add(50 * 365 * 24 * time.Hour)
	}

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
		Clock:               futureClock,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)

	result := verifier.VerifyDeviceResponse(response)

	// Should fail because certificate is expired
	if result.Valid {
		t.Error("VerifyDeviceResponse() should fail with expired certificate")
	}
}

func TestVerifier_ConfiguredIssuerURLOverridesCertificateSAN(t *testing.T) {
	// The DS certificate carries its own URI SAN, but the Verifier is
	// configured with an explicit IssuerURL. The configured IssuerURL must
	// win, per the documented priority: configured IssuerURL > certificate
	// URI SAN > certificate Organization.
	const certURI = "https://cert-issuer.example.com"
	const configuredIssuerURL = "https://configured-issuer.example.com"

	dsCert, dsKey, certChain := createTestTrustListWithDS(t, func(tmpl *x509.Certificate) {
		tmpl.URIs = []*url.URL{{Scheme: "https", Host: "cert-issuer.example.com"}}
	})
	_ = dsCert

	recorder := &recordingTrustEvaluator{trusted: true}

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      recorder,
		IssuerURL:           configuredIssuerURL,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)

	result := verifier.VerifyDeviceResponse(response)
	if !result.Valid {
		t.Fatalf("VerifyDeviceResponse() Valid = false, errors: %v", result.Errors)
	}

	if recorder.lastReq == nil {
		t.Fatal("expected TrustEvaluator.Evaluate to be called")
	}

	if got := recorder.lastReq.SubjectID; got != configuredIssuerURL {
		t.Errorf("SubjectID = %q, want configured IssuerURL %q (cert URI SAN was %q)", got, configuredIssuerURL, certURI)
	}
}

func TestVerifier_IssuerURLExtractedFromCertificateSANWhenNotConfigured(t *testing.T) {
	// When no IssuerURL is configured on the Verifier, the issuer identifier
	// used for trust evaluation must fall back to the DS certificate's URI SAN.
	const certURI = "https://cert-issuer.example.com"

	dsCert, dsKey, certChain := createTestTrustListWithDS(t, func(tmpl *x509.Certificate) {
		tmpl.URIs = []*url.URL{{Scheme: "https", Host: "cert-issuer.example.com"}}
	})
	_ = dsCert

	recorder := &recordingTrustEvaluator{trusted: true}

	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      recorder,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)

	result := verifier.VerifyDeviceResponse(response)
	if !result.Valid {
		t.Fatalf("VerifyDeviceResponse() Valid = false, errors: %v", result.Errors)
	}

	if recorder.lastReq == nil {
		t.Fatal("expected TrustEvaluator.Evaluate to be called")
	}

	if got := recorder.lastReq.SubjectID; got != certURI {
		t.Errorf("SubjectID = %q, want issuer ID extracted from certificate URI SAN %q", got, certURI)
	}
}

func TestExtractMDocIssuerID(t *testing.T) {
	tests := []struct {
		name   string
		cert   *x509.Certificate
		expect string
	}{
		{
			name: "https URI SAN used as-is",
			cert: &x509.Certificate{
				URIs: []*url.URL{{Scheme: "https", Host: "issuer.example.com"}},
			},
			expect: "https://issuer.example.com",
		},
		{
			name: "http URI SAN normalized to https",
			cert: &x509.Certificate{
				URIs: []*url.URL{{Scheme: "http", Host: "issuer.example.com", Path: "/vc"}},
			},
			expect: "https://issuer.example.com/vc",
		},
		{
			name: "DNS SAN converted to https URL",
			cert: &x509.Certificate{
				DNSNames: []string{"issuer.example.com"},
			},
			expect: "https://issuer.example.com",
		},
		{
			name: "wildcard DNS SAN is skipped in favor of Organization",
			cert: &x509.Certificate{
				DNSNames: []string{"*.example.com"},
				Subject:  pkix.Name{Organization: []string{"siros-id"}},
			},
			expect: "siros-id",
		},
		{
			name: "wildcard DNS SAN is skipped, falling back to Country when no Organization",
			cert: &x509.Certificate{
				DNSNames: []string{"*.example.com"},
				Subject:  pkix.Name{Country: []string{"SE"}},
			},
			expect: "SE",
		},
		{
			name: "non-wildcard DNS SAN preferred over Organization",
			cert: &x509.Certificate{
				DNSNames: []string{"issuer.example.com"},
				Subject:  pkix.Name{Organization: []string{"siros-id"}},
			},
			expect: "https://issuer.example.com",
		},
		{
			name: "Organization used when no SANs present",
			cert: &x509.Certificate{
				Subject: pkix.Name{Organization: []string{"siros-id"}},
			},
			expect: "siros-id",
		},
		{
			name: "Country used when no SANs or Organization",
			cert: &x509.Certificate{
				Subject: pkix.Name{Country: []string{"SE"}},
			},
			expect: "SE",
		},
		{
			name: "CommonName used as last resort before issuer fallback",
			cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "Test Document Signer"},
			},
			expect: "Test Document Signer",
		},
		{
			name: "falls back to issuer CommonName when subject has nothing usable",
			cert: &x509.Certificate{
				Issuer: pkix.Name{CommonName: "Test IACA Root"},
			},
			expect: "Test IACA Root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMDocIssuerID(tt.cert)
			if got != tt.expect {
				t.Errorf("extractMDocIssuerID() = %q, want %q", got, tt.expect)
			}
		})
	}
}
