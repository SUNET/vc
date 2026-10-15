package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func createTestReaderCertChain(t *testing.T) (*ecdsa.PrivateKey, []*x509.Certificate, *x509.Certificate) {
	t.Helper()

	// Generate CA key pair
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Reader CA"},
			CommonName:   "Test Reader CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	// Generate reader key pair
	readerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate reader key: %v", err)
	}

	// Create reader certificate
	readerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Verifier"},
			CommonName:   "Test Reader",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	readerCertDER, err := x509.CreateCertificate(rand.Reader, readerTemplate, caCert, &readerKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create reader certificate: %v", err)
	}

	readerCert, err := x509.ParseCertificate(readerCertDER)
	if err != nil {
		t.Fatalf("failed to parse reader certificate: %v", err)
	}

	return readerKey, []*x509.Certificate{readerCert, caCert}, caCert
}

func TestNewReaderAuthBuilder(t *testing.T) {
	builder := NewReaderAuthBuilder()

	if builder == nil {
		t.Fatal("NewReaderAuthBuilder() returned nil")
	}
}

func TestReaderAuthBuilder_WithSessionTranscript(t *testing.T) {
	builder := NewReaderAuthBuilder()
	transcript := testSessionTranscript()

	result := builder.WithSessionTranscript(transcript)

	if result != builder {
		t.Error("WithSessionTranscript() should return builder for chaining")
	}
	if string(builder.sessionTranscript) != string(transcript) {
		t.Error("sessionTranscript not set correctly")
	}
}

func TestReaderAuthBuilder_WithItemsRequest(t *testing.T) {
	builder := NewReaderAuthBuilder()
	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"family_name": false},
		},
	}

	result := builder.WithItemsRequest(request)

	if result != builder {
		t.Error("WithItemsRequest() should return builder for chaining")
	}
	if builder.itemsRequest == nil {
		t.Error("itemsRequest not set")
	}
}

func TestReaderAuthBuilder_WithReaderKey(t *testing.T) {
	builder := NewReaderAuthBuilder()
	readerKey, certChain, _ := createTestReaderCertChain(t)

	result := builder.WithReaderKey(readerKey, certChain)

	if result != builder {
		t.Error("WithReaderKey() should return builder for chaining")
	}
	if builder.readerKey == nil {
		t.Error("readerKey not set")
	}
	if len(builder.readerCertChain) == 0 {
		t.Error("readerCertChain not set")
	}
}

func TestReaderAuthBuilder_Build(t *testing.T) {
	readerKey, certChain, _ := createTestReaderCertChain(t)
	transcript := testSessionTranscript()
	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"family_name": false, "given_name": false},
		},
	}

	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithItemsRequest(request).
		WithReaderKey(readerKey, certChain)

	readerAuth, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(readerAuth) == 0 {
		t.Error("Build() returned empty bytes")
	}
}

func TestReaderAuthBuilder_Build_MissingTranscript(t *testing.T) {
	readerKey, certChain, _ := createTestReaderCertChain(t)
	request := &ItemsRequest{DocType: DocType}

	builder := NewReaderAuthBuilder().
		WithItemsRequest(request).
		WithReaderKey(readerKey, certChain)

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without session transcript")
	}
}

func TestReaderAuthBuilder_Build_MissingRequest(t *testing.T) {
	readerKey, certChain, _ := createTestReaderCertChain(t)
	transcript := testSessionTranscript()

	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithReaderKey(readerKey, certChain)

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without items request")
	}
}

func TestReaderAuthBuilder_Build_MissingKey(t *testing.T) {
	transcript := testSessionTranscript()
	request := &ItemsRequest{DocType: DocType}

	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithItemsRequest(request)

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without reader key")
	}
}

func TestReaderAuthBuilder_BuildDocRequest(t *testing.T) {
	readerKey, certChain, _ := createTestReaderCertChain(t)
	transcript := testSessionTranscript()
	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"family_name": false},
		},
	}

	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithItemsRequest(request).
		WithReaderKey(readerKey, certChain)

	docRequest, err := builder.BuildDocRequest()
	if err != nil {
		t.Fatalf("BuildDocRequest() error = %v", err)
	}

	if len(docRequest.ItemsRequest) == 0 {
		t.Error("BuildDocRequest() ItemsRequest is empty")
	}

	if len(docRequest.ReaderAuth) == 0 {
		t.Error("BuildDocRequest() ReaderAuth is empty")
	}
}

func TestReaderAuthBuilder_BuildDocRequest_NoAuth(t *testing.T) {
	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"family_name": false},
		},
	}

	builder := NewReaderAuthBuilder().
		WithItemsRequest(request)

	docRequest, err := builder.BuildDocRequest()
	if err != nil {
		t.Fatalf("BuildDocRequest() error = %v", err)
	}

	if len(docRequest.ItemsRequest) == 0 {
		t.Error("BuildDocRequest() ItemsRequest is empty")
	}

	if len(docRequest.ReaderAuth) != 0 {
		t.Error("BuildDocRequest() ReaderAuth should be empty without credentials")
	}
}

func TestNewReaderTrustList(t *testing.T) {
	trustList := NewReaderTrustList()

	if trustList == nil {
		t.Fatal("NewReaderTrustList() returned nil")
	}
}

func TestReaderTrustList_AddTrustedCertificate(t *testing.T) {
	trustList := NewReaderTrustList()
	_, certChain, _ := createTestReaderCertChain(t)

	trustList.AddTrustedCertificate(certChain[0])

	if len(trustList.trustedCerts) != 1 {
		t.Error("trustedCerts should have 1 certificate")
	}
}

func TestReaderTrustList_AddTrustedCA(t *testing.T) {
	trustList := NewReaderTrustList()
	_, _, caCert := createTestReaderCertChain(t)

	trustList.AddTrustedCA(caCert)

	if len(trustList.trustedCAs) != 1 {
		t.Error("trustedCAs should have 1 certificate")
	}
}

func TestReaderTrustList_SetIntentMapping(t *testing.T) {
	trustList := NewReaderTrustList()
	_, certChain, _ := createTestReaderCertChain(t)

	trustList.SetIntentMapping(certChain[0].Subject.CommonName, []string{Namespace})

	namespaces := trustList.GetAllowedNamespaces(certChain[0])
	if len(namespaces) != 1 {
		t.Error("GetAllowedNamespaces() should return 1 namespace")
	}
	if namespaces[0] != Namespace {
		t.Errorf("GetAllowedNamespaces() = %v, want %s", namespaces, Namespace)
	}
}

func TestReaderTrustList_IsTrusted_DirectCert(t *testing.T) {
	trustList := NewReaderTrustList()
	_, certChain, _ := createTestReaderCertChain(t)

	trustList.AddTrustedCertificate(certChain[0])

	err := trustList.IsTrusted(certChain)
	if err != nil {
		t.Errorf("IsTrusted() error = %v", err)
	}
}

func TestReaderTrustList_IsTrusted_CA(t *testing.T) {
	trustList := NewReaderTrustList()
	_, certChain, caCert := createTestReaderCertChain(t)

	trustList.AddTrustedCA(caCert)

	err := trustList.IsTrusted(certChain)
	if err != nil {
		t.Errorf("IsTrusted() error = %v", err)
	}
}

func TestReaderTrustList_IsTrusted_Untrusted(t *testing.T) {
	trustList := NewReaderTrustList()
	_, certChain, _ := createTestReaderCertChain(t)

	// Don't add to trust list

	err := trustList.IsTrusted(certChain)
	if err == nil {
		t.Error("IsTrusted() should fail for untrusted certificate")
	}
}

func TestReaderTrustList_IsTrusted_Empty(t *testing.T) {
	trustList := NewReaderTrustList()

	err := trustList.IsTrusted([]*x509.Certificate{})
	if err == nil {
		t.Error("IsTrusted() should fail for empty chain")
	}
}

func TestNewReaderAuthVerifier(t *testing.T) {
	transcript := testSessionTranscript()
	trustList := NewReaderTrustList()

	verifier := NewReaderAuthVerifier(transcript, trustList)

	if verifier == nil {
		t.Fatal("NewReaderAuthVerifier() returned nil")
	}
}

func TestReaderAuthVerifier_VerifyReaderAuth(t *testing.T) {
	readerKey, certChain, caCert := createTestReaderCertChain(t)
	transcript := testSessionTranscript()
	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"family_name": false},
		},
	}

	// Build reader auth
	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithItemsRequest(request).
		WithReaderKey(readerKey, certChain)

	readerAuth, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Encode items request for verification
	encoder, _ := NewCBOREncoder()
	itemsRequestBytes, _ := encoder.Marshal(request)

	// Create trust list
	trustList := NewReaderTrustList()
	trustList.AddTrustedCA(caCert)

	// Verify
	verifier := NewReaderAuthVerifier(transcript, trustList)
	verifiedRequest, readerCert, err := verifier.VerifyReaderAuth(readerAuth, itemsRequestBytes)
	if err != nil {
		t.Fatalf("VerifyReaderAuth() error = %v", err)
	}

	if verifiedRequest == nil {
		t.Fatal("VerifyReaderAuth() returned nil request")
	}

	if readerCert == nil {
		t.Fatal("VerifyReaderAuth() returned nil certificate")
	}

	if verifiedRequest.DocType != DocType {
		t.Errorf("VerifyReaderAuth() DocType = %s, want %s", verifiedRequest.DocType, DocType)
	}
}

func TestReaderAuthVerifier_VerifyReaderAuth_Untrusted(t *testing.T) {
	readerKey, certChain, _ := createTestReaderCertChain(t)
	transcript := testSessionTranscript()
	request := &ItemsRequest{DocType: DocType}

	// Build reader auth
	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithItemsRequest(request).
		WithReaderKey(readerKey, certChain)

	readerAuth, _ := builder.Build()

	encoder, _ := NewCBOREncoder()
	itemsRequestBytes, _ := encoder.Marshal(request)

	// Create empty trust list (untrusted)
	trustList := NewReaderTrustList()

	verifier := NewReaderAuthVerifier(transcript, trustList)
	_, _, err := verifier.VerifyReaderAuth(readerAuth, itemsRequestBytes)
	if err == nil {
		t.Error("VerifyReaderAuth() should fail for untrusted reader")
	}
}

func TestReaderAuthVerifier_VerifyReaderAuth_WrongTranscript(t *testing.T) {
	readerKey, certChain, caCert := createTestReaderCertChain(t)
	transcript := testSessionTranscript()
	wrongTranscript := []byte("wrong transcript")
	request := &ItemsRequest{DocType: DocType}

	// Build reader auth with correct transcript
	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithItemsRequest(request).
		WithReaderKey(readerKey, certChain)

	readerAuth, _ := builder.Build()

	encoder, _ := NewCBOREncoder()
	itemsRequestBytes, _ := encoder.Marshal(request)

	trustList := NewReaderTrustList()
	trustList.AddTrustedCA(caCert)

	// Verify with wrong transcript
	verifier := NewReaderAuthVerifier(wrongTranscript, trustList)
	_, _, err := verifier.VerifyReaderAuth(readerAuth, itemsRequestBytes)
	if err == nil {
		t.Error("VerifyReaderAuth() should fail with wrong transcript")
	}
}

func TestReaderAuthVerifier_FilterRequestByIntent(t *testing.T) {
	_, certChain, _ := createTestReaderCertChain(t)
	transcript := testSessionTranscript()

	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace:                 {"family_name": false, "portrait": false},
			"org.iso.18013.5.1.aamva": {"dhs_compliance": false},
		},
	}

	trustList := NewReaderTrustList()
	trustList.SetIntentMapping(certChain[0].Subject.CommonName, []string{Namespace})

	verifier := NewReaderAuthVerifier(transcript, trustList)
	filtered := verifier.FilterRequestByIntent(request, certChain[0])

	if len(filtered.NameSpaces) != 1 {
		t.Errorf("FilterRequestByIntent() namespaces = %d, want 1", len(filtered.NameSpaces))
	}

	if _, ok := filtered.NameSpaces[Namespace]; !ok {
		t.Error("FilterRequestByIntent() should include allowed namespace")
	}

	if _, ok := filtered.NameSpaces["org.iso.18013.5.1.aamva"]; ok {
		t.Error("FilterRequestByIntent() should not include disallowed namespace")
	}
}

func TestValidateReaderCertificate(t *testing.T) {
	_, certChain, _ := createTestReaderCertChain(t)
	profile := DefaultReaderCertProfile()

	err := ValidateReaderCertificate(certChain[0], profile)
	if err != nil {
		t.Errorf("ValidateReaderCertificate() error = %v", err)
	}
}

func TestValidateReaderCertificate_Nil(t *testing.T) {
	profile := DefaultReaderCertProfile()

	err := ValidateReaderCertificate(nil, profile)
	if err == nil {
		t.Error("ValidateReaderCertificate() should fail for nil certificate")
	}
}

func TestValidateReaderCertificate_IsCA(t *testing.T) {
	_, _, caCert := createTestReaderCertChain(t)
	profile := DefaultReaderCertProfile()

	err := ValidateReaderCertificate(caCert, profile)
	if err == nil {
		t.Error("ValidateReaderCertificate() should fail for CA certificate")
	}
}

func TestHasReaderAuth(t *testing.T) {
	docRequest := &DocRequest{
		ItemsRequest: []byte{0x01},
		ReaderAuth:   []byte{0x02},
	}

	if !HasReaderAuth(docRequest) {
		t.Error("HasReaderAuth() should return true")
	}

	docRequest.ReaderAuth = nil
	if HasReaderAuth(docRequest) {
		t.Error("HasReaderAuth() should return false for nil ReaderAuth")
	}
}

func TestExtractReaderCertificate(t *testing.T) {
	readerKey, certChain, _ := createTestReaderCertChain(t)
	transcript := testSessionTranscript()
	request := &ItemsRequest{DocType: DocType}

	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithItemsRequest(request).
		WithReaderKey(readerKey, certChain)

	docRequest, _ := builder.BuildDocRequest()

	cert, err := ExtractReaderCertificate(docRequest)
	if err != nil {
		t.Fatalf("ExtractReaderCertificate() error = %v", err)
	}

	if cert == nil {
		t.Fatal("ExtractReaderCertificate() returned nil")
	}

	if cert.Subject.CommonName != certChain[0].Subject.CommonName {
		t.Error("ExtractReaderCertificate() returned wrong certificate")
	}
}

func TestExtractReaderCertificate_NoAuth(t *testing.T) {
	docRequest := &DocRequest{
		ItemsRequest: []byte{0x01},
	}

	_, err := ExtractReaderCertificate(docRequest)
	if err == nil {
		t.Error("ExtractReaderCertificate() should fail without reader auth")
	}
}

func TestDefaultReaderCertProfile(t *testing.T) {
	profile := DefaultReaderCertProfile()

	if profile == nil {
		t.Fatal("DefaultReaderCertProfile() returned nil")
	}

	if profile.ExtKeyUsageOID != "1.0.18013.5.1.6" {
		t.Errorf("ExtKeyUsageOID = %s, want 1.0.18013.5.1.6", profile.ExtKeyUsageOID)
	}
}

func TestReaderAuth_RoundTrip(t *testing.T) {
	// Complete round-trip test
	readerKey, certChain, caCert := createTestReaderCertChain(t)
	transcript := testSessionTranscript()

	// Build request
	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {
				"family_name": false,
				"given_name":  false,
				"birth_date":  false,
			},
		},
	}

	// Build reader auth
	builder := NewReaderAuthBuilder().
		WithSessionTranscript(transcript).
		WithItemsRequest(request).
		WithReaderKey(readerKey, certChain)

	docRequest, err := builder.BuildDocRequest()
	if err != nil {
		t.Fatalf("BuildDocRequest() error = %v", err)
	}

	// Verify on device side
	trustList := NewReaderTrustList()
	trustList.AddTrustedCA(caCert)
	trustList.SetIntentMapping(certChain[0].Subject.CommonName, []string{Namespace})

	verifier := NewReaderAuthVerifier(transcript, trustList)
	verifiedRequest, cert, err := verifier.VerifyAndFilterRequest(docRequest.ReaderAuth, docRequest.ItemsRequest)
	if err != nil {
		t.Fatalf("VerifyAndFilterRequest() error = %v", err)
	}

	if verifiedRequest == nil {
		t.Fatal("verifiedRequest is nil")
	}

	if cert == nil {
		t.Fatal("cert is nil")
	}

	if verifiedRequest.DocType != DocType {
		t.Errorf("DocType = %s, want %s", verifiedRequest.DocType, DocType)
	}

	if len(verifiedRequest.NameSpaces[Namespace]) != 3 {
		t.Errorf("NameSpaces elements = %d, want 3", len(verifiedRequest.NameSpaces[Namespace]))
	}
}
