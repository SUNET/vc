package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/fxamacker/cbor/v2"
	"math/big"
	"testing"
	"time"
)

func createTestIssuerSigned(t *testing.T) *IssuerSignedMdoc {
	t.Helper()

	// Create issuer key and certificate
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test DS Certificate"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate device key: %v", err)
	}

	issuer, err := NewIssuer(IssuerConfig{
		SignerKey:        issuerKey,
		CertificateChain: []*x509.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("failed to create issuer: %v", err)
	}

	// Create mDL data
	mdoc := &MDoc{
		FamilyName:           "Smith",
		GivenName:            "John",
		BirthDate:            "1990-01-15",
		IssueDate:            "2024-01-01",
		ExpiryDate:           "2034-01-01",
		IssuingCountry:       "SE",
		IssuingAuthority:     "Transportstyrelsen",
		DocumentNumber:       "TEST123",
		Portrait:             []byte("fake-portrait-data"),
		DrivingPrivileges:    []DrivingPrivilege{{VehicleCategoryCode: "B"}},
		UNDistinguishingSign: "S",
	}

	// Add age attestations
	ageOver18 := true
	ageOver21 := true
	mdoc.AgeOver = &AgeOver{
		Over18: &ageOver18,
		Over21: &ageOver21,
	}

	issuedDoc, err := issuer.Issue(&IssuanceRequest{
		DevicePublicKey: &deviceKey.PublicKey,
		MDoc:            mdoc,
	})
	if err != nil {
		t.Fatalf("failed to issue: %v", err)
	}

	if len(issuedDoc.DocumentMdoc.Documents) == 0 {
		t.Fatal("no documents found in issued response")
	}

	doc, ok := issuedDoc.DocumentMdoc.Documents[0].(*DocumentMdoc)
	if !ok {
		t.Fatal("document is not of type *DocumentMdoc")
	}

	issuerSigned := doc.IssuerSigned

	return &issuerSigned
}

func TestNewSelectiveDisclosure(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)

	sd, err := NewSelectiveDisclosure(issuerSigned)
	if err != nil {
		t.Fatalf("NewSelectiveDisclosure() error = %v", err)
	}

	if sd == nil {
		t.Fatal("NewSelectiveDisclosure() returned nil")
	}
}

func TestNewSelectiveDisclosure_NilInput(t *testing.T) {
	_, err := NewSelectiveDisclosure(nil)
	if err == nil {
		t.Error("NewSelectiveDisclosure(nil) should fail")
	}
}

func TestSelectiveDisclosure_Disclose(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	sd, _ := NewSelectiveDisclosure(issuerSigned)

	// Request only family_name and age_over_18
	request := map[string][]string{
		Namespace: {"family_name", "age_over_18"},
	}

	disclosed, err := sd.Disclose(request)
	if err != nil {
		t.Fatalf("Disclose() error = %v", err)
	}

	items := disclosed.NameSpaces[Namespace]
	if len(items) != 2 {
		t.Errorf("Disclose() returned %d elements, want 2", len(items))
	}

	elementSet := make(map[string]bool)
	for _, anyItem := range items {
		var item IssuerSignedItem

		// Peek into the Tag 24 wrapper
		if tag, ok := anyItem.(cbor.Tag); ok {
			content, ok := tag.Content.([]byte)
			if !ok {
				t.Fatalf("Tag content is not []byte")
			}
			if err := cbor.Unmarshal(content, &item); err != nil {
				t.Fatalf("Failed to unmarshal item from Tag: %v", err)
			}
		} else if concrete, ok := anyItem.(IssuerSignedItem); ok {
			// Fallback for non-encoded items (if your mock creates them raw)
			item = concrete
		} else if pItem, ok := anyItem.(*IssuerSignedItem); ok {
			item = *pItem
		} else {
			t.Fatalf("Discloseaa() returned unexpected type %T in NameSpaces", anyItem)
		}

		elementSet[item.ElementIdentifier] = true
	}

	if !elementSet["family_name"] {
		t.Error("Disclose() missing family_name")
	}
	if !elementSet["age_over_18"] {
		t.Error("Disclose() missing age_over_18")
	}
	if elementSet["given_name"] {
		t.Error("Disclose() should not include given_name")
	}
}

func TestSelectiveDisclosure_Disclose_EmptyRequest(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	sd, _ := NewSelectiveDisclosure(issuerSigned)

	disclosed, err := sd.Disclose(map[string][]string{})
	if err != nil {
		t.Fatalf("Disclose() error = %v", err)
	}

	if len(disclosed.NameSpaces) != 0 {
		t.Errorf("Disclose() with empty request should return empty namespaces")
	}
}

func TestSelectiveDisclosure_Disclose_UnknownNamespace(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	sd, _ := NewSelectiveDisclosure(issuerSigned)

	request := map[string][]string{
		"unknown.namespace": {"element"},
	}

	disclosed, err := sd.Disclose(request)
	if err != nil {
		t.Fatalf("Disclose() error = %v", err)
	}

	if len(disclosed.NameSpaces) != 0 {
		t.Error("Disclose() with unknown namespace should return empty namespaces")
	}
}

func TestSelectiveDisclosure_DiscloseFromItemsRequest(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	sd, _ := NewSelectiveDisclosure(issuerSigned)

	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {
				"family_name": false,
				"given_name":  false,
			},
		},
	}

	disclosed, err := sd.DiscloseFromItemsRequest(request)
	if err != nil {
		t.Fatalf("DiscloseFromItemsRequest() error = %v", err)
	}

	items := disclosed.NameSpaces[Namespace]
	if len(items) != 2 {
		t.Errorf("DiscloseFromItemsRequest() returned %d elements, want 2", len(items))
	}
}

func TestSelectiveDisclosure_GetAvailableElements(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	sd, _ := NewSelectiveDisclosure(issuerSigned)

	available := sd.GetAvailableElements()

	elements := available[Namespace]
	// MDoc has many mandatory elements plus our test data
	if len(elements) < 10 {
		t.Errorf("GetAvailableElements() returned %d elements, want at least 10", len(elements))
	}
}

func TestSelectiveDisclosure_HasElement(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	sd, _ := NewSelectiveDisclosure(issuerSigned)

	if !sd.HasElement(Namespace, "family_name") {
		t.Error("HasElement() should return true for family_name")
	}

	if sd.HasElement(Namespace, "unknown_element") {
		t.Error("HasElement() should return false for unknown_element")
	}

	if sd.HasElement("unknown.namespace", "family_name") {
		t.Error("HasElement() should return false for unknown namespace")
	}
}

func TestNewDeviceResponseBuilder(t *testing.T) {
	builder := NewDeviceResponseBuilder(DocType)

	if builder == nil {
		t.Fatal("NewDeviceResponseBuilder() returned nil")
	}
}

func TestDeviceResponseBuilder_Build_WithSignature(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	transcript := []byte("test session transcript")

	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"family_name": false, "age_over_18": false},
		},
	}

	builder := NewDeviceResponseBuilder(DocType).
		WithIssuerSigned(issuerSigned).
		WithDeviceKey(deviceKey).
		WithSessionTranscript(transcript).
		WithRequest(request)

	response, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if response.Version != "1.0" {
		t.Errorf("Version = %s, want 1.0", response.Version)
	}

	if len(response.Documents) != 1 {
		t.Fatalf("Documents count = %d, want 1", len(response.Documents))
	}

	doc, ok := response.Documents[0].(*DocumentMdoc)
	if !ok {
		t.Fatalf("Document at index 0 is type %T, want *DocumentMdoc", response.Documents[0])
	}

	if doc.DocType != DocType {
		t.Errorf("DocType = %s, want %s", doc.DocType, DocType)
	}

	items := doc.IssuerSigned.NameSpaces[Namespace]
	if len(items) != 2 {
		t.Errorf("Disclosed elements = %d, want 2", len(items))
	}
	sig, ok := doc.DeviceSigned.DeviceAuth.DeviceSignature.([]byte)
	if !ok {
		if sigArray, isArray := doc.DeviceSigned.DeviceAuth.DeviceSignature.([]any); isArray {
			if len(sigArray) == 0 {
				t.Error("DeviceSignature array is empty")
			}
		} else {
			t.Fatalf("DeviceSignature is unexpected type %T", doc.DeviceSigned.DeviceAuth.DeviceSignature)
		}
	} else if len(sig) == 0 {
		t.Error("DeviceSignature bytes are empty")
	}
}

func TestDeviceResponseBuilder_Build_WithMAC(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	macKey := make([]byte, 32)
	rand.Read(macKey)
	transcript := []byte("test session transcript")

	builder := NewDeviceResponseBuilder(DocType).
		WithIssuerSigned(issuerSigned).
		WithMACKey(macKey).
		WithSessionTranscript(transcript)

	response, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	doc, ok := response.Documents[0].(*DocumentMdoc)
	if !ok {
		t.Fatalf("expected *DocumentMdoc, got %T", response.Documents[0])
	}
	if len(doc.DeviceSigned.DeviceAuth.DeviceMac) == 0 {
		t.Error("DeviceMac is empty")
	}
	if doc.DeviceSigned.DeviceAuth.DeviceSignature != nil {
		sig, ok := doc.DeviceSigned.DeviceAuth.DeviceSignature.([]byte)
		if ok && len(sig) == 0 {
			t.Error("DeviceSignature was provided but is empty")
		}
	}
}

func TestDeviceResponseBuilder_Build_MissingTranscript(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	builder := NewDeviceResponseBuilder(DocType).
		WithIssuerSigned(issuerSigned).
		WithDeviceKey(deviceKey)

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without session transcript")
	}
}

func TestDeviceResponseBuilder_Build_MissingKey(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	transcript := []byte("test session transcript")

	builder := NewDeviceResponseBuilder(DocType).
		WithIssuerSigned(issuerSigned).
		WithSessionTranscript(transcript)

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail without device key or MAC key")
	}
}

func TestDeviceResponseBuilder_AddError(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	transcript := []byte("test session transcript")

	// Request an element that doesn't exist
	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"family_name": false, "nonexistent": false},
		},
	}

	builder := NewDeviceResponseBuilder(DocType).
		WithIssuerSigned(issuerSigned).
		WithDeviceKey(deviceKey).
		WithSessionTranscript(transcript).
		WithRequest(request)

	response, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	doc, ok := response.Documents[0].(*DocumentMdoc)
	if !ok {
		t.Fatalf("expected *DocumentMdoc, got %T", response.Documents[0])
	}

	if doc.Errors == nil {
		t.Fatal("Errors should not be nil")
	}

	errorCode, ok := doc.Errors[Namespace]["nonexistent"]
	if !ok {
		t.Error("Missing error for nonexistent element")
	}
	if errorCode != ErrorDataNotAvailable {
		t.Errorf("Error code = %d, want %d", errorCode, ErrorDataNotAvailable)
	}
}

func TestNewDisclosurePolicy(t *testing.T) {
	policy := NewDisclosurePolicy()

	if policy == nil {
		t.Fatal("NewDisclosurePolicy() returned nil")
	}
}

func TestDefaultMDLDisclosurePolicy(t *testing.T) {
	policy := DefaultMDLDisclosurePolicy()

	// Check always disclose includes age_over elements
	alwaysDisclose := policy.AlwaysDisclose[Namespace]
	if len(alwaysDisclose) == 0 {
		t.Error("AlwaysDisclose should not be empty")
	}

	// Check never disclose includes biometric elements
	neverDisclose := policy.NeverDisclose[Namespace]
	if len(neverDisclose) == 0 {
		t.Error("NeverDisclose should not be empty")
	}

	// Check require confirmation includes PII
	requireConfirm := policy.RequireConfirmation[Namespace]
	if len(requireConfirm) == 0 {
		t.Error("RequireConfirmation should not be empty")
	}
}

func TestDisclosurePolicy_FilterRequest(t *testing.T) {
	policy := NewDisclosurePolicy()
	policy.NeverDisclose[Namespace] = []string{"secret_element"}

	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {
				"family_name":    false,
				"secret_element": false,
			},
		},
	}

	filtered, blocked := policy.FilterRequest(request)

	// Check blocked
	if len(blocked[Namespace]) != 1 {
		t.Errorf("Blocked elements = %d, want 1", len(blocked[Namespace]))
	}
	if blocked[Namespace][0] != "secret_element" {
		t.Error("secret_element should be blocked")
	}

	// Check filtered
	if len(filtered.NameSpaces[Namespace]) != 1 {
		t.Errorf("Filtered elements = %d, want 1", len(filtered.NameSpaces[Namespace]))
	}
	if _, ok := filtered.NameSpaces[Namespace]["family_name"]; !ok {
		t.Error("family_name should be in filtered request")
	}
}

func TestDisclosurePolicy_RequiresConfirmation(t *testing.T) {
	policy := NewDisclosurePolicy()
	policy.RequireConfirmation[Namespace] = []string{"family_name"}

	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {
				"family_name": false,
				"age_over_18": false,
			},
		},
	}

	needsConfirm := policy.RequiresConfirmation(request)

	if len(needsConfirm[Namespace]) != 1 {
		t.Errorf("Elements needing confirmation = %d, want 1", len(needsConfirm[Namespace]))
	}
}

func TestDisclosurePolicy_CanAutoDisclose(t *testing.T) {
	policy := NewDisclosurePolicy()
	policy.AlwaysDisclose[Namespace] = []string{"age_over_18", "age_over_21"}

	// Request only age elements
	ageRequest := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"age_over_18": false},
		},
	}

	if !policy.CanAutoDisclose(ageRequest) {
		t.Error("Should be able to auto-disclose age_over_18")
	}

	// Request includes non-auto element
	mixedRequest := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {"age_over_18": false, "family_name": false},
		},
	}

	if policy.CanAutoDisclose(mixedRequest) {
		t.Error("Should not be able to auto-disclose family_name")
	}
}

func TestEncodeDecodeDeviceResponse(t *testing.T) {
	issuerSigned := createTestIssuerSigned(t)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	transcript := []byte("test session transcript")

	builder := NewDeviceResponseBuilder(DocType).
		WithIssuerSigned(issuerSigned).
		WithDeviceKey(deviceKey).
		WithSessionTranscript(transcript)

	response, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Encode
	encoded, err := EncodeDeviceResponse(response)
	if err != nil {
		t.Fatalf("EncodeDeviceResponse() error = %v", err)
	}

	if len(encoded) == 0 {
		t.Error("EncodeDeviceResponse() returned empty bytes")
	}

	// Decode
	decoded, err := DecodeDeviceResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeDeviceResponse() error = %v", err)
	}

	if decoded.Version != response.Version {
		t.Errorf("Decoded Version = %s, want %s", decoded.Version, response.Version)
	}

	if len(decoded.Documents) != len(response.Documents) {
		t.Errorf("Decoded Documents count = %d, want %d", len(decoded.Documents), len(response.Documents))
	}
}

func TestSelectiveDisclosure_RoundTrip(t *testing.T) {
	// Complete round-trip test: issue -> selective disclose -> verify
	issuerSigned := createTestIssuerSigned(t)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	transcript := []byte("test session transcript")

	// Create request for subset of elements
	request := &ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {
				"family_name": false,
				"age_over_18": false,
			},
		},
	}

	// Build response with selective disclosure
	response, err := NewDeviceResponseBuilder(DocType).
		WithIssuerSigned(issuerSigned).
		WithDeviceKey(deviceKey).
		WithSessionTranscript(transcript).
		WithRequest(request).
		Build()

	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	doc, ok := response.Documents[0].(*DocumentMdoc)
	if !ok {
		t.Fatalf("expected *DocumentMdoc, got %T", response.Documents[0])
	}

	items := doc.IssuerSigned.NameSpaces[Namespace]
	if len(items) != 2 {
		t.Errorf("Expected 2 disclosed elements, got %d", len(items))
	}

	identifiers := make(map[string]bool)
	for _, anyItem := range items {
		var item IssuerSignedItem

		// Unwrap the Tag 24 bytes to see what's inside
		if tag, ok := anyItem.(cbor.Tag); ok {
			content, _ := tag.Content.([]byte)
			if err := cbor.Unmarshal(content, &item); err != nil {
				t.Fatalf("failed to unmarshal disclosed item: %v", err)
			}
		} else if concrete, ok := anyItem.(IssuerSignedItem); ok {
			item = concrete
		} else if pItem, ok := anyItem.(*IssuerSignedItem); ok {
			item = *pItem
		} else {
			t.Fatalf("unexpected item type %T: verifier needs cbor.Tag or IssuerSignedItem", anyItem)
		}

		identifiers[item.ElementIdentifier] = true
	}

	if !identifiers["family_name"] {
		t.Error("family_name should be disclosed")
	}
	if !identifiers["age_over_18"] {
		t.Error("age_over_18 should be disclosed")
	}
	if identifiers["given_name"] {
		t.Error("given_name should not be disclosed")
	}
	if identifiers["portrait"] {
		t.Error("portrait should not be disclosed")
	}

	// If IssuerAuth is 'any', check it's not nil. If it's []byte, check len.
	if doc.IssuerSigned.IssuerAuth == nil {
		t.Error("IssuerAuth should be preserved")
	}
}
