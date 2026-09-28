package mdoc

import (
	"crypto/elliptic"
	"testing"
)

// issueWithStatus issues a test mdoc, optionally carrying a status reference.
func issueWithStatus(t *testing.T, ref *StatusReference) *DocumentMdoc {
	t.Helper()

	issuer, err := NewIssuer(createTestIssuerConfig(t))
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}
	deviceKey, err := GenerateDeviceKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateDeviceKeyPair() error = %v", err)
	}

	issued, err := issuer.Issue(&IssuanceRequest{
		DocumentData:    testMDLDocumentData(t),
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          testMDLSchema(),
		Status:          ref,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if len(issued.DocumentMdoc.Documents) != 1 {
		t.Fatalf("expected 1 document, got %d", len(issued.DocumentMdoc.Documents))
	}
	return &issued.DocumentMdoc.Documents[0]
}

// TestIssuedMdocCarriesStatusInMSO is the end-to-end case for the gap this
// change closes: before it, mdoc credentials carried no status reference
// anywhere, so no mdoc could ever be revoked.
//
// The reference must land in the MSO (draft-ietf-oauth-status-list Section
// 6.3), not in a namespace: a data element is subject to selective
// disclosure, so a holder could simply withhold it.
func TestIssuedMdocCarriesStatusInMSO(t *testing.T) {
	want := &StatusReference{URI: "https://registry.example.com/statuslists/7", Index: 42}
	doc := issueWithStatus(t, want)

	sign1, err := ParseIssuerAuth(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		t.Fatalf("ParseIssuerAuth: %v", err)
	}
	mso, err := DecodeMSOPayload(sign1)
	if err != nil {
		t.Fatalf("DecodeMSOPayload: %v", err)
	}
	if mso.Status == nil || mso.Status.StatusList == nil {
		t.Fatal("issued MSO carries no status parameter, so the credential cannot be revoked")
	}
	if got := mso.Status.StatusList; got.URI != want.URI || got.Index != want.Index {
		t.Fatalf("MSO status = %+v, want %+v", got, want)
	}

	// It must NOT have been written as a namespace data element.
	for ns, values := range map[string]map[string]any{
		Namespace: issuedElementValues(t, doc, Namespace),
	} {
		if _, found := values["status"]; found {
			t.Fatalf("status was written as a data element in namespace %q; a holder could withhold it", ns)
		}
	}

	ref, err := ExtractStatusReference(doc)
	if err != nil {
		t.Fatalf("ExtractStatusReference: %v", err)
	}
	if ref.URI != want.URI || ref.Index != want.Index {
		t.Fatalf("ExtractStatusReference = %+v, want %+v", ref, want)
	}
}

// TestNoStatusAllocatedMeansNoStatusParameter: an empty status parameter
// would advertise revocability the issuer cannot deliver.
func TestNoStatusAllocatedMeansNoStatusParameter(t *testing.T) {
	doc := issueWithStatus(t, nil)

	sign1, err := ParseIssuerAuth(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		t.Fatalf("ParseIssuerAuth: %v", err)
	}
	mso, err := DecodeMSOPayload(sign1)
	if err != nil {
		t.Fatalf("DecodeMSOPayload: %v", err)
	}
	if mso.Status != nil {
		t.Fatalf("MSO carries a status parameter %+v although none was allocated", mso.Status)
	}
	if _, err := ExtractStatusReference(doc); err == nil {
		t.Fatal("ExtractStatusReference found a reference in a credential issued without one")
	}
}
