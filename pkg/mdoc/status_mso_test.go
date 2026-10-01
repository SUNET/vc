package mdoc

import (
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
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

// docWithMSOStatus rebuilds a document whose MSO carries the given status
// value verbatim. It does not re-sign: statusFromMSO reads the payload
// without verifying, which is correct because the caller verifies the
// document first, so an unsigned but well-formed MSO is enough to exercise
// the parsing.
func docWithMSOStatus(t *testing.T, doc *DocumentMdoc, status any) *DocumentMdoc {
	t.Helper()

	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder: %v", err)
	}
	sign1, err := ParseIssuerAuth(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		t.Fatalf("ParseIssuerAuth: %v", err)
	}

	payload := sign1.Payload
	var tag cbor.Tag
	if err := encoder.Unmarshal(payload, &tag); err == nil && tag.Number == 24 {
		if content, ok := tag.Content.([]byte); ok {
			payload = content
		}
	}

	var mso map[string]any
	if err := encoder.Unmarshal(payload, &mso); err != nil {
		t.Fatalf("decode MSO: %v", err)
	}
	if status == nil {
		delete(mso, "status")
	} else {
		mso["status"] = status
	}

	msoBytes, err := encoder.Marshal(mso)
	if err != nil {
		t.Fatalf("encode MSO: %v", err)
	}
	tagged, err := encoder.Marshal(cbor.Tag{Number: TagEncodedCBOR, Content: msoBytes})
	if err != nil {
		t.Fatalf("encode tagged MSO: %v", err)
	}

	out := *doc
	out.IssuerSigned.IssuerAuth = []any{sign1.Protected, sign1.Unprotected, tagged, sign1.Signature}
	return &out
}

// TestUnreadableMSOStatusIsNotReportedAsAbsent separates the two answers
// that must never be conflated.
//
// A credential with no status parameter is not revocable, which is normal.
// A credential whose issuer signed a status parameter that cannot be read
// has an UNKNOWN revocation state. Reporting the second as the first makes
// it verify as permanently valid.
func TestUnreadableMSOStatusIsNotReportedAsAbsent(t *testing.T) {
	base := issueWithStatus(t, &StatusReference{URI: "https://registry.example.com/statuslists/1", Index: 3})

	cases := map[string]any{
		"status_list with no uri": map[string]any{
			"status_list": map[string]any{"idx": int64(3), "uri": ""},
		},
		"status with no status_list": map[string]any{"something_else": "x"},
		"negative index": map[string]any{
			"status_list": map[string]any{"idx": int64(-1), "uri": "https://registry.example.com/statuslists/1"},
		},
	}

	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			doc := docWithMSOStatus(t, base, status)

			ref, err := ExtractStatusReference(doc)
			if err == nil {
				t.Fatalf("an unreadable status parameter must be an error, got ref=%+v", ref)
			}
			if errors.Is(err, ErrNoStatusReference) {
				t.Fatalf("an unreadable status must not be reported as an absent one: %v", err)
			}
		})
	}
}

// TestAbsentMSOStatusIsErrNoStatusReference keeps the other half honest:
// the sentinel must still be what an ordinary non-revocable credential
// produces, or the caller would refuse every credential.
func TestAbsentMSOStatusIsErrNoStatusReference(t *testing.T) {
	doc := issueWithStatus(t, nil)
	if _, err := ExtractStatusReference(doc); !errors.Is(err, ErrNoStatusReference) {
		t.Fatalf("expected ErrNoStatusReference for a credential with no status, got %v", err)
	}
}
