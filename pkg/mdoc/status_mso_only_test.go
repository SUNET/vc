package mdoc

import (
	"errors"
	"testing"
)

// docWithStatusElementOnly is a legacy-shaped mdoc: no MSO status
// parameter, and a "status" issuer-signed DATA ELEMENT instead. Real
// implementations that predate draft-ietf-oauth-status-list Section 6.3
// put the reference there.
//
// IssuerAuth is a stub: statusFromMSO treats a document whose IssuerAuth
// will not parse as "no MSO status", which is the case being modelled -
// such a document fails verification for its own reasons long before
// anything asks about revocation.
func docWithStatusElementOnly() *DocumentMdoc {
	return &DocumentMdoc{
		DocType: DocType,
		IssuerSigned: IssuerSignedMdoc{
			NameSpaces: map[string][]any{
				Namespace: {
					IssuerSignedItem{
						DigestID:          0,
						Random:            make([]byte, 16),
						ElementIdentifier: "status",
						ElementValue: map[string]any{
							"status_list": map[string]any{
								"uri": "https://legacy.example.com/statuslists/1",
								"idx": int64(42),
							},
						},
					},
				},
			},
			IssuerAuth: []any{0xD2},
		},
	}
}

// TestExtractMSOStatusReference_IgnoresTheDataElement is the point of the
// split. A "status" data element is selectively disclosed, so a holder
// presenting a REVOKED credential simply leaves it out and the verifier
// sees a credential that is not revocable - and cannot tell. The MSO's
// ValueDigests name withheld elements by digestID only, so the identifier
// is exactly what a verifier cannot recover.
//
// A reference that only ever arrives when the holder allows it is not a
// revocation check, and reading one made vc's coverage look uniform across
// mdoc issuers when it is not.
func TestExtractMSOStatusReference_IgnoresTheDataElement(t *testing.T) {
	doc := docWithStatusElementOnly()

	// The fixture's own precondition: the fallback really does find this,
	// so the assertion below is about the new function and not about a
	// fixture that carries nothing.
	ref, err := ExtractStatusReference(doc)
	if err != nil {
		t.Fatalf("fixture does not carry a readable fallback reference: %v", err)
	}
	if ref.URI != "https://legacy.example.com/statuslists/1" {
		t.Fatalf("fixture reference = %+v", ref)
	}

	if _, err := ExtractMSOStatusReference(doc); !errors.Is(err, ErrNoStatusReference) {
		t.Fatalf("ExtractMSOStatusReference must report no reference, got %v", err)
	}
}

// TestExtractDocumentClaims_CarriesNoLegacyStatus: the whole reason the
// split exists is the verification path, so assert there too rather than
// only on the extractor. A claims map with no "status" is what
// revocation.Registry then sees.
func TestExtractDocumentClaims_CarriesNoLegacyStatus(t *testing.T) {
	handler := &MDocHandler{}

	claims, err := handler.extractDocumentClaims(docWithStatusElementOnly())
	if err != nil {
		t.Fatalf("extractDocumentClaims: %v", err)
	}
	if claims.Status != nil {
		t.Fatalf("a selectively disclosable reference must not become the credential's status: %+v", claims.Status)
	}
	if _, present := claims.GetClaims()["status"]; present {
		t.Fatal("and it must not reach the claims map the revocation registry reads")
	}
	// The element itself is still surfaced - this removes a revocation
	// decision, not data. It keeps its namespace-qualified key and its
	// place in Namespaces; only the bare "status" key, which every format
	// reserves for the reference, is withheld from it.
	if _, present := claims.Namespaces[Namespace]["status"]; !present {
		t.Fatal("the data element itself should still be presented as a claim")
	}
	if _, present := claims.GetClaims()[Namespace+".status"]; !present {
		t.Fatal("and under its namespace-qualified key in the flat map")
	}
}

// TestGetClaims_MSOStatusStillWins is the other direction, and the one that
// was already right: when the MSO does carry a reference it is what the
// "status" key holds, whatever a data element of the same name says.
func TestGetClaims_MSOStatusStillWins(t *testing.T) {
	handler := &MDocHandler{}
	claims, err := handler.extractDocumentClaims(docWithStatusElementOnly())
	if err != nil {
		t.Fatalf("extractDocumentClaims: %v", err)
	}
	claims.Status = &StatusReference{URI: "https://issuer.example.com/statuslists/9", Index: 7}

	status, ok := claims.GetClaims()["status"].(map[string]any)
	if !ok {
		t.Fatalf("no status claim: %+v", claims.GetClaims()["status"])
	}
	list, ok := status["status_list"].(map[string]any)
	if !ok {
		t.Fatalf("no status_list member: %+v", status)
	}
	if list["uri"] != "https://issuer.example.com/statuslists/9" {
		t.Fatalf("the MSO reference must win over the data element, got %v", list["uri"])
	}
}
