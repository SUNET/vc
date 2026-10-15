package mdoc

import (
	"errors"
	"testing"
)

// docWithStatusElementOnly is a legacy-shaped mdoc: a real, decodable MSO
// that carries no status parameter, and a "status" issuer-signed DATA
// ELEMENT instead. Real implementations that predate
// draft-ietf-oauth-status-list Section 6.3 put the reference there.
//
// Built from a genuinely issued document rather than from a stub. An
// earlier version used an IssuerAuth that would not parse, which worked
// only because statusFromMSO swallowed the decode failure and reported
// "no MSO status" - the very conflation that swallow has been removed
// for. A fixture standing on the defect cannot be evidence about it.
//
// The data element is appended without a matching MSO digest, which is
// fine here: nothing in these tests verifies digests, they ask only where
// a document says its status lives.
func docWithStatusElementOnly(t *testing.T) *DocumentMdoc {
	t.Helper()
	doc := issueWithStatus(t, nil)
	doc.IssuerSigned.NameSpaces[Namespace] = append(doc.IssuerSigned.NameSpaces[Namespace],
		IssuerSignedItem{
			DigestID:          9999,
			Random:            make([]byte, 16),
			ElementIdentifier: "status",
			ElementValue: map[string]any{
				"status_list": map[string]any{
					"uri": "https://legacy.example.com/statuslists/1",
					"idx": int64(42),
				},
			},
		})
	return doc
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
	doc := docWithStatusElementOnly(t)

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

	claims, err := handler.extractDocumentClaims(docWithStatusElementOnly(t))
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
	claims, err := handler.extractDocumentClaims(docWithStatusElementOnly(t))
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

// An MSO whose status member has the wrong CBOR shape must be an error,
// not "this credential is not revocable".
//
// The MSO's status field is typed, so a wrong shape fails the decode of
// the WHOLE MSO - which statusFromMSO used to swallow into (nil, nil).
// ExtractMSOStatusReference then reported ErrNoStatusReference, the
// caller left claims.Status nil, no "status" claim was emitted, and the
// credential verified as permanently valid. With a fail-open revocation
// policy that is a revoked credential accepted; without one it is still a
// credential whose state is unknown being treated as known-good.
//
// The swallow was justified by the document failing verification first,
// which is true today and by coincidence: VerifyDeviceResponse happens to
// decode the MSO with this same DecodeMSOPayload and happens to return
// early. TestMalformedMSOStatusIsRefusedByVerificationToo pins that
// second line of defence; this one pins the helper's own.
func TestExtractMSOStatusReference_RefusesAnUnreadableMSO(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status any
	}{
		{"a text string where an object belongs", "revoked"},
		{"an array", []any{1, 2}},
		{"status_list as a string", map[string]any{"status_list": "https://x/1#4"}},
		{"idx as a string", map[string]any{"status_list": map[string]any{"uri": "https://x/1", "idx": "4"}}},
		{"an integer", int64(7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := docWithMSOStatus(t, issueWithStatus(t, nil), tc.status)

			// The fixture's precondition: this really is the decode
			// failure being modelled, not some other refusal.
			sign1, err := ParseIssuerAuth(doc.IssuerSigned.IssuerAuth)
			if err != nil {
				t.Fatalf("ParseIssuerAuth: %v", err)
			}
			if _, err := DecodeMSOPayload(sign1); err == nil {
				t.Fatal("this status shape decodes, so it does not exercise the case")
			}

			ref, err := ExtractMSOStatusReference(doc)
			if err == nil {
				t.Fatalf("an unreadable MSO must be refused, got reference %+v", ref)
			}
			if errors.Is(err, ErrNoStatusReference) {
				t.Fatal("an unreadable status parameter must not be reported as an absent one: the credential claims to be revocable and its state is unknown")
			}

			// And the caller refuses the document rather than carrying a
			// nil status forward.
			handler := &MDocHandler{}
			claims, err := handler.extractDocumentClaims(doc)
			if err == nil {
				t.Fatalf("extractDocumentClaims must refuse it, got claims with status %+v", claims.Status)
			}
		})
	}
}

// The diagnostic keeps its leniency, and only it. tsl_checker asks "where
// does this document say its status lives" about documents an operator
// supplies by hand, which is still worth answering when the MSO will not
// decode.
func TestExtractStatusReference_StillFallsBackWhenTheMSOWillNotDecode(t *testing.T) {
	doc := docWithStatusElementOnly(t)
	doc.IssuerSigned.IssuerAuth = []any{0xD2} // will not parse

	ref, err := ExtractStatusReference(doc)
	if err != nil {
		t.Fatalf("the diagnostic must still try the data element: %v", err)
	}
	if ref.URI != "https://legacy.example.com/statuslists/1" {
		t.Fatalf("ref = %+v, want the data element's reference", ref)
	}

	// The verification entry point answers the other way for the same
	// document, which is the whole point of the split.
	if _, err := ExtractMSOStatusReference(doc); err == nil || errors.Is(err, ErrNoStatusReference) {
		t.Fatalf("ExtractMSOStatusReference must refuse an unreadable MSO, got %v", err)
	}
}

// The second line of defence, so the claim that this was never reachable
// through verifyAndExtract is a test rather than a reading.
//
// VerifyMSO decodes the MSO with the same DecodeMSOPayload and
// verifyDocumentWithContext returns early when it fails, so a document
// whose MSO will not decode is never valid and never reaches claim
// extraction.
//
// Rebuilding the MSO payload also invalidates the issuer's signature, so
// the refusal here arrives at the signature check a step earlier - which
// is itself worth stating: a status member can only be malformed if the
// ISSUER signed it that way, and that document is refused by the decode
// inside VerifyMSO. Either way it is refused, which is what this asserts.
func TestMalformedMSOStatusIsRefusedByVerificationToo(t *testing.T) {
	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)
	verifier, err := NewVerifier(VerifierConfig{
		TrustEvaluator:      trustEvaluator,
		SkipRevocationCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	response := createTestDeviceResponse(t, dsKey, certChain)
	if len(response.Documents) == 0 {
		t.Fatal("expected a document to mangle")
	}

	// The precondition: unmangled, this document verifies. Without it a
	// refusal below would say nothing.
	if result := verifier.VerifyDocument(&response.Documents[0]); !result.Valid {
		t.Fatalf("the unmangled fixture must verify, errors: %v", result.Errors)
	}

	mangled := docWithMSOStatus(t, &response.Documents[0], "revoked")
	if result := verifier.VerifyDocument(mangled); result.Valid {
		t.Fatal("a document whose MSO will not decode must not verify")
	}
}
