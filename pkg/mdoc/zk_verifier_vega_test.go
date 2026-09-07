package mdoc

// Unit tests for the Vega comparison logic (checkVegaIssuerKeyMatches /
// BuildVegaDisclosedBytes / checkVegaValidityWindow) - pure Go functions,
// testable without the "zknative" build tag or any native library,
// independent of the full cgo/subprocess round trip already verified
// end-to-end in pkg/mdoc/zknative_vega's own tests.

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func digestIDPtr(v uint32) *uint32 { return &v }

func TestCheckVegaIssuerKeyMatches(t *testing.T) {
	qx := make([]byte, 32)
	qy := make([]byte, 32)
	qx[31] = 0x01
	qy[31] = 0x02

	sec1 := append([]byte{0x04}, append(append([]byte{}, qx...), qy...)...)

	t.Run("matching key succeeds", func(t *testing.T) {
		if err := checkVegaIssuerKeyMatches(sec1, qx, qy); err != nil {
			t.Fatalf("expected match, got error: %v", err)
		}
	})

	t.Run("mismatched qx is rejected", func(t *testing.T) {
		wrongQx := make([]byte, 32)
		wrongQx[31] = 0xff
		if err := checkVegaIssuerKeyMatches(sec1, wrongQx, qy); err == nil {
			t.Fatal("expected mismatch to be rejected")
		}
	})

	t.Run("wrong-length SEC1 key is rejected", func(t *testing.T) {
		if err := checkVegaIssuerKeyMatches(sec1[:64], qx, qy); err == nil {
			t.Fatal("expected short SEC1 key to be rejected")
		}
	})

	t.Run("non-0x04-prefixed SEC1 key is rejected", func(t *testing.T) {
		compressed := append([]byte{0x02}, sec1[1:]...)
		if err := checkVegaIssuerKeyMatches(compressed, qx, qy); err == nil {
			t.Fatal("expected non-uncompressed SEC1 key to be rejected")
		}
	})
}

func TestBuildVegaDisclosedBytes(t *testing.T) {
	t.Run("disclosed slot gets its wire bytes, undisclosed slots are empty", func(t *testing.T) {
		givenNameBytes := []byte{0xd8, 0x18, 0x01, 0x02, 0x03}
		dd := &ZkDocumentDataMdoc{
			ClaimSlotDigestIds: []uint32{26, 300, 4444, 55555},
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(300), IssuerSignedItemBytes: givenNameBytes},
				},
			},
		}
		out, err := BuildVegaDisclosedBytes(dd)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if len(out) != 4 {
			t.Fatalf("expected 4 slots, got %d", len(out))
		}
		if len(out[0]) != 0 || len(out[2]) != 0 || len(out[3]) != 0 {
			t.Fatalf("expected undisclosed slots empty, got %v", out)
		}
		if !bytes.Equal(out[1], givenNameBytes) {
			t.Fatalf("expected slot 1 (digestId 300) to carry given_name's wire bytes, got %v", out[1])
		}
	})

	t.Run("wrong claimSlotDigestIds length is rejected", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			ClaimSlotDigestIds: []uint32{26, 300},
			IssuerSigned:       map[string][]ZkSignedItemMdoc{},
		}
		if _, err := BuildVegaDisclosedBytes(dd); err == nil {
			t.Fatal("expected wrong-length claimSlotDigestIds to be rejected")
		}
	})

	t.Run("missing claimSlotDigestIds (pre-r12 or non-Vega artifact) is rejected", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(26)},
				},
			},
		}
		if _, err := BuildVegaDisclosedBytes(dd); err == nil {
			t.Fatal("expected absent claimSlotDigestIds to be rejected")
		}
	})

	t.Run("disclosed wire item missing issuerSignedItemBytes is rejected", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			ClaimSlotDigestIds: []uint32{26, 300, 4444, 55555},
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(300)},
				},
			},
		}
		if _, err := BuildVegaDisclosedBytes(dd); err == nil {
			t.Fatal("expected missing issuerSignedItemBytes to be rejected")
		}
	})

	t.Run("wire claim whose digestId is absent from claimSlotDigestIds is rejected", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			// 300 (given_name's digestId below) is not one of these four.
			ClaimSlotDigestIds: []uint32{1, 2, 3, 4},
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(300), IssuerSignedItemBytes: []byte{0x01}},
				},
			},
		}
		if _, err := BuildVegaDisclosedBytes(dd); err == nil {
			t.Fatal("expected a wire claim with no matching circuit slot to be rejected")
		}
	})

	t.Run("wire item missing digestId is rejected", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			ClaimSlotDigestIds: []uint32{26, 300, 4444, 55555},
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: nil, IssuerSignedItemBytes: []byte{0x01}},
				},
			},
		}
		if _, err := BuildVegaDisclosedBytes(dd); err == nil {
			t.Fatal("expected missing-digestId wire item to be rejected")
		}
	})
}

func TestCheckVegaValidityWindow(t *testing.T) {
	validFrom := []byte("2026-01-01T00:00:00Z")
	validUntil := []byte("2027-01-01T00:00:00Z")

	t.Run("within window succeeds", func(t *testing.T) {
		now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		if err := checkVegaValidityWindow(validFrom, validUntil, now); err != nil {
			t.Fatalf("expected valid window, got error: %v", err)
		}
	})

	t.Run("before validFrom is rejected", func(t *testing.T) {
		now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		if err := checkVegaValidityWindow(validFrom, validUntil, now); err == nil {
			t.Fatal("expected not-yet-valid credential to be rejected")
		}
	})

	t.Run("after validUntil is rejected", func(t *testing.T) {
		now := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
		if err := checkVegaValidityWindow(validFrom, validUntil, now); err == nil {
			t.Fatal("expected expired credential to be rejected")
		}
	})

	t.Run("malformed timestamp is rejected", func(t *testing.T) {
		now := time.Now()
		if err := checkVegaValidityWindow([]byte("not-a-timestamp"), validUntil, now); err == nil {
			t.Fatal("expected malformed valid_from_ts to be rejected")
		}
	})
}

// buildVegaItemBytes builds a real #6.24(bstr .cbor IssuerSignedItem), the
// framing ISO 18013-5 specifies. Built through EncodedCBORBytes rather than
// hand-assembled so the test actually exercises the tag-24 unwrap path -
// a bare CBOR map here would silently take the fallback branch instead.
func buildVegaItemBytes(t *testing.T, digestID uint32, identifier string, value any) []byte {
	t.Helper()
	enc, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder: %v", err)
	}
	inner, err := enc.Marshal(vegaIssuerSignedItem{
		DigestID:          digestID,
		Random:            []byte("0123456789abcdef"),
		ElementIdentifier: identifier,
		ElementValue:      value,
	})
	if err != nil {
		t.Fatalf("marshal inner item: %v", err)
	}
	wrapped, err := enc.Marshal(EncodedCBORBytes(inner))
	if err != nil {
		t.Fatalf("wrap in tag 24: %v", err)
	}
	if len(wrapped) < 2 || wrapped[0] != 0xd8 || wrapped[1] != 0x18 {
		t.Fatalf("expected a tag-24 prefix, got % x", wrapped[:min(4, len(wrapped))])
	}
	return wrapped
}

func vegaWireDoc(items ...ZkSignedItemMdoc) *ZkDocumentDataMdoc {
	return &ZkDocumentDataMdoc{
		IssuerSigned: map[string][]ZkSignedItemMdoc{Namespace: items},
	}
}

// TestCheckVegaWireMatchesProofBoundItems covers the property that a
// successful verify() does NOT provide on its own: verify() authenticates
// the issuerSignedItemBytes, while the claims handed downstream come from
// the separate wire-declared elementIdentifier/elementValue fields.
func TestCheckVegaWireMatchesProofBoundItems(t *testing.T) {
	t.Run("agreeing wire and proof-bound item is accepted", func(t *testing.T) {
		dd := vegaWireDoc(ZkSignedItemMdoc{
			ElementIdentifier:     "given_name",
			ElementValue:          "Jane",
			DigestID:              digestIDPtr(300),
			IssuerSignedItemBytes: buildVegaItemBytes(t, 300, "given_name", "Jane"),
		})
		if err := checkVegaWireMatchesProofBoundItems(dd); err != nil {
			t.Fatalf("expected agreement to be accepted, got: %v", err)
		}
	})

	// The attack: bind the genuine bytes so verify() passes, then declare
	// something else on the wire.
	t.Run("lying elementValue is rejected", func(t *testing.T) {
		dd := vegaWireDoc(ZkSignedItemMdoc{
			ElementIdentifier:     "given_name",
			ElementValue:          "Mallory",
			DigestID:              digestIDPtr(300),
			IssuerSignedItemBytes: buildVegaItemBytes(t, 300, "given_name", "Jane"),
		})
		err := checkVegaWireMatchesProofBoundItems(dd)
		if err == nil {
			t.Fatal("a wire value that disagrees with the proof-bound value must be rejected")
		}
		if !strings.Contains(err.Error(), "elementValue") {
			t.Fatalf("error should name the mismatching field, got: %v", err)
		}
	})

	t.Run("lying elementIdentifier is rejected", func(t *testing.T) {
		// Relabelling is as damaging as changing the value: the identifier
		// becomes the claim key downstream, so age_over_21's bytes could be
		// presented as age_over_18.
		dd := vegaWireDoc(ZkSignedItemMdoc{
			ElementIdentifier:     "age_over_18",
			ElementValue:          true,
			DigestID:              digestIDPtr(300),
			IssuerSignedItemBytes: buildVegaItemBytes(t, 300, "age_over_21", true),
		})
		if err := checkVegaWireMatchesProofBoundItems(dd); err == nil {
			t.Fatal("a wire identifier that disagrees with the proof-bound one must be rejected")
		}
	})

	t.Run("lying digestId is rejected", func(t *testing.T) {
		dd := vegaWireDoc(ZkSignedItemMdoc{
			ElementIdentifier:     "given_name",
			ElementValue:          "Jane",
			DigestID:              digestIDPtr(301),
			IssuerSignedItemBytes: buildVegaItemBytes(t, 300, "given_name", "Jane"),
		})
		if err := checkVegaWireMatchesProofBoundItems(dd); err == nil {
			t.Fatal("a wire digestId that disagrees with the proof-bound one must be rejected")
		}
	})

	t.Run("absent wire digestId is rejected", func(t *testing.T) {
		dd := vegaWireDoc(ZkSignedItemMdoc{
			ElementIdentifier:     "given_name",
			ElementValue:          "Jane",
			DigestID:              nil,
			IssuerSignedItemBytes: buildVegaItemBytes(t, 300, "given_name", "Jane"),
		})
		if err := checkVegaWireMatchesProofBoundItems(dd); err == nil {
			t.Fatal("a missing wire digestId must be rejected, not treated as agreement")
		}
	})

	t.Run("undecodable issuerSignedItemBytes is rejected", func(t *testing.T) {
		dd := vegaWireDoc(ZkSignedItemMdoc{
			ElementIdentifier:     "given_name",
			ElementValue:          "Jane",
			DigestID:              digestIDPtr(300),
			IssuerSignedItemBytes: []byte{0xff, 0xff, 0xff},
		})
		if err := checkVegaWireMatchesProofBoundItems(dd); err == nil {
			t.Fatal("bytes that decode as neither framing must be rejected")
		}
	})

	// The bare-map framing is accepted deliberately - see
	// decodeVegaIssuerSignedItem's doc comment - and must compare identically.
	t.Run("bare-map framing is compared the same way", func(t *testing.T) {
		enc, err := NewCBOREncoder()
		if err != nil {
			t.Fatal(err)
		}
		bare, err := enc.Marshal(vegaIssuerSignedItem{
			DigestID:          300,
			Random:            []byte("0123456789abcdef"),
			ElementIdentifier: "given_name",
			ElementValue:      "Jane",
		})
		if err != nil {
			t.Fatal(err)
		}

		ok := vegaWireDoc(ZkSignedItemMdoc{
			ElementIdentifier: "given_name", ElementValue: "Jane",
			DigestID: digestIDPtr(300), IssuerSignedItemBytes: bare,
		})
		if err := checkVegaWireMatchesProofBoundItems(ok); err != nil {
			t.Fatalf("bare map that agrees should be accepted, got: %v", err)
		}

		lying := vegaWireDoc(ZkSignedItemMdoc{
			ElementIdentifier: "given_name", ElementValue: "Mallory",
			DigestID: digestIDPtr(300), IssuerSignedItemBytes: bare,
		})
		if err := checkVegaWireMatchesProofBoundItems(lying); err == nil {
			t.Fatal("bare map that disagrees must still be rejected")
		}
	})
}

// TestBuildVegaDisclosedBytesRejectsDuplicateSlots: a digestId in two slots
// would put one item's bytes in both, building a differently-shaped input
// than the credential the proof was made over - and the existing
// "every disclosed item is bound" check would not notice, since it only
// asks whether each item was used at all.
func TestBuildVegaDisclosedBytesRejectsDuplicateSlots(t *testing.T) {
	dd := &ZkDocumentDataMdoc{
		ClaimSlotDigestIds: []uint32{26, 300, 300, 55555},
		IssuerSigned: map[string][]ZkSignedItemMdoc{
			Namespace: {
				{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(300), IssuerSignedItemBytes: []byte{0x01}},
			},
		},
	}
	_, err := BuildVegaDisclosedBytes(dd)
	if err == nil {
		t.Fatal("a duplicated digestId in claimSlotDigestIds must be rejected")
	}
	if !strings.Contains(err.Error(), "both slot 1 and slot 2") {
		t.Fatalf("error should name both slots, got: %v", err)
	}
}
