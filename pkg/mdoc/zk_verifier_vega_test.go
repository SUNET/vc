package mdoc

// Unit tests for the Vega comparison logic (checkVegaIssuerKeyMatches /
// checkVegaDisclosedClaimsMatchWire / checkVegaValidityWindow) - pure Go
// functions, testable without the "zknative" build tag or any native
// library, independent of the full cgo/subprocess round trip already
// verified end-to-end in pkg/mdoc/zknative_vega's own tests.

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/mdoc/zkvegaworker"
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

// buildVegaPlaintext CBOR-encodes a vegaIssuerSignedItemPlaintext - the
// shape zk-cred-vega's verify returns as a disclosed claim's plaintext
// bytes (the full original IssuerSignedItem, not just elementValue).
func buildVegaPlaintext(t *testing.T, digestID uint32, identifier string, value any) []byte {
	t.Helper()
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder: %v", err)
	}
	b, err := encoder.Marshal(vegaIssuerSignedItemPlaintext{
		DigestID:          digestID,
		Random:            []byte{0x01, 0x02, 0x03},
		ElementIdentifier: identifier,
		ElementValue:      value,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

func TestCheckVegaDisclosedClaimsMatchWire(t *testing.T) {
	t.Run("matching disclosed claim succeeds", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(26)},
				},
			},
		}
		claims := []zkvegaworker.DisclosedClaim{
			{Disclosed: true, DigestID: 26, Plaintext: buildVegaPlaintext(t, 26, "given_name", "Jane")},
		}
		if err := checkVegaDisclosedClaimsMatchWire(dd, claims); err != nil {
			t.Fatalf("expected match, got error: %v", err)
		}
	})

	t.Run("wire value not matching proof-disclosed value is rejected", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(26)},
				},
			},
		}
		claims := []zkvegaworker.DisclosedClaim{
			// Proof actually attests a DIFFERENT value than what the wire
			// declares for the same digestId - the exact attack this check
			// exists to catch.
			{Disclosed: true, DigestID: 26, Plaintext: buildVegaPlaintext(t, 26, "given_name", "NotJane")},
		}
		if err := checkVegaDisclosedClaimsMatchWire(dd, claims); err == nil {
			t.Fatal("expected value mismatch to be rejected")
		}
	})

	t.Run("wire claim with no matching disclosed proof slot is rejected", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(26)},
				},
			},
		}
		claims := []zkvegaworker.DisclosedClaim{
			// The proof never disclosed digestId 26 at all.
			{Disclosed: false, DigestID: 26, Plaintext: nil},
		}
		if err := checkVegaDisclosedClaimsMatchWire(dd, claims); err == nil {
			t.Fatal("expected undisclosed-on-proof claim to be rejected")
		}
	})

	t.Run("wire item missing digestId is rejected", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: nil},
				},
			},
		}
		claims := []zkvegaworker.DisclosedClaim{
			{Disclosed: true, DigestID: 26, Plaintext: buildVegaPlaintext(t, 26, "given_name", "Jane")},
		}
		if err := checkVegaDisclosedClaimsMatchWire(dd, claims); err == nil {
			t.Fatal("expected missing-digestId wire item to be rejected")
		}
	})

	t.Run("undisclosed proof claims not on the wire are ignored", func(t *testing.T) {
		dd := &ZkDocumentDataMdoc{
			IssuerSigned: map[string][]ZkSignedItemMdoc{
				Namespace: {
					{ElementIdentifier: "given_name", ElementValue: "Jane", DigestID: digestIDPtr(26)},
				},
			},
		}
		claims := []zkvegaworker.DisclosedClaim{
			{Disclosed: true, DigestID: 26, Plaintext: buildVegaPlaintext(t, 26, "given_name", "Jane")},
			// A second, undisclosed slot the wallet chose not to reveal -
			// harmless, must not cause a rejection.
			{Disclosed: false, DigestID: 300, Plaintext: nil},
		}
		if err := checkVegaDisclosedClaimsMatchWire(dd, claims); err != nil {
			t.Fatalf("expected undisclosed unrelated claim to be ignored, got error: %v", err)
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
