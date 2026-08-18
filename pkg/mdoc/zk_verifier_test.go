package mdoc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
)

const testZkSystemID = "longfellow-libzk-v1_8_1_4259_2945"

func encodeTestZkVPToken(t *testing.T, dd ZkDocumentDataMdoc, proof []byte) string {
	t.Helper()
	data := encodeTestZkDeviceResponse(t, dd, proof)
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestNewZkHandler_MissingTrustEvaluator(t *testing.T) {
	_, err := NewZkHandler(ZkVerifierConfig{})
	if err == nil {
		t.Error("NewZkHandler() expected error for missing TrustEvaluator, got nil")
	}
}

func TestZkHandler_VerifyAndExtract_UntrustedIssuer(t *testing.T) {
	cert := createTestZkCert(t)
	dd := buildTestZkDocumentData(t, cert, testZkSystemID, false)
	vpToken := encodeTestZkVPToken(t, dd, []byte{0x01})

	handler, err := NewZkHandler(ZkVerifierConfig{TrustEvaluator: createTestTrustEvaluator(false)})
	if err != nil {
		t.Fatalf("NewZkHandler() error = %v", err)
	}

	_, err = handler.VerifyAndExtract(context.Background(), vpToken, ZkPresentationContext{
		SessionID:          "session-1",
		RequestedZkSystems: []openid4vp.ZKSystemTypeSpec{{ID: testZkSystemID, System: "longfellow-libzk-v1"}},
		SessionTranscript:  []byte{0xA0},
	})
	if err == nil {
		t.Fatal("VerifyAndExtract() expected error for untrusted issuer, got nil")
	}
	if errors.Is(err, ErrNativeZkVerifyNotImplemented) {
		t.Errorf("VerifyAndExtract() error should be a trust failure, not the native-stub error: %v", err)
	}
}

func TestZkHandler_VerifyAndExtract_ZkSystemTypeMismatch(t *testing.T) {
	cert := createTestZkCert(t)
	dd := buildTestZkDocumentData(t, cert, testZkSystemID, false)
	vpToken := encodeTestZkVPToken(t, dd, []byte{0x01})

	handler, err := NewZkHandler(ZkVerifierConfig{TrustEvaluator: createTestTrustEvaluator(true)})
	if err != nil {
		t.Fatalf("NewZkHandler() error = %v", err)
	}

	_, err = handler.VerifyAndExtract(context.Background(), vpToken, ZkPresentationContext{
		SessionID: "session-1",
		// Deliberately does not include testZkSystemID.
		RequestedZkSystems: []openid4vp.ZKSystemTypeSpec{{ID: "some-other-circuit", System: "longfellow-libzk-v1"}},
		SessionTranscript:  []byte{0xA0},
	})
	if err == nil {
		t.Fatal("VerifyAndExtract() expected error for zk_system_type mismatch, got nil")
	}
	if errors.Is(err, ErrNativeZkVerifyNotImplemented) {
		t.Errorf("VerifyAndExtract() error should be a zk_system_type mismatch, not the native-stub error: %v", err)
	}
}

func TestZkHandler_VerifyAndExtract_MissingSessionTranscript(t *testing.T) {
	cert := createTestZkCert(t)
	dd := buildTestZkDocumentData(t, cert, testZkSystemID, false)
	vpToken := encodeTestZkVPToken(t, dd, []byte{0x01})

	handler, err := NewZkHandler(ZkVerifierConfig{TrustEvaluator: createTestTrustEvaluator(true)})
	if err != nil {
		t.Fatalf("NewZkHandler() error = %v", err)
	}

	_, err = handler.VerifyAndExtract(context.Background(), vpToken, ZkPresentationContext{
		SessionID:          "session-1",
		RequestedZkSystems: []openid4vp.ZKSystemTypeSpec{{ID: testZkSystemID, System: "longfellow-libzk-v1"}},
	})
	if err == nil {
		t.Fatal("VerifyAndExtract() expected error for missing SessionTranscript, got nil")
	}
}

// TestZkHandler_VerifyAndExtract_ReachesNativeStub confirms that once trust
// evaluation and zk_system_type matching both succeed, the ONLY thing
// stopping full verification is the native ZK binding gap - i.e. the
// plumbing this change adds is real, and the remaining gap is exactly and
// only ErrNativeZkVerifyNotImplemented.
func TestZkHandler_VerifyAndExtract_ReachesNativeStub(t *testing.T) {
	cert := createTestZkCert(t)
	dd := buildTestZkDocumentData(t, cert, testZkSystemID, false)
	vpToken := encodeTestZkVPToken(t, dd, []byte{0x01, 0x02, 0x03})

	handler, err := NewZkHandler(ZkVerifierConfig{TrustEvaluator: createTestTrustEvaluator(true)})
	if err != nil {
		t.Fatalf("NewZkHandler() error = %v", err)
	}

	_, err = handler.VerifyAndExtract(context.Background(), vpToken, ZkPresentationContext{
		SessionID:          "session-1",
		RequestedZkSystems: []openid4vp.ZKSystemTypeSpec{{ID: testZkSystemID, System: "longfellow-libzk-v1"}},
		SessionTranscript:  []byte{0xA0},
		RequestedClaimIDs:  []string{"given_name"},
	})
	if err == nil {
		t.Fatal("VerifyAndExtract() expected the native-stub error, got nil")
	}
	if !errors.Is(err, ErrNativeZkVerifyNotImplemented) {
		t.Errorf("VerifyAndExtract() error = %v, want ErrNativeZkVerifyNotImplemented", err)
	}
}

// TestZkHandler_VerifyAndExtract_PPIDPath is the same as
// TestZkHandler_VerifyAndExtract_ReachesNativeStub but for a document that
// disclosed a pairwise_pseudonym claim - it must take the
// verify_with_ppid/ComputeZkVerifierContext branch, not silently skip PPID
// handling. What happens next depends on the build:
//   - default (no "zknative" tag): nativeVerifyZkProofWithPPID is a stub,
//     so this reaches (only) ErrNativeZkVerifyNotImplemented - checked by
//     assertZkPPIDPathOutcome in zk_verifier_stub_test.go.
//   - "zknative" tag: nativeVerifyZkProofWithPPID is real and actually
//     attempts verification (with this test's deliberately-bogus
//     cert/proof and a circuit-id/attribute-count mismatch - testZkSystemID
//     is the 1-attribute circuit but this fixture discloses 2 attributes),
//     so it must fail for a REAL reason, NOT
//     ErrNativeZkVerifyNotImplemented - checked by assertZkPPIDPathOutcome
//     in zk_verifier_native_test.go. See docs/ZK_PPID_VERIFICATION_PLAN.md.
func TestZkHandler_VerifyAndExtract_PPIDPath(t *testing.T) {
	cert := createTestZkCert(t)
	dd := buildTestZkDocumentData(t, cert, testZkSystemID, true /* includePseudonym */)
	vpToken := encodeTestZkVPToken(t, dd, []byte{0x01})

	handler, err := NewZkHandler(ZkVerifierConfig{TrustEvaluator: createTestTrustEvaluator(true)})
	if err != nil {
		t.Fatalf("NewZkHandler() error = %v", err)
	}

	_, err = handler.VerifyAndExtract(context.Background(), vpToken, ZkPresentationContext{
		SessionID:          "session-1",
		PPIDContext:        "https://relying-party.example",
		RequestedZkSystems: []openid4vp.ZKSystemTypeSpec{{ID: testZkSystemID, System: "longfellow-libzk-v1"}},
		SessionTranscript:  []byte{0xA0},
		RequestedClaimIDs:  []string{"given_name"},
	})
	assertZkPPIDPathOutcome(t, err)
}

func TestComputeZkVerifierContext_Deterministic(t *testing.T) {
	a := ComputeZkVerifierContext("session-1", "client-1", "ctx")
	b := ComputeZkVerifierContext("session-1", "client-1", "ctx")
	if a != b {
		t.Errorf("ComputeZkVerifierContext() not deterministic: %x != %x", a, b)
	}
}

func TestComputeZkVerifierContext_SessionIDPreferredOverClientID(t *testing.T) {
	withSession := ComputeZkVerifierContext("session-1", "client-1", "")
	withDifferentClientSameSession := ComputeZkVerifierContext("session-1", "client-2", "")
	if withSession != withDifferentClientSameSession {
		t.Error("ComputeZkVerifierContext() should ignore ClientID when SessionID is set")
	}

	withoutSession := ComputeZkVerifierContext("", "client-1", "")
	withDifferentSessionEmpty := ComputeZkVerifierContext("", "client-2", "")
	if withoutSession == withDifferentSessionEmpty {
		t.Error("ComputeZkVerifierContext() should fall back to ClientID when SessionID is empty")
	}
}

func TestComputeZkVerifierContext_PPIDContextChangesResult(t *testing.T) {
	withoutContext := ComputeZkVerifierContext("session-1", "", "")
	withContext := ComputeZkVerifierContext("session-1", "", "some-context")
	if withoutContext == withContext {
		t.Error("ComputeZkVerifierContext() should differ when ppidContext is present vs absent")
	}
}

// TestComputeZkVerifierContext_MatchesDocumentedFormula pins the exact
// byte-level formula against an independent computation, so a future
// refactor can't silently drift from the confirmed wire format:
//
//	verifier_context = SHA256(SHA256(verifier_id) || SHA256-or-zero(ppid_context))
func TestComputeZkVerifierContext_MatchesDocumentedFormula(t *testing.T) {
	sessionID := "session-abc"
	ppidContext := "https://verifier.example"

	verifierIDHash := sha256.Sum256([]byte(sessionID))
	ppidContextHash := sha256.Sum256([]byte(ppidContext))
	want := sha256.Sum256(append(append([]byte{}, verifierIDHash[:]...), ppidContextHash[:]...))

	got := ComputeZkVerifierContext(sessionID, "", ppidContext)
	if got != want {
		t.Errorf("ComputeZkVerifierContext() = %x, want %x", got, want)
	}
}

func TestComputeZkVerifierContext_AbsentPPIDContextIsNotHashedEmptyString(t *testing.T) {
	sessionID := "session-abc"
	verifierIDHash := sha256.Sum256([]byte(sessionID))

	var zero [32]byte
	wantAbsent := sha256.Sum256(append(append([]byte{}, verifierIDHash[:]...), zero[:]...))

	emptyHash := sha256.Sum256([]byte(""))
	wantIfHashedEmptyString := sha256.Sum256(append(append([]byte{}, verifierIDHash[:]...), emptyHash[:]...))

	got := ComputeZkVerifierContext(sessionID, "", "")
	if got != wantAbsent {
		t.Errorf("ComputeZkVerifierContext() with absent ppidContext = %x, want %x (zero-bytes fallback)", got, wantAbsent)
	}
	if got == wantIfHashedEmptyString {
		t.Error("ComputeZkVerifierContext() must not hash an empty string for absent ppidContext")
	}
}

// TestDeviceSignedToWireMap_CBOREncodingIsDeterministic guards against a
// real bug: device_name_spaces_bytes must byte-match the canonical CBOR
// encoding a real wallet's own canonical encoder produced when it built
// the ZK proof. deviceSignedToWireMap returns a genuine Go map
// (map[string]map[string]any), and Go deliberately randomizes map
// iteration order - encoding it with the CBOR library's plain
// package-level Marshal (SortNone) would silently produce different
// bytes across calls for any document with more than one
// namespace/element, which is exactly what this multi-namespace,
// multi-element case exercises. The fix (this package's canonical
// NewCBOREncoder(), used here) must always sort map keys regardless of
// Go's map iteration order.
func TestDeviceSignedToWireMap_CBOREncodingIsDeterministic(t *testing.T) {
	deviceSigned := map[string][]ZkSignedItemMdoc{
		"org.iso.18013.5.1": {
			{ElementIdentifier: "given_name", ElementValue: "Alice"},
			{ElementIdentifier: "family_name", ElementValue: "Doe"},
			{ElementIdentifier: "age_over_18", ElementValue: true},
		},
		"eu.europa.ec.eudi.pid.1": {
			{ElementIdentifier: "birth_date", ElementValue: "1990-01-01"},
			{ElementIdentifier: "nationality", ElementValue: "SE"},
		},
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder: %v", err)
	}

	var first []byte
	for i := 0; i < 50; i++ {
		// Rebuild the map fresh each iteration - Go's map iteration order
		// is randomized per range statement, so reusing one map instance
		// wouldn't meaningfully re-exercise the ordering risk.
		wireMap := deviceSignedToWireMap(deviceSigned)
		encoded, err := encoder.Marshal(wireMap)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if i == 0 {
			first = encoded
			continue
		}
		if !bytes.Equal(first, encoded) {
			t.Fatalf("iteration %d: CBOR encoding of deviceSignedToWireMap output is non-deterministic\nfirst: %x\ngot:   %x", i, first, encoded)
		}
	}
}

// TestBuildZkAttributes_StructuredValueCBOREncodingIsDeterministic mirrors
// TestDeviceSignedToWireMap_CBOREncodingIsDeterministic for
// buildZkAttributes: an mdoc element's value can itself decode as a Go map
// (structured claims), so value_cbor must also go through the canonical
// encoder rather than the CBOR library's plain, order-unstable default.
func TestBuildZkAttributes_StructuredValueCBOREncodingIsDeterministic(t *testing.T) {
	issuerSigned := map[string]map[string]any{
		"org.iso.18013.5.1": {
			"driving_privileges": map[string]any{
				"vehicle_category_code": "B",
				"issue_date":            "2020-01-01",
				"expiry_date":           "2030-01-01",
				"codes":                 "none",
			},
		},
	}

	var first []byte
	for i := 0; i < 50; i++ {
		attributes, _, err := buildZkAttributes(issuerSigned, []string{"driving_privileges"})
		if err != nil {
			t.Fatalf("buildZkAttributes: %v", err)
		}
		if len(attributes) != 1 {
			t.Fatalf("expected 1 attribute, got %d", len(attributes))
		}
		encoded := attributes[0].ValueCBOR
		if i == 0 {
			first = encoded
			continue
		}
		if !bytes.Equal(first, encoded) {
			t.Fatalf("iteration %d: value_cbor for a structured attribute is non-deterministic\nfirst: %x\ngot:   %x", i, first, encoded)
		}
	}
}

// TestBuildZkAttributes_RejectsWrongTypePseudonymClaim guards against a
// real gap: a document could carry a "pairwise_pseudonym"-identified claim
// whose CBOR value doesn't decode to []byte (malformed, or a wallet bug).
// Silently falling back to treating the document as non-PPID would route
// verification into nativeVerifyZkProof, which is unimplemented even under
// the "zknative" tag - producing a misleading
// ErrNativeZkVerifyNotImplemented instead of a clear error naming the
// actual problem.
func TestBuildZkAttributes_RejectsWrongTypePseudonymClaim(t *testing.T) {
	issuerSigned := map[string]map[string]any{
		"org.iso.18013.5.1": {
			"given_name":             "Alice",
			PseudonymClaimIdentifier: "not-bytes", // wrong CBOR type
		},
	}
	_, _, err := buildZkAttributes(issuerSigned, []string{"given_name"})
	if err == nil {
		t.Fatal("expected an error for a wrong-type pairwise_pseudonym claim, got nil")
	}
	if !strings.Contains(err.Error(), PseudonymClaimIdentifier) {
		t.Errorf("expected error to name %q, got: %v", PseudonymClaimIdentifier, err)
	}
}

// TestBuildZkAttributes_OrderMatchesRequestedClaimIDsWithPseudonymLast guards
// against the real, confirmed bug this fix addresses: buildZkAttributes used
// to derive attribute order from Go map iteration (randomized), but
// zk-cred-longfellow's native verifier matches attributes to circuit slots
// purely by position - a wrong order makes native verification of a
// genuinely valid proof fail. This exercises many namespaces/claims (so a
// single lucky map-iteration order can't mask a regression) and confirms:
// (1) order exactly matches RequestedClaimIDs, (2) it's identical across
// repeated calls regardless of Go's randomized map order, (3)
// pairwise_pseudonym always lands last even though it's stored in a
// different namespace than the requested claims and never appears in
// RequestedClaimIDs itself - mirroring siros-sdk-kotlin/siros-sdk-swift's
// `requestedClaims + PSEUDONYM_CLAIM` proving-side convention.
func TestBuildZkAttributes_OrderMatchesRequestedClaimIDsWithPseudonymLast(t *testing.T) {
	issuerSigned := map[string]map[string]any{
		"eu.europa.ec.eudi.pid.1": {
			"given_name":  "Helen",
			"family_name": "Mirren",
			"birth_date":  "1945-08-26",
			"age_over_18": true,
			"nationality": "GB",
		},
		"org.iso.18013.5.1": {
			PseudonymClaimIdentifier: []byte("0123456789abcdef0123456789abcdef"),
		},
	}
	requestedClaimIDs := []string{"family_name", "given_name", "age_over_18"}
	wantOrder := []string{"family_name", "given_name", "age_over_18", PseudonymClaimIdentifier}

	var firstIdentifiers []string
	for i := 0; i < 50; i++ {
		attributes, pseudonym, err := buildZkAttributes(issuerSigned, requestedClaimIDs)
		if err != nil {
			t.Fatalf("iteration %d: buildZkAttributes: %v", i, err)
		}
		if pseudonym == nil {
			t.Fatalf("iteration %d: expected a non-nil pseudonym", i)
		}
		gotIdentifiers := make([]string, len(attributes))
		for j, attr := range attributes {
			gotIdentifiers[j] = attr.Identifier
		}
		if i == 0 {
			firstIdentifiers = gotIdentifiers
			if !slices.Equal(gotIdentifiers, wantOrder) {
				t.Fatalf("attribute order = %v, want %v", gotIdentifiers, wantOrder)
			}
			continue
		}
		if !slices.Equal(gotIdentifiers, firstIdentifiers) {
			t.Fatalf("iteration %d: attribute order is non-deterministic\nfirst: %v\ngot:   %v", i, firstIdentifiers, gotIdentifiers)
		}
	}
}

// TestBuildZkAttributes_RejectsUndisclosedRequestedClaim guards against
// silently proceeding when a claim the DCQL request named wasn't actually
// disclosed - the old map-iteration-based version would have simply
// produced a shorter, silently-wrong attribute list instead of a clear
// error naming the missing claim.
func TestBuildZkAttributes_RejectsUndisclosedRequestedClaim(t *testing.T) {
	issuerSigned := map[string]map[string]any{
		"org.iso.18013.5.1": {
			"given_name": "Alice",
		},
	}
	_, _, err := buildZkAttributes(issuerSigned, []string{"given_name", "family_name"})
	if err == nil {
		t.Fatal("expected an error for a requested-but-undisclosed claim, got nil")
	}
	if !strings.Contains(err.Error(), "family_name") {
		t.Errorf("expected error to name the missing claim %q, got: %v", "family_name", err)
	}
}

// TestBuildZkAttributes_RejectsEmptyRequestedClaimIDs guards against
// silently guessing an order when the caller has no DCQL-derived ordering
// to supply (e.g. no cached DCQL query for this session) - failing loudly
// here is safer than falling back to any order this function might pick on
// its own, since native verification's positional matching would otherwise
// fail unpredictably instead of with a clear, attributable error.
func TestBuildZkAttributes_RejectsEmptyRequestedClaimIDs(t *testing.T) {
	issuerSigned := map[string]map[string]any{
		"org.iso.18013.5.1": {"given_name": "Alice"},
	}
	_, _, err := buildZkAttributes(issuerSigned, nil)
	if err == nil {
		t.Fatal("expected an error for empty requestedClaimIDs, got nil")
	}
}

// TestBuildZkAttributes_RejectsPseudonymInRequestedClaimIDs guards against a
// DCQL request that names "pairwise_pseudonym" explicitly in its claims list
// (which siros-sdk-kotlin/siros-sdk-swift never do - it's always appended
// separately) - accepting that would double it up at the wrong position
// rather than the required last slot.
func TestBuildZkAttributes_RejectsPseudonymInRequestedClaimIDs(t *testing.T) {
	issuerSigned := map[string]map[string]any{
		"org.iso.18013.5.1": {
			"given_name":             "Alice",
			PseudonymClaimIdentifier: []byte("0123456789abcdef0123456789abcdef"),
		},
	}
	_, _, err := buildZkAttributes(issuerSigned, []string{"given_name", PseudonymClaimIdentifier})
	if err == nil {
		t.Fatal("expected an error for pairwise_pseudonym appearing in requestedClaimIDs, got nil")
	}
}
