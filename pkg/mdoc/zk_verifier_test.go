package mdoc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
// handling, and still reach (only) the native-stub error.
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
	})
	if !errors.Is(err, ErrNativeZkVerifyNotImplemented) {
		t.Errorf("VerifyAndExtract() error = %v, want ErrNativeZkVerifyNotImplemented", err)
	}
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
