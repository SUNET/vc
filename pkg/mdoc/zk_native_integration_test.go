//go:build zknative

package mdoc

// Real, end-to-end integration test for the "zknative" build: exercises
// nativeVerifyZkProofWithPPID itself (circuit resolution via
// pkg/mdoc/zkcircuit against the live https://zk-circuits.fly.dev catalog,
// the verifier cache in zk_native_cgo.go, and the cgo call into
// zk-cred-longfellow via pkg/mdoc/zknative) against a REAL, known-good V8
// pairwise-pseudonym (PPID) proof - not just the lower-level cgo wrapper
// (see pkg/mdoc/zknative's own test for that).
//
// Fixtures (pkg/mdoc/testdata/zk_native/*) are the same ones used by
// pkg/mdoc/zknative's test - see that test file's doc comment for
// provenance/regeneration instructions.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const zkNativeTestCircuitID = "longfellow-libzk-v1_8_2_4307_2945"

func readZkNativeFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "zk_native", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

// TestNativeVerifyZkProofWithPPID_RealCircuitAndProof confirms the actual
// wiring this change adds - circuit resolution from a presented zkSystemId
// through to a real native verify call - works end to end, using the exact
// same entry point ZkHandler.verifyOneDocument calls.
func TestNativeVerifyZkProofWithPPID_RealCircuitAndProof(t *testing.T) {
	docType := strings.TrimSpace(string(readZkNativeFixture(t, "doc_type.txt")))
	timeStr := strings.TrimSpace(string(readZkNativeFixture(t, "time.txt")))
	issuerPK := readZkNativeFixture(t, "issuer_pk.bin")
	givenNameCBOR := readZkNativeFixture(t, "given_name_cbor.bin")
	ppidCBOR := readZkNativeFixture(t, "ppid_cbor.bin")
	transcript := readZkNativeFixture(t, "transcript.bin")
	verifierContext := readZkNativeFixture(t, "verifier_context.bin")
	proof := readZkNativeFixture(t, "proof.bin")

	attributes := []ZkAttribute{
		{Identifier: "given_name", ValueCBOR: givenNameCBOR},
		{Identifier: "pairwise_pseudonym", ValueCBOR: ppidCBOR},
	}
	deviceNameSpacesBytes := []byte{0xa0} // empty CBOR map

	ctx := context.Background()

	err := nativeVerifyZkProofWithPPID(
		ctx, zkNativeTestCircuitID, issuerPK, attributes, docType,
		deviceNameSpacesBytes, transcript, timeStr, verifierContext, proof, nil,
	)
	if err != nil {
		if strings.Contains(err.Error(), "fetching circuit descriptor") {
			t.Skipf("zk-circuits.fly.dev unreachable, skipping live test: %v", err)
		}
		t.Fatalf("expected genuine proof to verify via the real wiring, got: %v", err)
	}

	// A second call must hit the verifier cache, not re-fetch/re-load the
	// circuit (this also confirms the cache doesn't somehow invalidate a
	// working verifier after one use).
	err = nativeVerifyZkProofWithPPID(
		ctx, zkNativeTestCircuitID, issuerPK, attributes, docType,
		deviceNameSpacesBytes, transcript, timeStr, verifierContext, proof, nil,
	)
	if err != nil {
		t.Fatalf("expected second call (cached verifier) to succeed, got: %v", err)
	}

	// A tampered proof must be rejected with a real error, not silently
	// accepted.
	tampered := append([]byte(nil), proof...)
	tampered[len(tampered)-1] ^= 0xff
	err = nativeVerifyZkProofWithPPID(
		ctx, zkNativeTestCircuitID, issuerPK, attributes, docType,
		deviceNameSpacesBytes, transcript, timeStr, verifierContext, tampered, nil,
	)
	if err == nil {
		t.Fatal("expected tampered proof to be rejected")
	}

	// Wrong attribute count must be rejected by this file's own
	// pre-VerifyWithPPID check, with a message naming the mismatch.
	err = nativeVerifyZkProofWithPPID(
		ctx, zkNativeTestCircuitID, issuerPK, attributes[:1], docType,
		deviceNameSpacesBytes, transcript, timeStr, verifierContext, proof, nil,
	)
	if err == nil {
		t.Fatal("expected wrong attribute count to be rejected")
	}
	if !strings.Contains(err.Error(), "expects 2 attribute") {
		t.Errorf("expected an attribute-count error, got: %v", err)
	}
}

// TestNativeVerifyZkProof_NonPPIDStillNotImplemented confirms the non-PPID
// direction still returns a clear, distinct ErrNativeZkVerifyNotImplemented
// even under the "zknative" tag (see zk_native_cgo.go's doc comment: no
// plain verify function exists in zk-cred-longfellow's Go C ABI yet).
func TestNativeVerifyZkProof_NonPPIDStillNotImplemented(t *testing.T) {
	err := nativeVerifyZkProof(
		context.Background(), zkNativeTestCircuitID, nil, nil, "doc", nil, nil, "", nil, nil,
	)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrNativeZkVerifyNotImplemented) {
		t.Errorf("expected ErrNativeZkVerifyNotImplemented, got: %v", err)
	}
}
