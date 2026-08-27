//go:build zknative

package zknative_vega

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// This test is a REAL end-to-end exercise of the cgo boundary: it loads a
// real, published-shaped verifier key and a real proof over it, both
// produced by zk-cred-vega's own already-tested safe Rust API, and
// verifies the proof through the actual C ABI, from actual Go.
//
// Fixtures live in testdata/ (git-ignored - the verifier key is ~105MB
// decompressed, too large to commit, unlike pkg/mdoc/testdata/zk_native's
// small Longfellow fixtures). Regenerate via, in a zk-cred-vega checkout:
//
//	cargo test --release go_ffi::tests::dump_golden_fixture_for_go_smoke_test -- --ignored
//
// then copy target/go-cabi/testdata/{verifier_key,proof,claim0}.bin here.
// Skipped automatically if the fixtures aren't present, rather than
// failing the whole suite - mirrors pkg/mdoc/zknative's own
// network-unreachable skip, just for a different "not set up" reason
// (this crate has no live-published circuit to fetch from yet - see
// go-zk-circuits' r7 entries' unpublished state).
func TestVerify_RealGoldenProof(t *testing.T) {
	vkBytes, proofBytes, claim0 := loadFixtures(t)

	vk, err := NewVerifierKey(vkBytes)
	if err != nil {
		t.Fatalf("NewVerifierKey: %v", err)
	}
	defer vk.Close()

	result, err := vk.Verify(proofBytes, disclosedBytesForFixture(claim0))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.Claims[0].Disclosed {
		t.Error("claims[0] should be disclosed")
	}
	if int(result.Claims[0].RealLen) != len(claim0) {
		t.Errorf("claims[0].RealLen = %d, want %d", result.Claims[0].RealLen, len(claim0))
	}
	if !bytes.Equal(result.Claims[0].Plaintext, claim0) {
		t.Errorf("claims[0].Plaintext = %x, want %x", result.Claims[0].Plaintext, claim0)
	}
	if result.Claims[1].Disclosed {
		t.Error("claims[1] should NOT be disclosed")
	}
	if len(result.Claims[1].Plaintext) != 0 {
		t.Errorf("undisclosed claims[1].Plaintext should be empty, got %d bytes", len(result.Claims[1].Plaintext))
	}

	var zero [32]byte
	if result.Qx == zero {
		t.Error("Qx should not be all-zero")
	}
	if result.Qy == zero {
		t.Error("Qy should not be all-zero")
	}
}

// A tampered proof must be rejected with a real, non-empty error message.
func TestVerify_RejectsTamperedProof(t *testing.T) {
	vkBytes, proofBytes, claim0 := loadFixtures(t)

	vk, err := NewVerifierKey(vkBytes)
	if err != nil {
		t.Fatalf("NewVerifierKey: %v", err)
	}
	defer vk.Close()

	tampered := append([]byte(nil), proofBytes...)
	tampered[len(tampered)-1] ^= 0xff

	if _, err := vk.Verify(tampered, disclosedBytesForFixture(claim0)); err == nil {
		t.Fatal("expected tampered proof to fail verification")
	}
}

func TestNewVerifierKey_RejectsEmptyBytes(t *testing.T) {
	if _, err := NewVerifierKey(nil); err == nil {
		t.Fatal("expected empty verifier key bytes to be rejected")
	}
}

func TestVerify_RejectsClosedKey(t *testing.T) {
	vkBytes, proofBytes, claim0 := loadFixtures(t)

	vk, err := NewVerifierKey(vkBytes)
	if err != nil {
		t.Fatalf("NewVerifierKey: %v", err)
	}
	vk.Close()
	vk.Close() // Close must be idempotent.

	if _, err := vk.Verify(proofBytes, disclosedBytesForFixture(claim0)); err == nil {
		t.Fatal("expected Verify on a closed key to fail")
	}
}

// disclosedBytesForFixture builds the MaxClaims-length disclosedBytes
// Verify now requires, for this package's golden-fixture tests: slot 0
// gets claim0 (the fixture's own disclosed claim, matching the assertions
// below), every other slot is left empty (undisclosed) - this fixture
// predates r12 and was never regenerated to dump every slot's bytes, only
// claim0's; see this file's own package doc for the regeneration command.
func disclosedBytesForFixture(claim0 []byte) [][]byte {
	out := make([][]byte, MaxClaims)
	out[0] = claim0
	return out
}

func loadFixtures(t *testing.T) (vkBytes, proofBytes, claim0 []byte) {
	t.Helper()
	dir := "testdata"
	vkBytes = readFixtureOrSkip(t, filepath.Join(dir, "verifier_key.bin"))
	proofBytes = readFixtureOrSkip(t, filepath.Join(dir, "proof.bin"))
	claim0 = readFixtureOrSkip(t, filepath.Join(dir, "claim0.bin"))
	return vkBytes, proofBytes, claim0
}

func readFixtureOrSkip(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("fixture %s not present - see this file's package doc for how to regenerate it", path)
		}
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	return data
}
